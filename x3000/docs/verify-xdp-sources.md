# BPF sources for `verify-xdp.sh`

`verify-xdp.sh` uses three pre-compiled eBPF objects so the router needs no
compiler. They live in `bpf/` next to the script; the script falls back to
fetching them from the repo over HTTPS if that directory is missing.

eBPF is architecture-independent bytecode — only endianness matters, and these
are little-endian (`ELF 64-bit LSB … eBPF`), matching the target's
`CONFIG_CPU_LITTLE_ENDIAN=y`. The sources are kept here so the objects are
auditable and reproducible.

Two naming details worth knowing:

- The files are `.bpf`, not `.o`, because the repo's `.gitignore` has a blanket
  `*.o` rule that would swallow them.
- They are shipped as files rather than base64 inside the script. OpenWrt's
  busybox is built without the `base64` applet, so an embedded blob cannot be
  decoded on the router — the script fails with `base64: not found`.

Build command (clang 18, any host):

```sh
clang -O2 -g -target bpf -c xdp_pass.c -o bpf/xdp_pass.bpf
clang -O2 -g -target bpf -c xdp_drop.c -o bpf/xdp_drop.bpf
clang -O2 -g -target bpf -c tc_rawip.c -o bpf/tc_rawip.bpf
```

The tail probe is built differently and the difference matters, so it has its
own line:

```sh
clang -Os -g -target bpfel -c bpf/xdp_tail_probe.bpf.c -o /tmp/t.o
llvm-strip --strip-debug --keep-section=.BTF /tmp/t.o -o bpf/xdp_tail_probe.bpf
```

`-Os` and the strip keep it small enough to hand-paste as hex when a router has
no way to fetch it, and `--keep-section=.BTF` is not optional: the map is
BTF-defined, and libbpf refuses the object without it. Build from a short path -
the source filename is recorded in `.BTF.ext`, so building from a long scratch
directory bakes that path into the committed object.

Checksums, which `verify-xdp.sh` verifies before loading and refuses to run
without matching. Update these and the objects together:

| object | sha256 |
|---|---|
| `xdp_pass.bpf` | `a862ec14a5928c05863155946a4f7b0591e623b33dfa2ffc4b0f39876a497499` |
| `xdp_drop.bpf` | `c8df00ebec9a03bc4224120120bef008a0b44a6b67fabbd6dd837b5403fa0379` |
| `tc_rawip.bpf` | `0b45aeded4ecfc9beb21fcb216196b15c4d2dc66021e2c70f9fdc9271c7af0d2` |
| `xdp_tail_probe.bpf` | `2e34ea12f2189b307f6ccfcee5daf55f1632554ac6d6272a68d812198f639f31` |

---

## `xdp_pass.c` — attaches and does nothing

Used by step 5 (does the program land in DRIVER mode?) and step 6 (does GRO
survive the attach?). It must be a no-op so those two answers are not
confounded by the program's own behaviour.

```c
#define SEC(N) __attribute__((section(N), used))
struct xdp_md { unsigned int data, data_end, data_meta, ingress_ifindex, rx_queue_index, egress_ifindex; };
SEC("xdp") int xdp_pass(struct xdp_md *ctx) { return 2; }   /* XDP_PASS */
char _license[] SEC("license") = "GPL";
```

## `xdp_drop.c` — proves the verdict is honoured

Step 9, opt-in via `--with-drop`. Drops every WAN ingress packet for 5 seconds;
LAN and SSH are unaffected because the hook is on `wwan0` only.

```c
#define SEC(N) __attribute__((section(N), used))
struct xdp_md { unsigned int data, data_end, data_meta, ingress_ifindex, rx_queue_index, egress_ifindex; };
SEC("xdp") int xdp_drop(struct xdp_md *ctx) { return 1; }   /* XDP_DROP */
char _license[] SEC("license") = "GPL";
```

## `tc_rawip.c` — L3/L4 parse on a device with no L2 header

Step 10, opt-in via `--with-tc`. At tc ingress the core pushes `skb->mac_len`,
which is 0 on `wwan0`, so `data` points straight at the IP header — an
Ethernet-assuming program reads the first two octets of the source address as
an EtherType and silently decides every packet is "not IPv4".

The variable-offset L4 read goes through `bpf_skb_load_bytes()` on purpose:
direct packet access at `ip[ihl + N]` makes clang re-derive the pointer as
`ip + (ihl | N)`, a different derivation the range check does not cover, and
the verifier rejects it with *"R6 offset is outside of the packet"*.

```c
#define SEC(N) __attribute__((section(N), used))
typedef unsigned char __u8; typedef unsigned short __u16; typedef unsigned int __u32;
struct __sk_buff {
	__u32 len, pkt_type, mark, queue_mapping, protocol, vlan_present,
	      vlan_tci, vlan_proto, priority, ingress_ifindex, ifindex,
	      tc_index, cb[5], hash, tc_classid, data, data_end, napi_id,
	      family, remote_ip4, local_ip4, remote_ip6[4], local_ip6[4],
	      remote_port, local_port, data_meta;
};
#define TC_ACT_OK 0
static long (*bpf_trace_printk)(const char *fmt, __u32 fmt_size, ...) = (void *)6;
static long (*bpf_skb_load_bytes)(const void *skb, __u32 off, void *to, __u32 len) = (void *)26;
#define bpf_printk(fmt, ...) ({ char ____fmt[] = fmt; \
	bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); })
#define bpf_ntohs(x) ((__u16)((((x) >> 8) & 0xff) | (((x) & 0xff) << 8)))

SEC("classifier/rawip")
int rawip(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *end  = (void *)(long)skb->data_end;
	__u8 *ip = data;
	__u8 ports[4];

	if (ip + 20 > (__u8 *)end)
		return TC_ACT_OK;

	if ((ip[0] >> 4) == 4) {
		__u32 ihl = (ip[0] & 0x0f) * 4;
		__u8 proto = ip[9];
		__u32 saddr = (ip[12]<<24)|(ip[13]<<16)|(ip[14]<<8)|ip[15];
		__u32 daddr = (ip[16]<<24)|(ip[17]<<16)|(ip[18]<<8)|ip[19];
		__u16 sport = 0, dport = 0;

		if (ihl >= 20 && bpf_skb_load_bytes(skb, ihl, ports, 4) == 0) {
			sport = (ports[0] << 8) | ports[1];
			dport = (ports[2] << 8) | ports[3];
		}
		bpf_printk("RAWIP-OK v4 proto=%d src=%x dst=%x", proto, saddr, daddr);
		bpf_printk("RAWIP-OK L4 sport=%d dport=%d skbproto=%x",
			   sport, dport, bpf_ntohs(skb->protocol));
	} else if ((ip[0] >> 4) == 6) {
		bpf_printk("RAWIP-OK v6 nexthdr=%d len=%d", ip[6], skb->len);
	} else {
		bpf_printk("RAWIP-?? first_nibble=%d", ip[0] >> 4);
	}
	return TC_ACT_OK;
}
char _license[] SEC("license") = "GPL";
```

Note `bpf_trace_printk` takes at most three variadic arguments; a fourth is a
compile error (`too many arguments`), which is why the output is split across
two calls.

## `xdp_tail_probe.bpf.c` — tells 893's native hook from 891's generic one

The source is committed next to the object at `bpf/xdp_tail_probe.bpf.c`, so it
is not reproduced here. What it does, and why it is the discriminator:

It calls `bpf_xdp_adjust_tail(ctx, 64)`, records the return value in slot 2 of a
three-entry array map, undoes the growth if it somehow succeeded - it runs on
live forwarded traffic and must not leave a packet longer than it arrived - and
returns `XDP_PASS`.

893 allocates exactly `XDP_PACKET_HEADROOM + dgram_len +
SKB_DATA_ALIGN(sizeof(struct skb_shared_info))`, so `xdp_data_hard_end()`
(`include/net/xdp.h:147`) lands at the end of the datagram and there is no room
to grow: the call must return `-EINVAL`. The generic path runs the same program
over an skb whose allocation kmalloc rounded up, so the same call finds tailroom
and returns 0.

That difference is the only thing that separates the two paths from userspace.
Both attach through the same `ndo_bpf` and both report `prog/xdp id N` with no
`xdpgeneric` qualifier, so `ip -d link` cannot tell them apart.

It also checks `frame_sz`, which is the part worth having. An overstated
`frame_sz` is what lets `bpf_xdp_adjust_tail()`'s memset run past the end of the
buffer, and it would show up here as a successful grow. Measured on the flashed
image 2026-09-15: `xdpdrv` returned `-22`, `xdpgeneric` returned `0` -
`xdp-methods-tested.md` 24.18.

It has no CO-RE relocations and reads nothing out of any kernel struct, so a
kernel bump cannot break it the way it can break `xdp_ft_wwan.bpf`.
