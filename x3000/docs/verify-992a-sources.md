# BPF sources embedded in `verify-992a.sh`

`verify-992a.sh` uses three pre-compiled eBPF objects so the router needs no
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
