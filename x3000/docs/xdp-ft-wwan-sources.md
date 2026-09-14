# BPF source for `xdp-ft-wwan.sh`

Same arrangement as `verify-992a-sources.md`, for the same reasons: the objects
live in `bpf/` as `.bpf` files so the repo's blanket `*.o` rule does not swallow
them, they ship as files rather than base64 because busybox here has no `base64`
applet, and each source sits next to its object so the object is auditable and
reproducible.

| file | what it is |
|---|---|
| `bpf/xdp_ft_probe.bpf` | the probe object, little-endian eBPF, DWARF stripped and `.BTF` kept |
| `bpf/xdp_ft_probe.bpf.c` | the probe source |
| `bpf/xdp_ft_wwan.bpf` | the fastpath object, same treatment |
| `bpf/xdp_ft_wwan.bpf.c` | the fastpath source |
| `xdp-ft-wwan.sh` | preflight, fetch, attach, sample, detach |

Two objects rather than one, and the split is not cosmetic. The fastpath reads
fields out of `struct flow_offload_tuple`, which needs CO-RE relocations this
kernel's BTF resolves ambiguously, and `bpftool prog loadall` fails the whole
object when any single program in it fails to relocate. With both programs in one
file the relocation failure took the probe down with it, so the measurement could
never run. Apart, the probe loads.

Kept as separate `.c` files rather than inlined here: the fastpath is roughly 400
lines, where the three objects in `verify-992a-sources.md` are a dozen each.

Build command (clang 18, any host — eBPF bytecode is architecture-neutral):

```sh
for o in xdp_ft_probe xdp_ft_wwan; do
	clang -O2 -g -Wall -Wextra -target bpf -mcpu=v3 \
	      -idirafter /usr/include/$(uname -m)-linux-gnu \
	      -c bpf/$o.bpf.c -o bpf/$o.bpf
	llvm-strip -g bpf/$o.bpf
done
```

`llvm-strip -g`, never plain `strip`. It drops DWARF and keeps `.BTF`, and
`.BTF` is what CO-RE needs to relocate the kernel struct offsets at load time.
An object stripped the wrong way loads and then misreads every field, which
looks like a kernel bug rather than a build mistake.

sha256 of the committed objects:

```
5f09be7526a53b16184d84b3c61bad3655fde27d3d0ce7675730d16abfe564e5  bpf/xdp_ft_probe.bpf
19774db2d8dea3ae1f2265f845588514804bb2e9bd75b127ad3d35bda334212d  bpf/xdp_ft_wwan.bpf
```

## What the two programs do

`xdp_ft_probe` parses the packet, calls `bpf_xdp_flow_lookup()`, counts the
result in a per-CPU array and returns `XDP_PASS`. It changes nothing, and it
answers the question section 16.5 of `xdp-methods-tested.md` raised and nothing
had tested: whether the kfunc actually hits on `wwan0`.

It declares the kfunc's return type opaque, exactly as the in-tree selftest
`tools/testing/selftests/bpf/progs/xdp_flowtable.c` does. Nothing is read out of
the returned tuplehash, only tested for NULL, so there is nothing to relocate and
nothing to be ambiguous about. That is the whole reason the probe loads and the
fastpath does not.

`xdp_ft_fastpath` adds the NAT rewrite, the TTL decrement, an Ethernet header via
`bpf_xdp_adjust_head()` and `XDP_REDIRECT` to a wired port.

## Things the source depends on, each read from v6.12.103

- `bpf_xdp_flow_lookup()` resolves its flowtable from `xdp->rxq->dev`. On
  `wwan0` that is the real netdev, because 992 runs the program through
  `do_xdp_generic()`, whose rxq comes from `netif_get_rxqueue(skb)`
  (`dev.c:5079`). On the wired ports it is `eth->dummy_dev` and every lookup
  misses — which is why this program is for `wwan0` and nowhere else.
- The packet has no Ethernet header. `wwan0` is `ARPHRD_RAWIP` (519) with
  `hard_header_len` 0, and 991 anchors `mac_header` at `skb->data`, so
  `mac_len` is 0 and the IP header is at `ctx->data`. The in-tree selftest this
  is modelled on parses `ethhdr` and would read the first two octets of the
  source address as an EtherType.
- NAT direction handling is copied case by case from `nf_flow_snat_ip()` and
  `nf_flow_dnat_ip()` in `net/netfilter/nf_flow_table_ip.c`.
- `container_of()` on the returned tuplehash produces a pointer the verifier no
  longer trusts, so it goes through `bpf_rdonly_cast()` (`helpers.c:2771`).
- Only `FLOW_OFFLOAD_XMIT_DIRECT` flows are handled. `NEIGH` needs a neighbour
  lookup the program cannot do, and those get `XDP_PASS`.
- The redirect target must advertise `NETDEV_XDP_ACT_NDO_XMIT` (`devmap.c:488`).
  The mtk netdevs do; `wwan0` and the AP netdevs do not.
- Keep the firewall on **software** flow offloading. Hardware offload sends
  `nf_flow_table_offload_setup()` down the other branch
  (`nf_flow_table_offload.c:1258`) and the device is never inserted into the XDP
  hashtable, so every lookup returns `-ENOENT`.
- `wwan0` reaches the flowtable at all only because of this tree's firewall4
  patch `001-flowtable-fall-back-to-l3-device`.

## State

**The probe runs.** Measured on the box, one 30-second sample with traffic
crossing `wwan0`:

| what | value | how |
|---|---|---|
| `rx_packets` delta on `wwan0` | 61773 | `/sys/class/net/wwan0/statistics/rx_packets`, before and after |
| `seen` | 61820 | 61191 on cpu0 plus 629 on cpu1 |
| `not_ipv4`, cpu0 alone | 60871 | the other CPU's share was not read |

`seen` tracking `rx_packets` to within 0.1% is the result that matters: the
program is on the interface, in the receive path, and looking at essentially
every packet. The attach is generic-mode — `bpftool net show` reports
`xdp generic`, which is authoritative where `ip -d link show` printing `prog/xdp`
is not.

The rest of the distribution is not recorded yet, because the sampler's counter
parser was reading a format this bpftool does not emit and printed zeros over
live data for several runs. That is fixed in `xdp-ft-wwan.sh`; the numbers above
are the ones read by hand from the raw dump, so they stand. `not_ipv4` dominating
suggests the modem path is IPv6-primary and the probe is IPv4-only by choice, but
that is reasoning, not a measurement, and a re-run settles it.

**The fastpath does not load.** `bpftool prog loadall` rejects it:

```
libbpf: relo #7: relocation decision ambiguity: success 90056 != success 90242
```

Two candidate types for `struct flow_offload_tuple` in the running kernel's BTF,
two different field offsets, and libbpf refuses to guess. So the fastpath rewrite
has been through a compiler and nothing else. A wrong checksum shows up as
clients losing connectivity, so `probe` comes first and `off` stays to hand.
