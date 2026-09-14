# BPF source for `xdp-ft-wwan.sh`

Same arrangement as `verify-992a-sources.md`, for the same reasons: the object
lives in `bpf/` as a `.bpf` file so the repo's blanket `*.o` rule does not
swallow it, it ships as a file rather than base64 because busybox here has no
`base64` applet, and the source sits next to it so the object is auditable and
reproducible.

| file | what it is |
|---|---|
| `bpf/xdp_ft_wwan.bpf` | the compiled object, little-endian eBPF, DWARF stripped and `.BTF` kept |
| `bpf/xdp_ft_wwan.bpf.c` | the source |
| `xdp-ft-wwan.sh` | preflight, fetch, attach, sample, detach |

Kept as a separate `.c` rather than inlined here: it is roughly 400 lines, where
the three objects in `verify-992a-sources.md` are a dozen each.

Build command (clang 18, any host — eBPF bytecode is architecture-neutral):

```sh
clang -O2 -g -Wall -Wextra -target bpf -mcpu=v3 \
      -idirafter /usr/include/$(uname -m)-linux-gnu \
      -c bpf/xdp_ft_wwan.bpf.c -o bpf/xdp_ft_wwan.bpf
llvm-strip -g bpf/xdp_ft_wwan.bpf
```

`llvm-strip -g`, never plain `strip`. It drops DWARF and keeps `.BTF`, and
`.BTF` is what CO-RE needs to relocate the kernel struct offsets at load time.
An object stripped the wrong way loads and then misreads every field, which
looks like a kernel bug rather than a build mistake.

sha256 of the committed object:

```
19774db2d8dea3ae1f2265f845588514804bb2e9bd75b127ad3d35bda334212d
```

## What the two programs do

`xdp_ft_probe` parses the packet, calls `bpf_xdp_flow_lookup()`, counts the
result and returns `XDP_PASS`. It changes nothing, and it answers the question
section 16.5 raised and nothing has tested: whether the kfunc actually hits on
`wwan0`.

`xdp_ft_fastpath` adds the NAT rewrite, the TTL decrement, an Ethernet header
via `bpf_xdp_adjust_head()` and `XDP_REDIRECT` to a wired port.

## Things the source depends on, each read from v6.12.103

- `bpf_xdp_flow_lookup()` resolves its flowtable from `xdp->rxq->dev`. On
  `wwan0` that is the real netdev, because 992 runs the program through
  `do_xdp_generic()`, whose rxq comes from `netif_get_rxqueue(skb)`
  (`dev.c:5079`). On the wired ports it is `eth->dummy_dev` and every lookup
  misses — which is why this program is for `wwan0` and nowhere else.
- The packet has no Ethernet header. `wwan0` is `ARPHRD_RAWIP` with
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

Compiled, never run. The fastpath rewrite in particular has been through a
compiler and nothing else — a wrong checksum shows up as clients losing
connectivity, so run `probe` first and keep `off` to hand.
