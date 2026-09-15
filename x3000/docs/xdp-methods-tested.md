# XDP / eBPF / tc-BPF on the X3000: every method, tested

## Which tree each claim was read from - read this before trusting a line number

The image is built from three separate source trees, on a base of
[vjt's Jeeves](https://github.com/vjt/openwrt-glinet-x3000) fork of OpenWrt plus
this repo's lean overlay. Paths are relative to
`build_dir/target-aarch64_cortex-a53_musl/linux-mediatek_filogic/`:

| what | tree | notes |
|---|---|---|
| kernel | `linux-6.12.103` | post upstream + Jeeves + OpenWrt patches + this repo's 990-993 |
| wireless driver | `mt76-2026.03.19~39c960c3` | separate package; files are `dma.c`, `mac80211.c`, not `mt76_*.c` |
| 802.11 stack | `mac80211-regular/backports-6.18.39` | **backports, not the kernel's own `net/mac80211`**. Confirmed on the box: `modinfo mac80211` shows `depends: cfg80211,compat` |

**Sections 0 through 17 carry line numbers from earlier trees.** Sections 5 and 9
already note this for themselves. Drift against the shipped kernel, re-measured
2026-09-12 against a pristine `v6.12.103` checkout with this tree's patch set
diffed against it:

| source area | offset from pristine v6.12.103 | why |
|---|---|---|
| `net/core/dev.c` | **exactly +5 below line 3693** | one patch touches this file: `generic/hack-6.12/721-net-add-packet-mangeling.patch`, +5 lines at `xmit_one()`. Nothing else in the tree patches `dev.c` |
| `include/linux/netdevice.h` | **+10 below line 2242** | patches 651 (+0), 721 (+1, +5, +4), 731 (+0) |
| `net/core/gro.c`, `gro_cells.c`, `filter.c`, `kernel/bpf/*`, `net/xdp/*`, `net/netfilter/*` | **0** | unpatched in this tree; citations resolve as written |
| `drivers/net/ethernet/mediatek/` | 300 to 600 | where the patches accumulate |
| `drivers/net/wwan/mhi_wwan_mbim.c` | shifts with 991/992 | cite against pristine and say so, as sections 20 and 22 do |

So a `dev.c` citation in this file can be checked arithmetically rather than
re-found: subtract 5 and it must match pristine v6.12.103. Fifteen citations were
checked that way on 2026-09-12 and all fifteen matched, including
`do_xdp_generic` 5621/5616, `sch_handle_ingress` 5661/5656, `generic_xdp_tx`
5242/5237, `napi_threaded_poll_loop` 7004/6999 and the `dev_xdp_mode()` mode line
9457/9452. **Section 19 is the resolved index** - citations verified against the
shipped trees on 2026-09-11. Anything not listed there should be re-found by
symbol name, not by line number:

    K=$(echo build_dir/target-*/linux-*/linux-6.12*)
    grep -n '<symbol>' "$K/<path>"

To re-derive the offsets rather than trust them, diff this tree's patches against
a pristine checkout of the same release:

    git clone --filter=blob:none --no-checkout --depth 1 -b v6.12.103 \
        https://github.com/gregkh/linux.git linux-pristine
    cd linux-pristine && git sparse-checkout init --cone
    git sparse-checkout set net/core net/xdp include/linux include/net kernel/bpf drivers/net
    git checkout
    # then, in this repo:
    grep -rl -E '^(---|\+\+\+) [ab]?/?net/core/dev\.c' \
        target/linux/generic/ target/linux/mediatek/

Compile tests (historical): **x86_64 defconfig + `MHI_BUS=y WWAN=m
MHI_WWAN_MBIM=m GRO_CELLS=y BPF_SYSCALL=y XDP_SOCKETS=y TCP_CONG_BBR=m`**, driver
and `net/core/filter.c` built with `W=1`.
Runtime tests (historical): a container's live kernel on **real netdevs** - an
`IFF_TUN` device (`ARPHRD_NONE`, `hard_header_len 0`, no L2 header: the closest
analogue of `wwan0`), an `IFF_TAP` device, a veth pair, a bridge and an ifb.
clang 18 / libbpf 1.3 / iproute2 6.1. On-hardware results are labelled as such.

---

## 0. Two corrections to earlier claims

**I was wrong about the blocker for XDP_REDIRECT on `wwan0`.**
I said it needed a one-line `EXPORT_SYMBOL_GPL(xdp_do_generic_redirect)` kernel
patch. It does not. `do_xdp_generic()` — which *contains* the redirect dispatch,
the `XDP_TX` path and its own `bpf_net_context` — **is already exported**:

```
net/core/dev.c:5301:  EXPORT_SYMBOL_GPL(do_xdp_generic);
```

and `drivers/net/tun.c` calls it from a driver in exactly the shape needed
(tun.c:1929 and tun.c:2529 - the second was cited as 2523 here until 2026-09-12,
which is `eth_type_trans()`, six lines short). I was looking one level too deep in
the call chain and stopped at the first unexported symbol.

**992 changed the default XDP attach mode on `wwan0`, and that is why
`xdp-loader load wwan0` broke.**

```
net/core/dev.c:9457:  return dev->netdev_ops->ndo_bpf ? XDP_MODE_DRV : XDP_MODE_SKB;
```

Pristine `mhi_wwan_mbim.c` has **0** `ndo_bpf` references; 991 has **0**; 992
adds **6**. So before 992, an attach with no mode flag went to `XDP_MODE_SKB`
(full generic XDP, redirect and AF_XDP included). After 992 it goes to
`XDP_MODE_DRV` — the hand-rolled hook, which advertises `NETDEV_XDP_ACT_BASIC`
and refuses `XDP_REDIRECT`. Verified at runtime (test C5 below).

That is the whole story of the crash: `xdp-loader load wwan0` installed
libxdp's `xsk_def_prog`, 992's `ndo_bpf` captured it into native mode, the
program called `bpf_redirect_map()` from the MHI tasklet, and there was no
`bpf_net_context`. The `bpf_net_context` fix stopped the oops; the redirect
itself was still refused at that point.

**That last sentence describes the hand-rolled hook, not the shipped patch.** 992
as it stands routes through `do_xdp_generic()`, which dispatches `XDP_REDIRECT`
and `XDP_TX` itself and sets up its own `bpf_net_context`, and the patch
advertises `NETDEV_XDP_ACT_BASIC | NETDEV_XDP_ACT_REDIRECT`. So redirect and
AF_XDP are supported on `wwan0` now; what is *incompatible* with a redirect is the
shaper, because every redirect path ends in `generic_xdp_tx()` with no qdisc - see
section 21.1. Noted 2026-09-12.

---

## 1. Method C — plain `xdpgeneric`, zero patches (WORKS TODAY)

| test | device | result |
|---|---|---|
| C1 | bridge (no `ndo_bpf`) | generic XDP **attached** |
| C2 | bridge, `xdpdrv` | refused: *"Underlying driver does not support XDP in native mode"* (`dev.c:9714`) |
| C3 | bridge, an `XDP_REDIRECT` program, generic | **attached** |
| C4 | ifb0 | **attached** |
| C5 | veth (**has** `ndo_bpf`), no mode flag | kernel picked **DRV** — confirms the 9335 rule |
| C6 | veth, DRV attached, then add generic | refused: *"Native and generic XDP can't be active at the same time"* |

`generic_xdp_install()` (`dev.c:5818`) takes any netdev — no capability check, no
`ndo_bpf`, nothing driver-specific. Then on the raw-IP tun device:

```
XDP-SEES nibble=4 byte9=17 ifindex=8      <- IPv4, proto 17 (UDP)
XDP-SEES src=a090901 dst=a090902          <- 10.9.9.1 -> 10.9.9.2
```

The program sees the **IP header at offset 0**. No crash, no misparse from the
`struct ethhdr` read inside `bpf_prog_run_generic_xdp()` (it only uses it to
detect whether the program *changed* the L2 header, and on raw IP `mac_len` is 0
so the `__skb_push` is a no-op).

**Full end-to-end redirect off a raw-IP device:**

| | packets redirected | what arrived on the far side |
|---|---|---|
| naive `bpf_redirect(veth0, 0)` | 3 / 3 | `proto=0xa09`, `len=32` — **malformed**: the first 14 bytes of the IP header were eaten as an Ethernet header |
| `bpf_xdp_adjust_head(ctx, -14)` then fill an ethhdr, then redirect | 3 / 3 | `skbproto=0x800`, ethertype `0800`, IPv4 at +14, proto 17 — **correct frame** |

So: **XDP_REDIRECT from `wwan0` works today with `ip link set dev wwan0
xdpgeneric obj prog.o sec xdp` — but the program must prepend an Ethernet header
before redirecting to any Ethernet device (br-lan, eth0, a veth).**

### The cost of Method C

```
include/linux/netdevice.h:2418
static inline bool netif_elide_gro(const struct net_device *dev)
{
	if (!(dev->features & NETIF_F_GRO) || dev->xdp_prog)
		return true;
	...
}

net/core/gro_cells.c:23
	if (!gcells->cells || skb_cloned(skb) || netif_elide_gro(dev)) {
		res = netif_rx(skb);
```

`xdpgeneric` sets `dev->xdp_prog`, so `gro_cells_receive()` bypasses GRO on
**every datagram**. Attaching generic XDP to `wwan0` turns 991 off. That is the
measured −36.6% softirq CPU/MB, gone.

---

## 2. Method A — call the exported `do_xdp_generic()` from the driver (BEST)

Full action set **and** GRO stays on, because the program lives on
`link->xdp_prog`, not `dev->xdp_prog`.

**Compile: clean, `W=1`, zero warnings, against a completely stock kernel.**
Only new undefined symbol:

```
U do_xdp_generic          <- EXPORT_SYMBOL_GPL, dev.c:5301
```

The hook shrinks from 120 lines to 57; `bpf_warn_invalid_xdp_action`,
`trace_xdp_exception`, `xdp_master_redirect` and `bpf_dispatcher_xdp_func` all
drop out of the module's undefined list because the core does that work.

**Runtime proof of the exact pattern.** `.ndo_bpf = tun_xdp` lives in
`tap_netdev_ops` (tun.c:1330), not `tun_netdev_ops` (tun.c:1246) — so an
`IFF_TAP` device attaches in **native** mode, stores the program on
`tun->xdp_prog`, and its RX path calls `do_xdp_generic()`. That is Method A
verbatim. Attaching a redirect program in `xdpdrv` mode to `tap0`:

```
NATIVE ATTACH ✓   prog/xdp id 127 name xdp_redir
veth1 rx_packets: 6 -> 10   (4 of 4 injected)
OBS skbproto=800   ethertype-field=0800   at+14: ver=4  byte23=17
```

**Native-mode attach → driver-owned prog → `do_xdp_generic()` → XDP_REDIRECT →
well-formed frame delivered. No kernel patch.**

Three preconditions the driver must satisfy (all from reading
`bpf_prog_run_generic_xdp()`, and all present in the exp-a patch):

1. `skb_reset_mac_header()` **before** the call. `mac_len = skb->data -
   skb_mac_header(skb)`; a fresh `netdev_alloc_skb()` leaves the `~0U` sentinel,
   and that arithmetic would walk off the front of the buffer. **Satisfied.**
   This line read "992 currently resets it only *after* the XDP hook" until the
   2026-09-09 rework moved it; corrected 2026-09-15, having gone stale in place
   for six days.
2. `skb->protocol` set before the call — `generic_xdp_tx()` and
   `dev_map_generic_redirect()` both end in `dev_queue_xmit()` and neither
   re-derives it. **Satisfied** since the same rework, and stale in the same
   way until 2026-09-15.
3. `do_xdp_generic()` takes `struct sk_buff **`, not `*` —
   `netif_skb_check_for_xdp()` may reallocate. (It won't here: the RX loop
   already reserves `XDP_PACKET_HEADROOM` when a program is attached. Honour the
   contract anyway.)

**And two postconditions, added 2026-09-15.** Method A is not finished when
`do_xdp_generic()` returns `XDP_PASS`. The core hands the skb back carrying
receive metadata it derived by reading the first fourteen bytes as an Ethernet
header -- which on a raw-IP link they are not. `skb->mac_header` may have moved
(`bpf_xdp_adjust_head()` shifts it at `dev.c:5107`), and `skb->pkt_type` may no
longer be `PACKET_HOST`, which costs every forwarded datagram at
`ip_forward.c:93`. 992 now re-anchors both headers and forces `PACKET_HOST`
before returning. Section 23.28 has the mechanism and the trigger set. Listing
only preconditions here was itself the mistake: I read the core's requirements
of the driver and not the driver's requirements of the core.

Known losses vs the hand-rolled hook: per-link `rx_errors`/`rx_dropped`
accounting for XDP verdicts goes away (the core frees the skb itself), and
`link->xdp_rxq` becomes dead — generic XDP uses
`netif_get_rxqueue(skb)->xdp_rxq`, which the core registers for every netdev in
`netif_alloc_rx_queues()` (`dev.c`, unconditional).

**AF_XDP works under Method A.** `xsk_rcv_check()` requires
`xs->dev == xdp->rxq->dev && xs->queue_id == xdp->rxq->queue_index`; a socket
bound to `(wwan0, queue 0)` satisfies both against `dev->_rx[0]`.

---

## 3. Method B — `EXPORT_SYMBOL_GPL(xdp_do_generic_redirect)` + in-driver redirect

Built it anyway, to see whether it holds up. It does — it's just strictly worse
than A.

**Compile: clean, `W=1`, zero warnings** (driver + `net/core/filter.c`).

```
driver:   U xdp_do_generic_redirect      U xdp_do_flush
filter.o: __export_symbol_xdp_do_generic_redirect     <- the modpost record
```

Two things the implementation has to get right that aren't obvious:

- The `bpf_net_context` must stay **alive across** `xdp_do_generic_redirect()` —
  `ri->map_type`, `ri->tgt_index` and `ri->tgt_value` live in it. Clearing it
  right after `bpf_prog_run_xdp()`, which is what 992 does today, throws the
  verdict away.
- `xdp_do_flush()` must be called before clearing the context. This is not inside
  `net_rx_action()`, so nothing else will drain the devmap/cpumap/xsk bulk queues
  this redirect just appended to.

Verdict: carries a kernel patch, duplicates code the core already exports, and
buys nothing over A. **Not recommended.**

---

## 4. Method D — tc-BPF on a raw-IP device (WORKS, with one gotcha)

Source, v6.12:

```
net/core/dev.c:4198   sch_ret = tcx_run(entry, skb, true);    /* ingress: pushes skb->mac_len */
net/core/dev.c:4257   sch_ret = tcx_run(entry, skb, false);   /* egress:  no push */
net/sched/cls_bpf.c:99  __skb_push(skb, skb->mac_len);        /* legacy cls_bpf, same */
```

`skb->mac_len` is 0 on `wwan0` (`__netif_receive_skb_core()` computes it as
`network_header - mac_header`, and the driver resets both to `skb->data`), so the
push is a no-op and **both hooks see the IP header at offset 0**.

Runtime, ingress on the raw-IP tun device:

```
RAWIP-OK v4 proto=17 src=a090901 dst=a090902
RAWIP-OK L4 sport=1111 dport=2222 skbproto=800
```

Egress, same program, same device:

```
RAWIP-OK v4 proto=17 src=a090902 dst=a090907
RAWIP-OK L4 sport=4444 dport=5555 skbproto=800
```

**L3 and L4 both parse correctly, ingress and egress, with one unmodified
program.** `skb->protocol` is `0x0800` at both hooks.

### The gotcha, demonstrated

The standard tc-BPF boilerplate that starts with `struct ethhdr *eth = data;`
does not fail loudly on `wwan0` — it fails **silently**:

```
ETHER-MISPARSE h_proto=a09 (not IPv4) -> bailing
```

`0x0a09` is the first two octets of the source address `10.9.9.1`, read as an
EtherType. Every packet looks like "not IPv4" and sails through unfiltered. The
`config.common` comment on `xdp-filter` ("It parses an Ethernet header, so it
belongs on the eth LAN/WAN ports, not the raw-IP wwan0 modem netdev") is exactly
right, and now demonstrated rather than inferred.

### A verifier trap worth knowing

My first raw-IP program was **rejected**:

```
47: (71) r1 = *(u8 *)(r6 +0)
invalid access to packet, off=0 size=1, R6(id=4,off=0,r=0)
R6 offset is outside of the packet
```

Reading `ip[ihl + N]` after bound-checking `ip + ihl + 4` makes clang re-derive
the pointer as `ip + (ihl | N)` — a *different* derivation, so the range doesn't
carry. Fix: read variable-offset L4 through `bpf_skb_load_bytes(skb, ihl, buf, 4)`.
The corrected program loads and attaches (`id 57 name rawip tag bc4f1df2d30ffdff`).

---

## 5. RX-path order and the offload matrix, re-verified

> Superseded in part by section 9. The line numbers below are from an
> early 6.12 and the DSA row does not apply to this board. Section 9 has
> the version re-checked against the pinned 6.12.103.

`__netif_receive_skb_core()` (v6.12, `dev.c:5457`), in order:

| line | hook |
|---|---|
| 5486 | **generic XDP** (`do_xdp_generic`) |
| 5530 | **tc ingress** (`sch_handle_ingress`) |
| 5538 | **netfilter ingress** — where the software nft flowtable hooks |
| 5564 | `rx_handler` (bridge) |

Native XDP runs earlier still, inside the driver. Both the single-skb (5668) and
list (5745) paths funnel through 5457, so gro_cells delivery reaches generic XDP
normally.

The flowtable is hard-restricted to that one hook:
`net/netfilter/nf_tables_api.c:8460` returns `-EOPNOTSUPP` for any
`hooknum != NF_NETDEV_INGRESS`. So it can never hide traffic from XDP or tc-BPF;
it bypasses everything *after* 5538, including the bridge `rx_handler`.

| path | native XDP | generic XDP | tc-BPF | HW BPF offload |
|---|---|---|---|---|
| wired LAN/WAN (`mtk_eth_soc`) | **yes** — `BASIC\|REDIRECT\|NDO_XMIT\|NDO_XMIT_SG` (`mtk_eth_soc.c:5360-5363`), gated on NETSYS v2+; MT7981 is v2 | yes | yes | no |
| DSA user ports | no — `net/dsa/user.c`: 0 `ndo_bpf` | yes | yes | no |
| `br-lan` | no — `net/bridge/br_device.c`: 0 `ndo_bpf` | yes | yes | no |
| wireless LAN (mac80211/mt76) | no — `net/mac80211/iface.c`: 0 `ndo_bpf` | yes | yes | no |
| wireless WAN (`wwan0`) | 992's hook, `BASIC` only | yes (full set) | yes (raw-IP-aware) | no |

**Hardware BPF/XDP offload does not exist on this box.** Whole-tree grep:
`NETDEV_XDP_ACT_HW_OFFLOAD` is set in exactly two files — `netdevsim/netdev.c:639`
and `nfp/nfp_net_common.c:2767` — and `bpf_offload_dev_create()` has exactly those
two callers. Nothing MediaTek, nothing mt76, nothing MHI.

**MediaTek PPE hardware NAT can never carry LAN↔wwan0.**
`mtk_ppe_offload.c` resolves the egress PSE port from `eth->netdev[0..2]` and
returns `-EOPNOTSUPP` otherwise (line 227). `wwan0` is not one of those.

---

## 6. The one kernel hook that *does* tie nft-offload to XDP

There is exactly one hook inside `kmod-nft-offload` or the kernel that makes
hardware/software offload reachable from BPF:

```
net/netfilter/nf_flow_table_bpf.c:59
__bpf_kfunc struct flow_offload_tuple_rhash *
bpf_xdp_flow_lookup(struct xdp_md *ctx, struct bpf_fib_lookup *fib_tuple,
                    struct bpf_flowtable_opts *opts, u32 opts_len);
```
```
net/netfilter/nf_flow_table_bpf.c:108
BTF_ID_FLAGS(func, bpf_xdp_flow_lookup, KF_TRUSTED_ARGS | KF_RET_NULL)
```

A kfunc for `BPF_PROG_TYPE_XDP` that looks a packet up in the software flowtable
from inside an XDP program. Registration happens in
`nf_flow_offload_xdp_setup()` (defined `nf_flow_table_xdp.c:133`, called
`nf_flow_table_offload.c:1259`), precisely when the
flowtable is **not** hardware-offloaded.

Build gating, `net/netfilter/Makefile`:

```
145  nf_flow_table-y                            += ... nf_flow_table_xdp.o
148  nf_flow_table-$(CONFIG_DEBUG_INFO_BTF_MODULES) += nf_flow_table_bpf.o
150  nf_flow_table-$(CONFIG_DEBUG_INFO_BTF)         += nf_flow_table_bpf.o
```

The device→flowtable registration (`nf_flow_table_xdp.o`) is unconditional. Only
the **kfunc** needs BTF.

**This build already has it.** `x3000/config.common` sets
`CONFIG_KERNEL_DEBUG_INFO_BTF=y` and `CONFIG_KERNEL_DEBUG_INFO_BTF_MODULES=y`
(lines 203–204), and `kmod-nft-offload` → `kmod-nf-flow` makes `NF_FLOW_TABLE` a
module, so `_BTF_MODULES` is the gate that applies. `bpf_xdp_flow_lookup()` will
be present in the image.

Caveat: it only helps where XDP runs *natively* — i.e. the wired ports. On
`wwan0` the flowtable's own ingress hook (5538) already runs after generic XDP
(5486), so there is nothing to short-circuit.

---


## 7. Recommendation

Switch 992's hook to **Method A**. It is one function replaced (`exp-a` is
written and compiles clean), no kernel patch, and it:

- restores `XDP_REDIRECT`, `XDP_TX`, AF_XDP and cpumap on `wwan0`;
- makes `xdp-loader load wwan0` work again instead of exception-counting;
- keeps 991's gro_cells alive, unlike `xdpgeneric`;
- deletes ~60 lines of hand-rolled action handling that the core already does,
  including the `bpf_net_context` dance (it establishes its own).

Then advertise `NETDEV_XDP_ACT_BASIC | NETDEV_XDP_ACT_REDIRECT`.

For tc-BPF: use the raw-IP program shape above on `wwan0`, and keep
`xdp-filter`/any Ethernet-parsing program on the eth ports only.

---

## 8. Still untested

- The full `vmlinux` + `modules` link (running; it will confirm modpost resolves
  `do_xdp_generic` and the Method-B export against a real `Module.symvers`).
- Anything on the actual X3000. Everything above is v6.12 source + x86 compile +
  runtime on ARPHRD_NONE/ARPHRD_ETHER analogues.
- Runtime confirmation that `XDP_SOCKETS`, `DEBUG_INFO_BTF` and `NF_FLOW_TABLE`
  landed in the built image — `zcat /proc/config.gz | grep -E
  'XDP_SOCKETS|DEBUG_INFO_BTF|NF_FLOW_TABLE|BPF_SYSCALL'` on the box settles it.

---

## 9. Re-verified against the pinned kernel, 2026-09-10

Everything in sections 5 and 6 was checked against "v6.12". The tree pins
**6.12.103** (`target/linux/generic/kernel-6.12`: `LINUX_VERSION-6.12 = .103`), and
line numbers have moved enough that it was worth redoing. The conclusions hold,
but three board-specific facts change the matrix and were not previously
recorded.

### 9.1 This board has no DSA switch

`target/linux/mediatek/filogic/base-files/etc/board.d/02_network` line 163:

    ucidef_set_interfaces_lan_wan eth1 eth0

and the board dtsi declares two direct MACs - `gmac0` (2500base-x to `phy5`) and
`gmac1` (gmii to the internal GbE PHY). There is no switch node and no DSA user
ports. So **LAN is `eth1` and WAN is `eth0`, and both are plain `mtk_eth_soc`
netdevs with full native XDP.** The "DSA user ports" row in the section 5 matrix
does not apply to this hardware at all.

### 9.2 One XDP program covers both wired ports

`mtk_xdp_setup()` stores the program on the controller, not the netdev:

    mtk_eth_soc.c:3614   old_prog = rcu_replace_pointer(eth->prog, prog, ...)
    mtk_eth_soc.c:1971   prog = rcu_dereference(eth->prog);

`mtk_xdp_run()` takes `dev` only for statistics and for the redirect/TX calls.
There is no per-netdev program pointer. **Attaching XDP to `eth0` attaches it to
`eth1` as well, and detaching from either detaches from both.** A program that
needs to behave differently on LAN and WAN has to branch on `ctx->ingress_ifindex`
itself.

Two side effects worth knowing: the first attach and the last detach bounce the
interface (`mtk_stop`/`mtk_open` when `!!eth->prog != !!prog`), because the page
pool's DMA direction depends on whether a program is present
(`mtk_eth_soc.c:1731`). And with a program attached, `mtk_change_mtu()` refuses
anything above `MTK_PP_MAX_BUF_SIZE` (`PAGE_SIZE` minus headroom and shared-info,
roughly 3.5 KB) - not a practical limit at 1500.

### 9.3 `wwan0` can be a redirect source but not a redirect target

`kernel/bpf/devmap.c:488`:

    if (!(dev->xdp_features & NETDEV_XDP_ACT_NDO_XMIT))
            return -EOPNOTSUPP;

992 advertises `NETDEV_XDP_ACT_BASIC | NETDEV_XDP_ACT_REDIRECT`, so a program on
`wwan0` can redirect *out*, but nothing can redirect *into* `wwan0`. The wired
ports advertise `NDO_XMIT` and `NDO_XMIT_SG` as well, so `eth1 -> eth0` XDP
forwarding works today and `eth1 -> wwan0` returns `-EOPNOTSUPP`. Closing that
would mean adding `ndo_xdp_xmit` to `mhi_wwan_mbim` - see section 13.

> **Corrected, 2026-09-14.** That gate is the native and devmap path only. A
> generic-mode redirect by ifindex never reaches `devmap.c`:
> `xdp_do_generic_redirect()` (`filter.c:4533`) applies only
> `xdp_ok_fwd_dev()` (`:4554`) - `IFF_UP` and the MTU - then calls
> `generic_xdp_tx()`. The core does not refuse `wwan0` or an AP netdev as a
> generic redirect target. Whether `mbim_tx_fixup()` copes with the skb is a
> different question, and untested. See 23.7.

### 9.4 The XDP gates on `mtk_eth_soc`, and why none of them bite here

    mtk_page_pool_enabled(eth)  ->  mtk_is_netsys_v2_or_greater(eth)

`mt7981_data.version = 2`, so the page pool and therefore XDP are enabled.
`mtk_xdp_setup()` also refuses when `eth->hwlro` is set, but
`eth->hwlro = MTK_HAS_CAPS(caps, MTK_HWLRO)` and `MT7981_CAPS` does not include
`MTK_HWLRO`, so that gate is permanently false on this SoC.

### 9.5 The corrected matrix for this board

| path | native XDP | generic XDP | tc-BPF | GRO | redirect target |
|---|---|---|---|---|---|
| `eth0` (WAN) | yes - `BASIC\|REDIRECT\|NDO_XMIT\|NDO_XMIT_SG` | yes | yes | `napi_gro_receive` (2207) | yes |
| `eth1` (LAN) | same program as `eth0` | yes | yes | same | yes |
| `br-lan` | no `ndo_bpf` | yes | yes | inherited | no |
| wireless (mt76/mac80211) | no `ndo_bpf` in `net/mac80211/iface.c` | yes | yes | `napi_gro_receive` (mt76 `mac80211.c:1550` -> `ieee80211_rx_napi` -> backports `rx.c:5497`) | no |
| `wwan0` | 992, `BASIC\|REDIRECT` | yes | yes (raw-IP aware) | 991 gro_cells | **no** |

Hardware BPF offload still does not exist anywhere on this box; that part of
section 5 is unchanged.

---

## 10. Software vs hardware flow offloading - they are not alternatives

LuCI's *Routing/NAT Offloading* dropdown offers "Software flow offloading" or
"Hardware flow offloading" and no way to pick both. That is not a limitation -
picking both is not a thing. The two UCI options behind the dropdown are nested,
not parallel.

`firewall4` (pinned at `b6e5157527d3`), `fw4.uc`:

    resolve_offload_devices: function() {
        if (!this.default_option("flow_offloading"))
            return [];                       // no flowtable at all
        let devices = this.resolve_hw_offload_devices();
        if (!devices) { ...software device list... }
        return devices;
    }

and `ruleset.uc`:

    flowtable ft {
        hook ingress priority 0;
        devices = { ... };
        counter;
    {% if (fw4.default_option("flow_offloading_hw")): %}
        flags offload;
    {% endif %}
    }

So `flow_offloading` is the master switch that creates the flowtable, and
`flow_offloading_hw` only adds `flags offload` to that same flowtable. Hardware
without software is not expressible. Three states, one dropdown.

It degrades on its own in two places:

- **At ruleset generation.** `resolve_hw_offload_devices()` builds a throwaway
  flowtable with `nft -c` (`nft_try_hw_offload`) and, if that fails, logs
  *"Hardware flow offloading unavailable, falling back to software offloading"*,
  clears the option and returns the software device list.
- **Per flow, at runtime.** `flow_offload_add()` (`nf_flow_table_core.c:275`)
  always inserts the flow into the software rhashtable first, and only then, if
  `nf_flowtable_hw_offload()`, queues an asynchronous hardware attempt. If
  `flow_offload_work_add()` fails it simply returns without setting
  `IPS_HW_OFFLOAD_BIT`, and the flow keeps working through the software fast
  path.

**So "Hardware flow offloading" already means "software, plus hardware for the
flows the hardware will take."** Choosing it never costs the software path.

### 10.1 On this box, hardware offload cannot touch the traffic that matters

`mtk_ppe_offload.c:224-231` resolves the egress PSE port only from the ethernet
controller's own netdevs:

    if (dev == eth->netdev[0])      pse_port = PSE_GDM1_PORT;
    else if (dev == eth->netdev[1]) pse_port = PSE_GDM2_PORT;
    else if (dev == eth->netdev[2]) pse_port = PSE_GDM3_PORT;
    else                            return -EOPNOTSUPP;

`wwan0` is not one of them. With the 5G modem as WAN, **every LAN-to-internet
flow is software-offloaded and nothing else is possible.** Hardware offload has
nothing to accelerate until a wired WAN or a LAN-to-LAN flow appears - and, per
10.2, asking for it costs something real.

That egress gate was the original reason given here, and it is the weaker one.
Checked again on 2026-09-10, a `wwan0` flow never reaches MediaTek code at all:

- `mhi_wwan_mbim`'s `net_device_ops` has exactly four entries - `ndo_open`,
  `ndo_stop`, `ndo_start_xmit`, `ndo_get_stats64` - plus `ndo_bpf` from 992.
  **No `ndo_setup_tc`.** So `nf_flow_table_offload_setup()` takes its `else`
  branch into `nf_flow_table_indr_offload_cmd()`, which calls
  `flow_indr_dev_setup_offload(dev, NULL, TC_SETUP_FT, ...)`.
- **MediaTek registers no indirect flow block.** `flow_indr_dev_register` does
  not appear in any file under `drivers/net/ethernet/mediatek/` -
  `mtk_eth_soc.c`, `mtk_ppe_offload.c`, `mtk_wed.c`, `mtk_ppe.c` and
  `mtk_eth_path.c` all checked. So the indirect dispatch has no MediaTek
  callback to reach.

`mtk_eth_setup_tc_block()` is therefore reachable only through
`ndo_setup_tc` on an mtk netdev, which is what `eth0` and `eth1` have and
`wwan0` does not. Reaching it another way would not even be safe:
`mtk_eth_setup_tc_block_cb()` treats `netdev_priv(dev)` as a `struct mtk_mac *`.

So there are three independent barriers, and the dispatch one is decisive: the
code path does not exist. An empty `/sys/kernel/debug/ppe*/bind` during modem
traffic is the predicted result, not evidence - which is why the test drafted
for this could never have discriminated. Running it remains a cheap
confirmation, but nothing rests on it.

### 10.2 Hardware offload and the XDP flowtable kfunc are mutually exclusive

This is the part that makes the dropdown a real decision rather than a free
upgrade. `nf_flow_table_offload.c:1250`:

    int nf_flow_table_offload_setup(struct nf_flowtable *flowtable,
                                    struct net_device *dev,
                                    enum flow_block_command cmd)
    {
            ...
            if (!nf_flowtable_hw_offload(flowtable))
                    return nf_flow_offload_xdp_setup(flowtable, dev, cmd);

            /* hardware path only, from here down */

`nf_flow_offload_xdp_setup()` on `FLOW_BLOCK_BIND` calls
`nf_flowtable_by_dev_insert()`, and that is the **only** caller - it is the sole
way a device gets into `nf_xdp_hashtable`. That hashtable is what
`nf_flowtable_by_dev()` reads, which is what `bpf_xdp_flow_tuple_lookup()` calls,
which is what the `bpf_xdp_flow_lookup()` kfunc from section 6 is built on:

    nf_flow_table_bpf.c:43   nf_flow_table = nf_flowtable_by_dev(dev);
    nf_flow_table_bpf.c:44   if (!nf_flow_table)
    nf_flow_table_bpf.c:45           return ERR_PTR(-ENOENT);

`nf_flowtable_hw_offload()` is just `flowtable->flags & NF_FLOWTABLE_HW_OFFLOAD`,
which is exactly the `flags offload` that `flow_offloading_hw` emits.

**So switching the LuCI dropdown to "Hardware flow offloading" silently makes
`bpf_xdp_flow_lookup()` return `-ENOENT` forever.** The device is never inserted
into the XDP map. There is no partial mode and no fallback - the check is at the
top of the setup function and it returns.

On this board that trade is strictly bad: hardware offload cannot carry
LAN-to-`wwan0` at all (10.1), so it gives up the only kernel hook that lets an
XDP program consult the flowtable in exchange for nothing. **Leave the
dropdown on Software flow offloading.**

That also corrects the ordering intuition. The flowtable's own hook runs at
`nf_ingress` (`dev.c:5664`), after generic XDP (`dev.c:5616`) and tc ingress
(`dev.c:5656`) - re-verified at 6.12.103; section 5's line numbers were from an
earlier point release. The flowtable never hides traffic from XDP. But choosing
hardware offload does remove XDP's ability to *query* it.

---

### 10.3 fw4 leaves L3-only interfaces out of the flowtable

Turning software flow offloading on produced this:

    flowtable ft {
            hook ingress priority filter
            devices = { "br-lan", "eth0" }
            counter
    }

`wwan0` is missing, and flow offload needs **both** directions' devices, so no
LAN-to-internet flow could be offloaded at all. The flowtable exists and looks
healthy; nothing reports the omission.

The cause is in `fw4.uc:619-623`. A network record is built as

    device:  ifc.l3_device ?? ifc.device,
    physdev: ifc.device,

and `resolve_offload_devices()` builds the flowtable from
`zone.related_physdevs`, which is fed only from `physdev` - `ifc.device` alone,
never `l3_device`. A `proto modemmanager` interface has no L2 device: `ubus
call network.interface dump` shows the `wwan` interface with `"l3_device":
"wwan0"` and **no `"device"` field at all**, so `physdev` is undefined, the
guard at `fw4.uc:2071` skips it, and the device never enters the list. Setting
`option device` on the zone does not help either - `fw4.uc:2078` pushes that
into `match_devices`, which the flowtable never reads.

`package/network/config/firewall4/patches/001-flowtable-fall-back-to-l3-device.patch`
changes `physdev` to `ifc.device ?? ifc.l3_device`. It only ever adds devices
that previously resolved to nothing: where `device` exists it still wins, so
PPPoE and VLAN setups keep resolving to their lower device unchanged. `physdev`
is read in exactly two places, both inside flowtable resolution, so nothing
else in fw4 is affected.

This also means the section 10.1 claim about PPE has still never been tested in
either direction. Even with `flow_offloading_hw=1`, PPE was never offered a
modem flow, because the flowtable did not contain `wwan0`.

---

## 11. WED is present, wired up, and switched off

`mt7981-wo-firmware` ships in `DEVICE_PACKAGES` and
`CONFIG_NET_MEDIATEK_SOC_WED=y` is set in the filogic target config. OpenWrt's
`117-complete-mt7981b-dtsi.patch` adds the full hardware description -
`wed@15010000` (`mediatek,mt7981-wed`), `wo_ccif0`, `wo_ilm0`, `wo_dlm0`,
`wo_cpuboot`, the `wo-emi`/`wo-data` reserved regions and `wed_pcie` - and
`mtk_eth_soc.c:5009` looks up the `mediatek,wed` phandle and calls
`mtk_wed_add_hw()`.

The wireless half never attaches. In openwrt/mt76 at the pinned commit
`39c960c3ada5`, `mt7915/mmio.c`:

    static bool wed_enable;
    module_param(wed_enable, bool, 0644);
    ...
    int mt7915_mmio_wed_init(...)
    {
            if (!wed_enable)
                    return 0;

The default is false and **nothing in the tree sets it** - a grep of `package/`,
`target/` and `x3000/` for `wed_enable` returns nothing. So WED is inert and the
WO firmware is never requested.

Before turning it on, note what it would buy. Its *forwarding* acceleration is
PPE-driven: `mtk_wed_setup_tc_block()` binds only
`FLOW_BLOCK_BINDER_TYPE_CLSACT_INGRESS`, and `mtk_wed_flow_add()` /
`mtk_wed_flow_remove()` are called from PPE flow entries. Per section 10.1 PPE
cannot carry `wwan0`, so that half would only ever accelerate wireless traffic to
and from the wired ports.

It is not only a forwarding engine, though. `mtk_wed_get_rx_capa()` returns true
on this SoC (see section 12), so WED v2 also runs its own RX datapath with the WO
MCU - which is exactly what `mt7981-wo-firmware` is for. Whether that alone saves
CPU with no PPE flows bound cannot be settled from the source; it has to be
measured. `mtk_wed_debugfs.o` is already built (section 13.3), so measuring it is
cheap once it is on.

Enabling it is one line - `mt7915e wed_enable=1` in a file under
`/etc/modules.d/` -
and it changes the wireless RX ring setup, so it is a change to make deliberately
and measure, not a free switch.

---

## 12. Odds and ends, re-verified at 6.12.103

Small claims that were resting on inference, now checked directly.

- **RX hook order.** `__netif_receive_skb_core()`: generic XDP `dev.c:5616`, tc
  ingress `dev.c:5656`, netfilter ingress `dev.c:5664`, bridge `rx_handler`
  `dev.c:5690`. Same order as section 5, different line numbers.
- **The kfunc really is built.** `net/netfilter/Makefile` at 6.12.103:
  `nf_flow_table_xdp.o` is unconditional in `nf_flow_table-objs` (line 145), and
  `nf_flow_table_bpf.o` is added by `CONFIG_DEBUG_INFO_BTF_MODULES` (148) or
  `CONFIG_DEBUG_INFO_BTF` (150). `kmod-nf-flow` builds `nf_flow_table.ko` as a
  module, so `_BTF_MODULES` is the gate that applies, and config.common sets it.
- **`kmod-nft-offload` composition.** It selects `NF_FLOW_TABLE_INET` and
  `NFT_FLOW_OFFLOAD` and ships `nf_flow_table_inet.ko` + `nft_flow_offload.ko`,
  depending on `kmod-nf-flow` for `nf_flow_table.ko` - which is where the XDP
  hook and the kfunc live. `kmod-nf-flow` also lists `CONFIG_NF_FLOW_TABLE_HW`
  and autoloads `nf_flow_table_hw`; neither exists in 6.12 (the Kconfig has only
  `NF_FLOW_TABLE`, `_INET` and `_PROCFS`). Harmless - kmodloader skips a module
  it cannot find - but the `/etc/modules.d/` entry names a phantom.
- **LAN/WAN assignment.** `ucidef_set_interfaces_lan_wan()` in
  `package/base-files/files/lib/functions/uci-defaults.sh:89` takes `$1` as LAN
  and `$2` as WAN, so `eth1 eth0` really is LAN `eth1`, WAN `eth0`.
- **Wired GRO is the main path.** `napi_gro_receive` at `mtk_eth_soc.c:2207` sits
  in the `mtk_poll_rx()` per-descriptor loop straight after `eth_type_trans()`
  and the PPE check. There is no other delivery call in the driver.
- **BBRv3 is the boot default.** `kmod-tcp-bbr` installs
  `package/kernel/linux/files/sysctl-tcp-bbr.conf` as `/etc/sysctl.d/12-tcp-bbr.conf`,
  containing `net.ipv4.tcp_congestion_control=bbr`, and 990 makes the module
  registered under that name BBRv3 (`#define BBR_VERSION 3`,
  `MODULE_VERSION(__stringify(BBR_VERSION))`, 1719 added lines in `tcp_bbr.c`).
- **The SoC wifi is an mt7915e device.** `mt798x_wmac_of_match` in mt76's
  `mt7915/soc.c` matches `mediatek,mt7981-wmac`, so the built-in radio binds the
  same module that carries the `wed_enable` parameter. `options mt7915e
  wed_enable=1` is the right spelling.
- **The mt76 package carries no patches.** `package/kernel/mt76/` contains only a
  Makefile - no `patches/`, no `files/`, and no occurrence of `wed` anywhere. The
  "nothing enables WED" finding in section 11 survives that stronger check.
- **Correction: WED v2 does have an RX datapath.** An earlier revision of this
  document claimed WED had no PPE-independent accelerator on this SoC. That was
  wrong, and it came from checking only hardware RRO. `mtk_wed_get_rx_capa()`
  (`include/linux/soc/mediatek/mtk_wed.h:251`) is

      if (dev->version == 3)
              return dev->wlan.hw_rro;
      return dev->version != 1;

  and `hw->version = eth->soc->version`, which is 2 for MT7981 - so it returns
  **true**. It gates RX ring setup and teardown, RX buffer allocation, the ext
  interrupt masks, and `mtk_wed_wo_reset()`/`mtk_wed_wo_deinit()`. WED v2 runs a
  real RX path driven by the WO MCU, which is what `mt7981-wo-firmware` feeds.
  What is genuinely off is hardware RRO specifically: `mtk_wed_hwrro_init()` and
  `mtk_wed_start_hw_rro()` both need `dev->wlan.hw_rro`, which is v3-only and
  which mt7915 never sets. Whether the v2 RX path saves CPU with no PPE flows
  bound is not answerable from source - it needs measurement.
- **No hardware BPF offload.** No `NETDEV_XDP_ACT_HW_OFFLOAD` in `mtk_eth_soc.c`,
  `net/mac80211/iface.c`, `net/dsa/user.c` or `net/bridge/br_device.c`.
- **AF_XDP works, but only in copy mode.** `CONFIG_KERNEL_XDP_SOCKETS=y` is set, so
  AF_XDP sockets bind fine - but `mtk_eth_soc.c` has zero occurrences of
  `ndo_xsk_wakeup` and zero of `NETDEV_XDP_ACT_XSK_ZEROCOPY`, so there is no
  zero-copy path on the wired ports. Worth stating because the config symbol
  invites the opposite assumption.
- **No XDP RX metadata.** `mtk_eth_soc.c` implements no `xdp_metadata_ops`, so
  none of `xmo_rx_hash`, `xmo_rx_timestamp` or the VLAN accessor exist. A BPF
  program on `eth0`/`eth1` cannot read the hardware RX hash through the
  `bpf_xdp_metadata_*` kfuncs, even though the driver computes a hash for the PPE
  path. Implementing `xdp_metadata_ops` would be a small, self-contained driver
  patch and is the cheapest of the driver-side enhancement candidates.

---

## 13. WED and PPE: what is actually there to hook into

### 13.1 PPE has a debugfs surface nobody is using

`drivers/net/ethernet/mediatek/Makefile` puts `mtk_ppe_debugfs.o` in `mtk_eth-y`
unconditionally, and `CONFIG_DEBUG_FS=y` in the generic config. So every build
already exposes, per PPE unit:

    /sys/kernel/debug/ppe0/entries    all FOE table entries
    /sys/kernel/debug/ppe0/bind       only the bound (offloaded) ones
    /sys/kernel/debug/ppe1/...        same, second unit

`mt7981_data.has_accounting = true`, so each line carries live per-flow counters:

    eth=<src>-><dst> etype=0800 vlan=0,0 ib1=... ib2=... packets=N bytes=N

**This is the falsification test for section 10.1.** The claim that PPE cannot
carry LAN-to-`wwan0` was derived from reading `mtk_ppe_offload.c`. Run a
speedtest through the modem and read `/sys/kernel/debug/ppe*/bind`: if the claim
holds, no entry appears for that traffic. If entries do appear, the source
reading is wrong and this document needs correcting. That is worth doing before
anyone acts on section 10.2's recommendation.

Both units are in use, so check both. `mtk_eth_soc.c:5586-5592` assigns
`ppe_idx` per MAC, and `mt7981_data.ppe_num = 2`, so gmac0 uses ppe0 and gmac1
uses ppe1.

### 13.2 The PPE binding policy is hardcoded

`mtk_ppe_init()` writes fixed constants that upstream exposes no way to change:

    mtk_ppe.c:1077   val = FIELD_PREP(MTK_PPE_BIND_RATE_BIND, 30) |
    mtk_ppe.c:1078         FIELD_PREP(MTK_PPE_BIND_RATE_PREBIND, 1);
    mtk_ppe.c:1058   val = FIELD_PREP(MTK_PPE_UNBIND_AGE_MIN_PACKETS, 1000) |
    mtk_ppe.c:1059         FIELD_PREP(MTK_PPE_UNBIND_AGE_DELTA, 3);

`BIND_RATE_BIND = 30` is the packets-per-tick a flow must sustain before the
hardware will bind it, and `UNBIND_AGE_MIN_PACKETS`/`DELTA` govern when a bound
flow is aged out. Short-lived flows never reach the bind threshold and are
handled entirely in software.

If PPE offload ever matters on this box - a wired WAN, or heavy LAN-to-LAN -
these are the two registers worth turning into module parameters or DT
properties, in the same shape as 993: default to the current values, patch only
`mtk_ppe_init()`, and leave behaviour unchanged unless the parameter is set.
That is a small, self-contained patch. It is not worth writing while the 5G
modem is the only WAN, because nothing binds.

### 13.3 WED has debugfs too, but only when it runs

`mtk_wed_debugfs.o` is gated on `CONFIG_NET_MEDIATEK_SOC_WED` **and**
`CONFIG_DEBUG_FS`, both of which are set. So if `wed_enable=1` were ever set, the
WED counters would appear without any further work - which makes measuring the
question in section 11 cheap rather than speculative.

---

## 14. Getting work off CPU0

All four MHI MSI vectors land on CPU0 (`mhi_init_irq_setup` assigns event ring
`n` to vector `n+1`), and the affinity write is refused - the MediaTek MSI domain
sets `MSI_FLAG_NO_AFFINITY`, so `/proc/irq/*/smp_affinity` returns `-EPERM`. The
interrupt cannot be moved. The processing after it can.

### 14.1 cpumap works, but it costs GRO

Verified end to end at 6.12.103:

- `do_xdp_generic()` (`dev.c:5262`) dispatches `XDP_REDIRECT` to
  `xdp_do_generic_redirect()`.
- `xdp_do_generic_redirect_map()` (`filter.c:4570`) handles
  `BPF_MAP_TYPE_CPUMAP` via `cpu_map_generic_redirect()`.
- `cpumap.o` is built by `CONFIG_BPF_SYSCALL`, always on here.
- 992 routes through `do_xdp_generic()` and advertises
  `NETDEV_XDP_ACT_REDIRECT`.

So an XDP program on `wwan0` can redirect into a CPUMAP pinned to CPU1 today,
with the image as built. The catch is the delivery on the far side:
`cpumap.c:364` is `netif_receive_skb_list(&list)` - **no GRO**. Redirecting to a
cpumap therefore bypasses 991's `gro_cells` entirely and hands the stack
un-aggregated packets on the other core. That is a trade, not a win, and 991
exists because the aggregation was worth having.

The native wired path has the same capability (`__xdp_do_redirect_frame` ->
`cpu_map_enqueue`) with the same caveat.

### 14.2 RPS does the same job and keeps GRO

`CONFIG_RPS=y`, `CONFIG_RFS_ACCEL=y` and `CONFIG_XPS=y` are all set in
`target/linux/mediatek/filogic/config-6.12`. The modem receive path is:

    MHI IRQ (CPU0) -> mhi_ev_task -> mhi_mbim_rx
      -> 992's do_xdp_generic hook, if a program is attached
      -> 991's gro_cells_receive, which queues on this_cpu (gro_cells.c:28)
      -> gro_cell_poll -> napi_gro_receive
      -> gro_normal_one -> netif_receive_skb_list_internal()
      -> __netif_receive_skb_core

and `netif_receive_skb_list_internal()` (`dev.c:6000`) applies RPS to that
post-GRO list:

    dev.c:6016   if (static_branch_unlikely(&rps_needed)) {
    dev.c:6019           int cpu = get_rps_cpu(skb->dev, skb, &rflow);
    dev.c:6021           if (cpu >= 0) {
    dev.c:6024                   enqueue_to_backlog(skb, cpu, &rflow->last_qtail);

So RPS runs **after** GRO has already aggregated, and moves the aggregated
super-packets to another core. That is strictly the better shape than cpumap
here: it keeps 991, needs no BPF program, and is a single sysfs write.

    echo 2 > /sys/class/net/wwan0/queues/rx-0/rps_cpus   # 0x2 = CPU1

Caveats worth stating plainly. RPS hashes per flow, so one big TCP stream moves
to one other core rather than spreading; on a dual-core A53 that still splits
IRQ plus GRO on CPU0 from stack processing on CPU1, which is the useful split.
It costs an IPI per batch, so at low rates it is a small loss. And the captures
on hand showed both CPUs at 0-6 percent during the stall, so **this box has not
yet been shown to be CPU-bound at all** - which makes RPS a lever to test at
250+ Mbps, not a known win. Measure `cpu0_busy`/`cpu0_si` in `dlwatch` with it
off and on before keeping it.


### 14.3 Measured, 2026-09-10: this box is not CPU-bound

> **Instrument warning, added 2026-09-11.** The figures below come from `dlwatch`
> sampling `cpu*_si` - softirq percentages out of `/proc/stat`. Section 18.3
> shows that on this box `/proc/stat` does not conserve time under load: summed
> across every state it returned 67 to 96 seconds against an 80-second budget,
> with the variance landing in `system`. At `CONFIG_HZ=100` the sampler has 10 ms
> resolution against NAPI polls lasting tens of microseconds. Treat small
> softirq-normalised deltas here as unreliable. Figures built on the `busy`
> columns, and conclusions that only need an order of magnitude, are less
> exposed.

Four alternating 60-second legs through the modem under OpenSpeedTest
(multi-connection, so flows hash across CPUs - the favourable case for RPS),
sampled by `dlwatch`:

| leg | rps_cpus | pkt/s | cpu0_busy | cpu0_si | cpu1_busy | cpu1_si |
|---|---|---|---|---|---|---|
| 1 | 0 | 15927 | 20.3 | 12.1 | 3.4 | 1.0 |
| 2 | 2 | 23168 | 22.9 | 12.1 | 11.6 | 8.3 |
| 3 | 0 | 20829 | 25.8 | 15.4 | 4.7 | 1.5 |
| 4 | 2 | 18949 | 20.2 | 10.0 | 10.4 | 7.4 |

Read the labels carefully: `rps_cpus=2` is not an experimental setting, it is
**this box's default**. `network.globals.packet_steering='1'`, and
`packet-steering.uc` assigns `wwan0`'s rx queue to CPU1 - it deliberately biases
away from the CPU running ethernet NAPI. So the legs are OpenWrt's default
steering on versus disabled, not off versus on.

Throughput varied 45 percent across legs, so the CPU figures only mean anything
normalised by packet rate (softirq percent per 1000 pkt/s):

| | cpu0_si per kpps | total_si per kpps |
|---|---|---|
| disabled (legs 1, 3) | **0.750** | 0.817 |
| default (legs 2, 4) | **0.525** | 0.899 |

**RPS works.** `cpu1_si` moves from about 1 to about 8; the work really is
relocating. It takes roughly 30 percent of CPU0's per-packet softirq off that
core, and costs about 10 percent more softirq overall - the IPI, the queueing
and the cache misses. That is the textbook signature: relocation, not
elimination.

**It does not change throughput.** The fastest leg was steering-on and the
second fastest was steering-off; the effect does not track the treatment. That
spread is the cellular link, which is why the legs alternate.

**And the conclusion that matters.** `cpu0_busy` peaked at 25.8 percent and
`cpu1_busy` at 11.6 percent, at roughly 250 Mbps. Extrapolating linearly, CPU0
would not saturate until something like 80 kpps, near 1 Gbps. Even the 41,194
pkt/s peak from the stall captures would leave CPU0 around half idle. **This
router is not CPU-bound and will not be on this WAN.**

The wireless path was measured separately - see 14.5. It costs about the same
per packet, so this conclusion holds for both, at modem rates.

An earlier revision of this section said to keep the default steering on "for
CPU0 headroom against jitter". That was an unmeasured claim and it is withdrawn
- see 14.4.

This is the measurement section 15 asked for, and it answers it in the
negative: **#101 and #102 stay parked.** They reduce per-packet CPU cost on a
machine with three quarters of CPU0 idle at full modem rate. There is no
bottleneck there to attack, and no amount of driver work creates one.



### 14.4 The latency question is not resolvable on this hardware

Throughput could not distinguish the steering settings, because the box is not
CPU-bound. The obvious follow-up was latency under load, comparing
`packet_steering` 0, 1 and 2 with `fping` during a sustained transfer. That test
was run on 2026-09-10 and produced nothing usable, for two separate reasons
worth recording so nobody repeats it.

**The probe target was wrong.** `fping -c 285 -p 200` is five echoes a second,
and six legs is about 1,700 ICMP packets to 1.1.1.1 in six minutes. Cloudflare
rate-limits ICMP hard. Loss went 17, 82, 72, 83, 84, 98 percent across the legs -
and legs 1 and 4 were the *same* setting, `packet_steering=0`, at 17 and 83
percent. The variable was elapsed time, not the treatment. The reported
`min/avg/max` are then statistics over whichever packets survived a throttle,
which is not a latency distribution.

The link itself was fine throughout: `dlwatch` recorded a mean of 23,097 pkt/s
across all 350 samples of the run, higher than any leg of the 14.3 test. Nothing
was lost on the WAN.

**And the effect is below the noise floor anyway.** At 25 percent CPU
utilisation, the queueing delay attributable to CPU scheduling is on the order of
microseconds. Cellular round trips run 25 to 200 ms with tens of milliseconds of
variance. The signal is three to four orders of magnitude smaller than the
measurement path's noise. No ping-based test through this modem can resolve it,
whatever the target or interval - so a better-designed version of this test would
not have helped either.

**Conclusion.** Packet steering makes no difference this hardware can
demonstrate, in throughput or in latency. Leave it at OpenWrt's default because
that is the default and costs nothing observable, not because a benefit has been
shown.

That also disposes of the two settings not tested. `steering_flows` (RFS) is
provably not in this path: `get_rps_cpu()` consults
`net_hotdata.rps_sock_flow_table`, which `rps_record_sock_flow()` fills from
socket receive paths only. Forwarded traffic has no local socket, so the identity
check at `dev.c:4771` fails and it falls through to plain RPS. RFS can only
affect flows terminating on the router itself. `packet_steering=2` differs from 1
only in CPU distribution - on two cores it puts CPU0 back in the mask, so roughly
half the flows would be steered onto the core already taking every MHI vector and
the ethernet NAPI, and would still pay the backlog cost, since `get_rps_cpu()`
does not compare its result against the current CPU. Predicted neutral to worse,
and equally unresolvable here.

### 14.5 Wireless costs the same as wired, and cost does not scale with flow count

> **Instrument warning, added 2026-09-11.** The figures below come from `dlwatch`
> sampling `cpu*_si` - softirq percentages out of `/proc/stat`. Section 18.3
> shows that on this box `/proc/stat` does not conserve time under load: summed
> across every state it returned 67 to 96 seconds against an 80-second budget,
> with the variance landing in `system`. At `CONFIG_HZ=100` the sampler has 10 ms
> resolution against NAPI polls lasting tens of microseconds. Treat small
> softirq-normalised deltas here as unreliable. Figures built on the `busy`
> columns, and conclusions that only need an order of magnitude, are less
> exposed.

Measured 2026-09-10 from a 5 GHz client (channel 100, 160 MHz) pulling parallel
downloads through the modem - the same routed path to the same destination as
the wired runs, differing only in the client link. Sampled with `IFACE=phy1-ap0
dlwatch` and analysed by endpoint difference over interval count.

Direction inverts between interfaces and this is easy to get wrong: on `wwan0`
the download is **rx**; on an AP interface it is **tx**, because the router is
transmitting to the client.

| concurrent flows | download pkt/s | cpu0 busy/si | cpu1 busy/si | si per 1000 pkt |
|---|---|---|---|---|
| 1 | 17,718 | 18.3 / 9.7 | 25.3 / 6.2 | **0.896** |
| 4 | 13,215 | 14.8 / 7.3 | 18.7 / 5.2 | **0.944** |
| 16 | 14,096 | 16.3 / 8.3 | 22.6 / 4.8 | **0.930** |
| 64 | 3,505 | 8.2 / 1.8 | 9.2 / 1.1 | **0.837** |

Two results.

**Wireless costs the same per packet as wired.** 0.896 against the wired
baseline's 0.897 at 21,059 pkt/s. The prediction going in was two to three times
worse, because of mac80211 and mt76 processing. It is not. The likely reason is
that both paths share the dominant cost - the modem RX side, MHI plus MBIM NTB
de-aggregation plus gro_cells - and the egress difference is a smaller share
than assumed. What changes is placement, not total: `cpu1_busy` runs higher on
the wireless path because packet steering pins mt76's threads to CPU1.

**Per-packet cost does not scale with flow count.** Across 1 to 64 concurrent
flows it stays within about 6 percent of 0.90 with no trend. This was tested
because the single-client speedtest is the easiest possible load and the
concern - reasonable - was that many clients would cost more per packet. It does
not, at least not through 64 flows.

Limits on that. Throughput *fell* as flows rose, from 17.7k to 3.5k pkt/s,
because 64 TCP flows over a cellular link mostly contend with each other. So
this tested many-flows-at-low-rate, never many-flows-at-high-rate, and the
64-flow row sits on low load where baseline noise dominates. And 64 flows from
one client is not 16 clients: separate stations bring more bridge FDB entries,
per-STA mac80211 queues, more broadcast and ARP, and airtime contention. Those
are real, but they are per-station wireless overhead rather than forwarding-path
packet cost, and are not what an XDP fast path would reduce.

An earlier revision of this section reported a wireless measurement from a run
whose CSV had been appended to an existing capture of a different interface, and
analysed with an awk that computed its first delta against the header row. Both
faults inflated the numbers. The conclusion was right; the data was not. These
figures replace it.

---

## 15. First pass at scoping the XDP fast path (superseded by section 16)

Kept for the driver-requirement inventory in 15.1 and 15.3, which still
hold. The conclusion in 15.4 does not: it parked #101 and #102 on "no
bottleneck demonstrated", which is a weaker and less useful reason than the
one section 16 establishes from driver source. Read 16 for the verdict.

Sections 9.3 and 13 left `ndo_xdp_xmit` on `mhi_wwan_mbim` as the headline
enhancement: it would make `wwan0` a valid redirect target and open a LAN to
modem XDP path. Scoping it against the driver turned up enough to argue for
deferring it.

### 15.1 What the driver would need

`mhi_mbim_ndo_xmit()` is skb-shaped throughout. `mbim_tx_fixup()` does
`skb_cow_head()` then `skb_push()` to prepend `struct mbim_tx_hdr` - NTH16 plus
NDP16 plus two DPE16, 28 bytes packed - and hands the result to
`mhi_queue_skb()`. Three problems follow from that.

**Framing.** An `xdp_frame` has no `skb_push()`. The header would be written by
adjusting `frame->data` and `frame->len` by hand, after checking
`frame->headroom` is actually 28 bytes or more rather than assuming the usual
`XDP_PACKET_HEADROOM`. Not hard, but it is open-coded pointer work in a path
where getting it wrong corrupts the NTB the modem parses. `mhi_queue_buf()`
exists and is the right queue call.

**Locking.** `mhi_mbim_ndo_xmit()` already takes `spin_lock_irqsave(&mbim->tx_lock)`,
commented "Serialize MHI channel queuing and MBIM seq", because several links
share one MHI channel and the NTB carries a sequence number. `ndo_start_xmit` is
serialized per queue by the netdev layer on top of that; **`ndo_xdp_xmit` is
not**, and can run concurrently on every CPU that has a redirecting NAPI. It
would have to take the same lock - so every redirected frame contends a spinlock
with normal TX, on a dual-core A53. That erodes a good part of what XDP is for.

**Completion.** `mhi_mbim_ul_callback()` opens with

    struct sk_buff *skb = mhi_res->buf_addr;
    struct net_device *ndev = skb->dev;

It hard-assumes the buffer is an skb and dereferences `skb->dev` for stats.
`mhi_result` carries no type tag, so mixing `xdp_frame`s into the same channel
means inventing one: a side table, a tagged wrapper (which reintroduces the
per-frame allocation XDP exists to avoid), or pointer-bit games. All of it lands
in a hot completion path.

Declining `NETDEV_XDP_ACT_NDO_XMIT_SG` avoids multi-buffer frames entirely -
`devmap.c:491` refuses fragmented frames when SG is not advertised - so at least
that part can be sidestepped.

### 15.2 The part that makes it a project rather than a patch

`ndo_xdp_xmit` on its own buys nothing usable, and not for a subtle reason.

Generic XDP runs at `dev.c:5616`, tc ingress at `5656`, netfilter ingress at
`5664`. An `XDP_REDIRECT` from `eth1` to `wwan0` hands the frame to the modem's
transmit path directly - **the packet never enters netfilter at all**, so
masquerading never happens. A LAN packet would leave the modem still carrying a
private source address and be dropped upstream.

Making it work means doing the NAT in BPF: look the flow up with
`bpf_xdp_flow_lookup()` (which is what section 6 is about - the returned
`flow_offload_tuple_rhash` gives access to `tuplehash[!dir].tuple`, carrying the
translated addresses and ports), rewrite the headers, fix the checksums, then
redirect. That is the actual shape of the work, and #101 is only its first
third.

### 15.3 Two cheaper paths already exist

- **tc-BPF `bpf_redirect()`** from `eth1` to `wwan0` works today with no driver
  change at all. It is skb-based, so slower than native XDP, but it is a real
  fast path available now.
- **The software flowtable now covers `wwan0`** (section 10.3). It skips
  conntrack re-lookup and the filter/nat/mangle chains at `nf_ingress`, and -
  unlike an XDP redirect - it does the NAT itself, because it *is* netfilter.

### 15.4 The measurement that is missing

> **Superseded, 2026-09-11.** The measurement specified here is expressed in
> softirq-per-1000-packets. Section 18.3 shows that quantity is not measurable on
> this hardware with `/proc/stat`. #114 was run against this specification and
> produced three mutually inconsistent answers before the instrument was
> identified as the problem. Do not re-run it as written.

Everything above is optimising a bottleneck nobody has demonstrated. Every
capture taken shows both CPUs at 0-6 percent, including during the 43-second
deadlock at full downlink rate. The box has never been shown to be CPU-bound.

So the order is: measure first. #98 (RPS) is a one-line sysfs write that shows
whether moving work off CPU0 changes anything at all. If it does not, the whole
XDP fast-path line of work is solving a problem this hardware does not have, and
#101 and #102 should stay parked. If it does, that same measurement says how
much headroom is actually on the table and whether it justifies a driver patch
plus a NAT-rewriting BPF program.

**Recommendation: park #101 and #102 behind a measurement.** They are not
blocked by anything technical - the analysis is done and the approach is sound -
but neither should be built on the assumption that this box needs them.

## 16. The pre-skb question, settled at the source

Section 15 parked #101 and #102 because no bottleneck had been demonstrated.
That was the wrong reason. The size of the prize was never in doubt - the 14.3
measurement works out to roughly 9 us of softirq per forwarded packet (0.897
percent of one CPU per 1000 pkt/s), and a working pre-allocation bypass would
skip most of that, not one percent of it. The only real question was whether
such a bypass can be reached on this hardware. This section answers that from
driver source instead of from throughput guesses.

### 16.1 On the wired ports the pre-skb win is real

`mtk_eth_soc` is a genuine page-pool XDP driver. In `mtk_poll_rx()`:

    2481   xdp_init_buff(&xdp, PAGE_SIZE, &ring->xdp_q);
    2482   xdp_prepare_buff(&xdp, data, MTK_PP_HEADROOM, pktlen, false);
    2486   ret = mtk_xdp_run(eth, ring, &xdp, netdev);
    2491   if (ret != XDP_PASS) goto skip_rx;
    2493   skb = napi_build_skb(data, PAGE_SIZE);
    ...
    2565   skb->protocol = eth_type_trans(skb, netdev);
    2585   skip_rx:

The program runs at 2486 on a buffer that is still nothing but DMA'd page-pool
memory. `napi_build_skb()` sits at 2493 and is reached only on `XDP_PASS`;
`eth_type_trans()` is seventy lines further on. Anything the program drops,
transmits or redirects never gets an `sk_buff` at all. So on `eth0` and `eth1`
the hook is genuinely ahead of allocation.

Two facts make it cheap to try. `mtk_page_pool_enabled()` is just
`mtk_is_netsys_v2_or_greater()`, and `mt7981_data.version = 2`, so this SoC
always takes the page-pool path whether or not a program is attached - attaching
one adds a `bpf_prog_run_xdp()` call and switches the pool's DMA direction to
bidirectional - `pp_params.dma_dir = rcu_access_pointer(eth->prog) ?
DMA_BIDIRECTIONAL : DMA_FROM_DEVICE`, just above the `__xdp_rxq_info_reg()` call
at 2115 - nothing structural. That DMA change is *why* the link has to bounce:
the page pool must be rebuilt. It does bounce the link once:
`mtk_xdp_setup()` calls `mtk_stop()`/`mtk_open()` when the program count crosses
zero.

### 16.2 But on the wired ports every ifindex-based helper reads a dummy netdev

MT7981 runs two netdevs on one DMA ring and one NAPI, so the driver has no real
device to register the RX queue against and uses a placeholder:

    2115   err = __xdp_rxq_info_reg(xdp_q, eth->dummy_dev, id,
                                   eth->rx_napi.napi_id, PAGE_SIZE);

    5724   eth->dummy_dev = alloc_netdev_dummy(0);

`alloc_netdev_dummy()` calls `alloc_netdev()` with `init_dummy_netdev_core`,
which sets `reg_state = NETREG_DUMMY` and never registers the device. Its
`ifindex` therefore stays 0 and it appears in no namespace's device list. That
one line breaks three things at once, because `xdp->rxq->dev` is what the BPF
side reads:

- `ctx->ingress_ifindex` compiles to `xdp->rxq->dev->ifindex`
  (`filter.c:10246-10255`), so it reads **0** on both wired ports. A program
  cannot tell which port a packet arrived on, and has no real ifindex to hand to
  anything else.
- `bpf_fib_lookup()` needs that ifindex, so it is unusable for the same reason.
- `bpf_xdp_flow_lookup()` calls `nf_flowtable_by_dev(xdp->rxq->dev)`
  (`nf_flow_table_bpf.c`), and `nf_flowtable_by_dev()` keys its hashtable on the
  `struct net_device *` pointer itself. Only devices named in the nftables
  flowtable are ever inserted, so the dummy pointer never matches and the lookup
  returns `-ENOENT` for every packet, permanently.

This is not a configuration problem. Adding `eth1` to the flowtable does not fix
it, and it is unrelated to whether hardware offload is on or off.
`bpf_xdp_flow_lookup()` is structurally unusable on the wired ports of this SoC.

What does still work there: `XDP_DROP`, `XDP_TX`, and `bpf_redirect()` /
`bpf_redirect_map()`. Redirect survives because `mtk_xdp_run()` passes the real
netdev to `xdp_do_redirect(dev, xdp, prog)` as a separate argument (line 1981);
only helpers that read `rxq->dev` are affected.

### 16.3 On wwan0 the helpers work and the pre-skb win does not exist

The modem path is the mirror image. 992 runs the program through
`do_xdp_generic()`, and `bpf_prog_run_generic_xdp()` takes its rxq from
`netif_get_rxqueue(skb)` (`dev.c:5079-5080`) - the real device. So on `wwan0`,
`ctx->ingress_ifindex`, `bpf_fib_lookup()` and `bpf_xdp_flow_lookup()` all
behave correctly, and since section 10.3 put `wwan0` in the flowtable, the
lookup can actually hit.

The price is exactly the thing the pre-allocation argument is about: 992 reaches
XDP only after `netdev_alloc_skb()` and `skb_copy_bits()` have already run,
because MBIM aggregation packs many datagrams into one 32 KB DMA buffer and each
has to be copied out before it can be inspected. The 992 patch header has always
said this. There is no pre-allocation saving available on the modem path, and
creating one would mean rebuilding the MBIM RX path around a page pool, not
adding a hook.

Also confirmed: `do_xdp_generic()` implements `XDP_REDIRECT` itself via
`xdp_do_generic_redirect((*pskb)->dev, ...)` and `XDP_TX` via
`generic_xdp_tx()`, returning `XDP_DROP` to signal the skb was consumed
(`dev.c:5262`). 992's `if (do_xdp_generic(...) != XDP_PASS) return false;` is
correct - redirect is fully wired, with the real device.

### 16.4 The two halves sit on opposite ends of the box

|                                    | eth0 / eth1 (native) | wwan0 (992)   | br-lan, AP netdevs |
|------------------------------------|----------------------|---------------|--------------------|
| Hook runs before `sk_buff` alloc   | yes                  | no            | no                 |
| `ctx->ingress_ifindex` usable      | no - dummy dev, 0    | yes           | yes                |
| `bpf_xdp_flow_lookup()` usable     | no - dummy dev       | yes           | not in flowtable   |
| `bpf_fib_lookup()` usable          | no                   | yes           | yes                |
| Valid `bpf_redirect()` target      | yes (`NDO_XMIT`)     | no (#101)     | yes, generic only  |
| `ndo_bpf` in driver                | yes                  | yes (992)     | no                 |

Neither `mac80211` nor the bridge implements `ndo_bpf` - no `ndo_bpf` and no
`xdp_set_features_flag` anywhere in `iface.c`, `main.c` or `br_device.c` - so
`br-lan` and the AP netdevs are generic-XDP-only.

Reading down the columns: the ports where a program runs early cannot look a
flow up, and the port where it can look a flow up cannot run early. And every
packet that matters on this box crosses `wwan0`.

### 16.5 What survives, and it is not nothing

> **Built and measured, 2026-09-14; still open.** See section 23. The lookup
> works - 98.8% hit on `wwan0`. The redirect fires on nothing, because every
> flow here is `FLOW_OFFLOAD_XMIT_NEIGH` and the `tuple.out` MAC addresses this
> design reads exist only for `XMIT_DIRECT`. The gate analysis below is correct
> as far as it goes; it does not check which arm of the union is populated,
> which is what decides it. Whether that is fixable is an open question with a
> named suspect - see 23.8.

**Shape A - wwan0 ingress to eth1 or an AP netdev, using `bpf_xdp_flow_lookup()`.**
Needs no kernel patch. Every gate is already satisfied:
`CONFIG_KERNEL_DEBUG_INFO_BTF_MODULES=y` builds `nf_flow_table_bpf.o`
(`net/netfilter/Makefile:148`); hardware offload is off, so
`nf_flow_table_offload_setup()` takes the `nf_flow_offload_xdp_setup()` branch
(`nf_flow_table_offload.c:1258-1259`) and populates the per-device hashtable;
and `wwan0` is in the flowtable device list. The program looks the flow up,
applies the NAT rewrite, and builds an Ethernet header itself from
`tuple.out.h_source` / `h_dest` (raw-IP source, so there is no L2 to rewrite),
then redirects.

Skips: the bridge `rx_handler`, `ip_rcv` and routing, the software flowtable's
own `nf_ingress` hook, and the neighbour lookup. Does not skip the `sk_buff` -
it is already allocated by then. It *does* skip the egress qdisc, which is not
a bonus; see section 17.2. This is the download direction, which is also the
high-PPS direction.

**Shape B - eth1 ingress to wwan0, with a program-owned flow map.**
Genuinely pre-allocation, but it cannot use the kernel flowtable (16.2), so it
needs its own map of flows filled from somewhere - a tc-BPF egress program, or
userspace. And it needs `wwan0` to be a valid redirect target, which is #101.
That part looks feasible: `mbim_tx_fixup()` needs only
`sizeof(struct mbim_tx_hdr)` of headroom to push the NTH16/NDP16 header, and an
`xdp_frame` off `eth1`'s page pool arrives with `MTK_PP_HEADROOM` (256 bytes) in
front of it, so an `ndo_xdp_xmit` could push the same header, hand the buffer to
`mhi_queue_buf()` instead of `mhi_queue_skb()`, and release it with
`xdp_return_frame()` from the UL completion callback. This is the upload
direction - small in bytes, but during a download it carries the ACK stream,
which at 250 Mbps is on the order of 10k pkt/s of minimum-size packets, and ACK
timing feeds straight back into what the sender's congestion control will do.

### 16.6 The measurement that decides it, and it is cheap

> **Superseded, 2026-09-11.** The measurement specified here is expressed in
> softirq-per-1000-packets. Section 18.3 shows that quantity is not measurable on
> this hardware with `/proc/stat`. #114 was run against this specification and
> produced three mutually inconsistent answers before the instrument was
> identified as the problem. Do not re-run it as written.

Section 15.4 asked for the wrong measurement. RPS answers a question about CPU
placement; it says nothing about what a pre-allocation bypass is worth. The
right measurement brackets the prize directly, on this hardware, with no new
kernel patch and no new driver code:

1. Attach a program to `eth1` whose whole body is `return XDP_PASS`. Re-run the
   `dlwatch` sweep. The delta in si-per-1000-packets is the cost of the hook
   itself. It should be near zero; if it is not, nothing built on top of it can
   pay for itself.
2. Attach a program that `XDP_DROP`s one specific test flow, then drop that same
   flow a second way with an `nft` rule in the forward chain. The difference
   between those two si figures is the full cost of `build_skb()` plus stack
   entry plus netfilter traversal - measured on this SoC rather than estimated.
   That is the ceiling on what shape B can save per packet.

Two numbers, and they settle whether A and B are worth building without building
either one. Note the 16.1 caveat: `eth->prog` is per-`mtk_eth`, not per-netdev,
so the program covers `eth0` and `eth1` together, and attaching it bounces both
links once.

## 17. The same question for the modem and for wireless LAN

Section 16 answered it for the wired ports. The other two attach points are
worse, each for a different reason, and one of the reasons applies to the wired
ports too and is the most important finding in this file.

### 17.1 Wireless LAN has no native XDP at all, and attaching generic XDP costs GRO

> **Re-verified against the shipped trees, 2026-09-11.** The citations below were
> originally read from the kernel's own `net/mac80211`, which this image does not
> build - `package/kernel/mac80211` ships **backports 6.18.39**, and the box
> confirms it (`modinfo mac80211` reports `depends: cfg80211,compat`; `compat` is
> the backports shim). Re-read against `mac80211-regular/backports-6.18.39`, the
> conclusion holds and only the addresses changed: **no mac80211 source file
> mentions `xdp` at all** - `grep -rl --include=*.c --include=*.h xdp
> net/mac80211/` returns nothing, and the three `net_device_ops` tables in
> `iface.c` (`ieee80211_dataif_ops` 896, `ieee80211_monitorif_ops` 934,
> `ieee80211_dataif_8023_ops` 1002) have no `ndo_bpf` between them. The line
> numbers below are corrected to backports 6.18.39. The mt76 half is also
> confirmed: `grep -c xdp` returns 0 for `dma.c`, `mt76.h` and `mac80211.c` in
> `mt76-2026.03.19~39c960c3`.

`mt76` uses a page pool for RX buffers, which makes it look like an XDP driver
from a distance. It is not one. There is no `xdp_rxq_info`, no `xdp_buff`, no
`bpf_prog_run_xdp` and no `ndo_bpf` anywhere in mt76's `dma.c` or `mt76.h` -
`grep -c xdp` returns 0 for both. Neither `mac80211` nor `br_device.c`
implements `ndo_bpf` either, so `br-lan` and every AP netdev are
generic-XDP-only.

Where the skb actually gets built on the wireless path:

    mt76 `dma.c`:1045       skb = napi_build_skb(data, q->buf_size);
      -> ieee80211_rx_napi()                        mac80211 rx.c:5474
        -> ieee80211_rx_list()   decrypt, defrag, A-MSDU split, 802.11->802.3
                                                  mac80211 rx.c:5337
          -> ieee80211_deliver_skb()                mac80211 rx.c:2677
            -> napi_gro_receive()                   mac80211 rx.c:5497
              -> __netif_receive_skb_core()  <- generic XDP hook is here

The allocation happens in the driver's NAPI poll, before mac80211 has even
looked at the frame. A generic XDP program on an AP netdev sits at the very end
of that chain - later than the equivalent point on `wwan0`, and about as far
from "before allocation" as it is possible to get.

And it is not free to attach. `generic_xdp_install()` does
`rcu_assign_pointer(dev->xdp_prog, new)` and `dev_disable_lro(dev)`
(`dev.c:5949-5976`), and `netif_elide_gro()` is:

    netdevice.h:2433   if (!(dev->features & NETIF_F_GRO) || dev->xdp_prog)
                               return true;

which `dev_gro_receive()` tests on every packet (`gro.c:488`, function at 477).
`gro_cells_receive()` tests the same predicate at `gro_cells.c:23` and falls back
to bare `netif_rx()` when it fires - which is exactly why 992 keeps its program
on `link->xdp_prog`, and what the 2.12x measurement in 20.3 confirms.
So attaching any generic XDP program to `phy0-ap0` or `phy1-ap0` **turns GRO off
for that interface**. This is the same trap 992 was written to avoid on the
modem - it is exactly why 992 keeps the program on `link->xdp_prog` instead of
`dev->xdp_prog` - and on a wifi netdev there is no equivalent dodge available,
because there is no driver hook to own the pointer.

Net: on wireless a certain, measurable loss (GRO and LRO) buys a hook that runs
after every expensive thing has already happened. There is no version
of this that pays.

### 17.2 Every generic-XDP redirect bypasses the qdisc, and tc ingress

This is the finding that matters most, and it applies to `wwan0` and to the
wired ports equally.

Both redirect paths converge:

    filter.c:4655            generic_xdp_tx(skb, xdp_prog);   /* bpf_redirect() */
    devmap.c:721             generic_xdp_tx(skb, xdp_prog);   /* bpf_redirect_map() */

and `generic_xdp_tx()` is (`dev.c:5242-5263`):

    txq = netdev_core_pick_tx(dev, skb, NULL);
    HARD_TX_LOCK(dev, txq, cpu);
    rc = netdev_start_xmit(skb, dev, txq, 0);

`netdev_start_xmit()` directly, under the hard TX lock. No `dev_queue_xmit()`,
no qdisc. The kernel says so itself, at `dev.c:5231`:

    /* When doing generic XDP we have to bypass the qdisc layer and the
     * network taps in order to match in-driver-XDP behavior. This also means
     * that XDP packets are able to starve other packets going through a
     * qdisc, and DDOS attacks will be more effective. ...

There is no devmap escape hatch - `dev_map_generic_redirect()` ends in the same
call.

The ingress side is the same story. In `__netif_receive_skb_core()` the generic
XDP hook is at `dev.c:5612`, and `sch_handle_ingress()` - which is where an SQM
ingress redirect to an IFB lives - is at `dev.c:5655`, **43 lines later**. A
redirect from XDP never reaches it. For 992 the gap is bigger still, since that
hook is inside `mhi_mbim_rx()` and runs before the packet is handed to the stack
at all.

So on this box the fast path and the AQM are mutually exclusive, on exactly the
link that needs the AQM. Any flow taking an XDP redirect on `wwan0` leaves both
the ingress shaper and the egress qdisc behind. For a build that carries
`qos-latency-research.md` as half its reason to exist, that is not a footnote -
it means shape A cannot be "always on". At best it is a per-flow decision: a
program that fastpaths only traffic that is explicitly exempt from shaping, and
returns `XDP_PASS` for everything else so it goes the normal way.

One exception worth recording: a *wireless* egress target is unaffected, because
mac80211's AQM is not a qdisc. `fq_codel` and AQL live inside
`ieee80211_subif_start_xmit()`, below `netdev_start_xmit()`, so they still apply
to a packet delivered via `generic_xdp_tx()`. OpenWrt leaves AP netdevs on
`noqueue` for the same reason. Only wired egress loses its queue discipline.

### 17.3 WED is the real wireless lever, and half of it is unreachable here

WED is not XDP and does not compete with it - it is a separate hardware block,
and it is the only thing on this SoC that removes wireless work from the CPU in
bulk. What it offers splits cleanly in two:

**The half that works regardless of anything else.** `mt76_wed_dma_setup()`
hands the WLAN TX ring, the TXFREE ring and the RX ring to WED hardware
(`MT76_WED_Q_TX`, `MT76_WED_Q_TXFREE`, `MT76_WED_Q_RX`). Token accounting and
completion recycling move off the CPU. `mtk_wed_get_rx_capa()` is
`dev->version != 1` for anything below v3, and MT7981 is v2, so the RX half is
available. None of this depends on PPE, so it applies to modem-to-wifi traffic
like anything else.

**The half that is unreachable.** The headline WED win is WDMA forwarding: PPE
binds a flow whose egress resolves to a WDMA PSE port and the packet goes
ETH -> PPE -> WDMA -> WED -> WLAN without the CPU touching it.
`mtk_flow_set_output_device()` shows a wifi netdev does resolve that way
(`mtk_ppe_offload.c:198-218`, `PSE_WDMA0/1/2_PORT`), so wireless is a legal PPE
*egress*. But a PPE entry needs both ends, and section 10.1 established that
`wwan0` can never be a PPE ingress - no `ndo_setup_tc`, no
`flow_indr_dev_register` on the MediaTek side, and `-EOPNOTSUPP` from the egress
port resolver. Every internet flow on this box crosses `wwan0`. So WDMA
forwarding can never fire for real traffic here; it would only ever cover
wired-WAN-to-wifi, on a port this box does not use as its WAN.

Enabling it is cheap - `wed_enable` is a module parameter on `mt7915e`
(`mt7915_mmio.c:16-18`, mode 0644, gate at line 640), so it goes in
`/etc/modules.d/` the same way 993's doorbell parameter does, and the AXI/SoC
branch of `mt7915_mmio_wed_init()` is fully populated for the built-in WMAC.

But not on the pinned mt76, and this is why #111 blocks #99. The pin has:

    wed.c:36   struct mt76_queue *q = &dev->q_rx[MT_RXQ_MAIN];

hardcoded, while the newer mt76 has:

    wed.c:41   if (wed->version == 2 && dev->phy.band_idx)
                       q = &dev->q_rx[MT_RXQ_BAND1];
               else
                       q = &dev->q_rx[MT_RXQ_MAIN];

MT7981 is WED v2 *and* DBDC, so on the pinned tree `mt76_wed_init_rx_buf()`
would build the WED RX buffer ring against band 0's queue while serving band 1 -
the 5 GHz band, which is the one actually in use here. That is a correctness
bug, not a tuning difference. `mt7915_mmio_wed_init()` itself is identical
between the two trees; the fix is entirely in `wed.c`.

### 17.4 Summary across all four attach points

| Attach point | Native XDP | Runs pre-skb | Flow lookup | Cost to attach | Verdict |
|---|---|---|---|---|---|
| `eth0`/`eth1` | yes | yes | no - dummy dev | link bounce, both ports | static filter only - see 18 |
| `wwan0` | yes (992) | no - MBIM copy | yes | none | shape A, but see 17.2 |
| AP netdevs | no | no | n/a | **GRO and LRO off** | not worth it |
| `br-lan` | no | no | n/a | GRO and LRO off | not worth it |

For wireless the answer is WED, not XDP - and WED needs #111 first, and even
then delivers only its DMA and token half, because its forwarding half cannot
reach a flow that crosses the modem.


---

## 18. #114 run on hardware, 2026-09-11: one result, one dead instrument, two structural findings

Section 16.6 asked for a bracket: the cost of the native XDP hook, and the cost
of everything a pre-`sk_buff` drop skips. Eight runs on the box produced one
throughput result, established that the specified instrument cannot measure what
16.6 asked for, and turned up two facts about the receive path that matter more
than the number.

Claims here are labelled **measured** on the router, **read** from the trees named
in the header, or **not established**. Nothing is labelled confirmed on the basis
of an earlier session.

### 18.1 The rig

Hand-compiled BPF objects were the original plan and never arrived. The cause
was not the paste, as first assumed: **busybox on this image has no `base64`
applet**. `base64 -d > file <<EOF` then creates the empty file anyway and the
"not found" error scrolls past, so the objects were zero bytes and `libxdp`
reported the misleading `BPF object format invalid`. The objects themselves were
fine - libbpf 1.3 opened them off-box. `x3000/docs/verify-992a.sh` had already
documented this and says so in its own header: *"OpenWrt's busybox ships without
the base64 applet, so a base64 blob in this script cannot be decoded on the
router."* Confirmed on the box: `command -v base64` finds nothing.

`xdp-tools` on this image ships `xdp-filter`, so no compiler or transfer is
needed:

    xdp-filter load -m native -f udp eth1      # parses to UDP, passes everything
    xdp-filter port -m dst -p udp 9999         # now udp/9999 dies pre-skb

The same program, `xdpfilt_alw_udp`, runs in both conditions and differs only by
one port-map entry, so the difference isolates the drop rather than comparing two
programs. It keeps exact per-action and per-port counters.

The flow is 64-byte UDP to the router's own LAN address, paced from a PC on a
wired LAN port. An `nft` rule at `type filter hook input priority 10` sinks it, so
no ICMP port-unreachable is generated - without that, the pass conditions carry a
rate-limited ICMP path the drop conditions do not.

### 18.2 The measured result

At roughly 100,000 pkt/s offered, over repeated 40- and 45-second windows: the
full receive path to the input chain ran with **zero loss**, and native
`XDP_DROP` ran with **zero loss**. Capacity on both paths therefore exceeds 100k
pkt/s on this port. No upper bound was established.

That is the whole measured result, and it is less than 16.6 asked for.

Two incidental corrections, both measured:

**The driver does export XDP counters to ethtool** - `rx_xdp_pass` and
`rx_xdp_drop` at `mtk_eth_soc.c:247-248`, and they move. They are also
**cumulative and survive an unload**, so a stale non-zero reading looks live
while never advancing; that silently produced one window reporting zero packets.

**`/proc/net/dev` `rx_packets` counts frames XDP dropped.** In one window
`xdp-filter` counted 12,032,615 drops while `rx_packets` on `eth1` moved
12,000,459 - 0.3% agreement. Read: `.ndo_get_stats64 = mtk_get_stats64`
(`mtk_eth_soc.c:5133`) pulls from `mac->hw_stats` via `mtk_stats_update_mac()`,
whose non-MT7628 branch does `hw_stats->rx_packets += mtk_r32(mac->hw,
reg_map->gdm1_cnt + 0x8 + offs)` with `offs = hw_stats->reg_offset` set to
`id * 0x80` at `5242`. That is a **hardware GDM frame counter**, incremented at
the MAC before any software verdict. So `/proc/net/dev` is the one packet source
that works in every condition.

### 18.3 `/proc/stat` cannot measure per-packet cost on this box

**Measured.** Eight consecutive 40-second windows on two CPUs, so an 80-second
budget each. Summing user, nice, system, idle, iowait, irq and softirq:

    72.04  73.71  70.02  92.54  81.51  73.81  66.71  96.25

67 to 96 against 80, with every bit of the variation in `system`, which ranged
0.82 to 23.50 across otherwise identical windows. One 60-second window summed to
134.00 against a 120-second budget. The windows really were the stated length:
each received within 0.5% of the same packet count. On an idle box the same
sampler closed to 89.8 against 90.

**Read, from the running kernel's own `/proc/config.gz`** (available because
IKCONFIG is in this repo's overlay), matching `build_dir/.config` symbol for
symbol: `CONFIG_TICK_CPU_ACCOUNTING=y`, `CONFIG_IRQ_TIME_ACCOUNTING=y`,
`CONFIG_NO_HZ_IDLE=y`, `CONFIG_HZ=100`, `CONFIG_PREEMPTION=y`,
`CONFIG_PREEMPT_DYNAMIC=y`, `CONFIG_PREEMPT_RCU=y` with `PREEMPT_NONE` as the
boot default, and no `VIRT_CPU_ACCOUNTING*`.

So user, system and idle are assigned by sampling at 100 Hz - **one sample per
10 ms per CPU, 8,000 samples per 40-second two-CPU window** - with precisely
measured irq and softirq time subtracted from each tick's allotment. NAPI polls
on the order of 1,500 times a second in bursts of tens of microseconds. A sampler
at that resolution, attributing whole ticks, cannot resolve work at that
timescale. The variance is structural.

**Not established: the specific mis-attribution.** Three mechanisms were proposed
during the session - NO_HZ lump attribution, `ksoftirqd` billing, preemption mode
- and none was traced. A fourth is not offered. What the evidence supports is
narrower and sufficient: the instrument does not conserve time under load here,
and at this resolution it cannot measure per-packet cost.

**Not established: whether this repo's overlay is responsible.**
`CONFIG_PREEMPT_DYNAMIC` and `CONFIG_PREEMPT_RCU` come from the lean overlay;
stock OpenWrt builds `PREEMPTION=n`. Preemption changes how much softirq work is
deferred to `ksoftirqd`, which is the one task `irqtime_account_process_tick()`
special-cases. The A/B that would settle it is unavailable: `CONFIG_SCHED_DEBUG`
is not set, and `debugfs_create_file("preempt", ...)` lives in
`kernel/sched/debug.c:506`, which only builds under that symbol. A rebuild with
`CONFIG_SCHED_DEBUG=y` gives the runtime knob; one 40-second window per mode
then answers it.

**Three per-packet figures produced during this session - 1,583, 4,132 and
1,870 ns/pkt - are withdrawn**, along with the capacity and line-rate claims
derived from them.

Two rig confounders found on the way, neither the root cause, both able to ruin a
run alone:

- **`ttyd` spins.** Streaming the results file with `tail -f` through `ttyd` put
  `ttyd` at 30.24 seconds and 100.8% of a core in one 30-second window and left
  15-16 seconds of *user* time in three others. Start the run detached with
  `setsid` over ssh; read the file afterwards.
- **`irqbalance` rewrites IRQ affinity mid-window.** Stop it for the duration,
  and put it back after - it had arranged RX on CPU0 and TX on CPU1.

### 18.4 The wired receive path is one kernel thread, on a device with no sysfs entry

Per-task sampling - reading `utime` and `stime` from `/proc/<pid>/stat`, because
busybox `top` and `ps` list no kernel threads at all - named the holder of the
receive work as `napi/mtk_eth-6`. That thread exists because of an OpenWrt patch,
not upstream:
`target/linux/generic/pending-6.12/702-net-ethernet-mtk_eth_soc-enable-threaded-NAPI.patch`,
Felix Fietkau, 2022, *"This can improve performance under load by ensuring that
NAPI processing is not pinned on CPU 0."*

    5730   eth->dummy_dev->threaded = 1;
    5731   strcpy(eth->dummy_dev->name, "mtk_eth");
    5732   netif_napi_add(eth->dummy_dev, &eth->tx_napi, mtk_napi_tx);
    5733   netif_napi_add(eth->dummy_dev, &eth->rx_napi, mtk_napi_rx);

The name follows from `dev.c:1508`, `kthread_run(napi_threaded_poll, n,
"napi/%s-%d", n->dev->name, n->napi_id)`. Which of the two napi ids is RX is
inferred from registration order, not read.

**`cat /sys/class/net/eth1/threaded` returns 0 and is not wrong.** It answers
about eth1's own NAPI list, which is empty. Both instances belong to
`eth->dummy_dev`, and a dummy netdev has no sysfs directory for the attribute.
There is no runtime switch for threading on this path.

**The thread's time lands in two places at once.** `napi_threaded_poll_loop()`
runs the poll bh-disabled - `local_bh_disable()` at `dev.c:7014`, `__napi_poll()`
at `7021`, `local_bh_enable()` at `7033` - so the same microseconds appear as
`softirq` in `/proc/stat` and as `stime` on the thread. Not additive. Measured in
one clean window: 7.69 s attributed to `napi/mtk_eth-6` over 30 s while
`/proc/stat` softirq for the overlapping window was 7.28 s. That pair identifies
the holder; per 18.3 it does not quantify the cost.

**RPS backlog work for the local CPU happens inside that same thread.**
`dev.c:4919` skips raising `NET_RX_SOFTIRQ` when `sd->in_napi_threaded_poll` is
set, and `dev.c:7027-7030` dispatches pending RPS IPIs inside the bh-disabled
region. So RPS does not separate cleanly into its own bucket either.

**Receive is single-NAPI.** Exactly two `netif_napi_add` calls in the driver and
no `netif_set_real_num_rx_queues`. There are four RX rings
(`MTK_MAX_RX_RING_NUM 4`) but rings 1-3 are HWLRO-only - every loop over them
starts at `i = 1` - and `mtk_xdp_setup()` refuses XDP outright when `eth->hwlro`
is set. The fact that `xdp-filter load -m native eth1` **succeeded** therefore
proves HWLRO is off here, leaving ring 0 with one NAPI. RPS is the only mechanism
that brings CPU1 into this path.

**Pinning the interrupt does not pin the work.** `echo 1 >
/proc/irq/76/smp_affinity` fixes the hard IRQ; the poll runs in a schedulable
thread, and patch 702 exists precisely so it can migrate. Stabilising placement
means `taskset` on the `napi/mtk_eth` thread, not on the IRQ.

So `eth->dummy_dev` carries three separate constraints: no ifindex, so every
ifindex-based BPF helper fails (16.2); no sysfs, so threading cannot be changed at
runtime; and it owns the NAPI the whole wired receive path runs inside.

### 18.5 What this changes

**#101 and #102 are unaffected**, and they do not need any of tonight's numbers.
16.2 and 16.3 decide them, and both chains were re-read end to end against the
shipped trees - see 19. A flow-aware fast path cannot be built on `eth0`/`eth1`,
and `wwan0` has no pre-allocation win to capture.

**14.3's independent argument for parking them is weaker than it reads.** Its
headline rests on the `busy` columns, which are less exposed than its
softirq-normalised 0.750-to-0.525 delta - a 10% difference, exactly the magnitude
18.3's variance manufactures. Lean on 16.2 and 16.3, not on 14.3.

**#114 closes as bounded by instrumentation**, not as answered.

**What is better founded than #102 was, and narrower: native XDP on `eth0` for
flood absorption.** A static filter needs neither `bpf_xdp_flow_lookup()` nor
`ctx->ingress_ifindex`, which is why `xdp-filter` worked where a flow-aware
program structurally cannot. Sizing it needs a generator that can exceed the
box's capacity, and **WSL2 is not one**: four unpaced worker processes never
cleared 150k pkt/s, while paced at 100k it delivered 99.9k. The cap therefore
sits between those figures. Whether the limit is the Hyper-V virtual switch or
Python's per-packet cost is **not established** - running the same unpaced flood
natively on Windows would separate them.

For reference: 64-byte UDP occupies 130 bytes on the wire (106-byte frame, 4 FCS,
20 preamble/SFD/IFG), so gigabit line rate is 961,538 pkt/s and the 2.5G WAN port
is 2,403,846 pkt/s. A sizing run must offer more than the path under test can
absorb, or it measures the generator.

### 18.6 Operational notes for repeating any of this

- `xdp-filter` is on the image; no compiler, no object transfer.
  `xdp-filter status` gives exact per-action and per-port counters.
- **Attaching or detaching bounces the link.** `mtk_xdp_setup()` sets
  `need_update = !!eth->prog != !!prog` and calls `mtk_stop(dev)` then
  `mtk_open(dev)` around the swap - so a zero-to-one or one-to-zero transition
  bounces, a program replacement does not. The reason is the page pool's DMA
  direction changing (16.1). `ip -d link show eth1` caught it as
  `NO-CARRIER ... state DOWN` right after a load. Allow several seconds of settle.
- Use `/proc/net/dev` `rx_packets` for packet counts, not ethtool's `rx_xdp_*`.
- Sink the test flow at `type filter hook input priority 10`.
- Have the runner wait for traffic rather than relying on start order. One run
  measured an idle link for four straight windows.
- Run detached over ssh, stop `irqbalance`, and read the output only afterwards.
- busybox `top` and `ps` hide kernel threads. Sample `/proc/<pid>/stat` directly.

## 19. Citation index, resolved against the shipped trees, 2026-09-11

Verified in the trees named in the header. Use this in preference to any line
number in sections 0-17.

| Symbol or quote | File | Line |
|---|---|---|
| `xdp_init_buff` / `xdp_prepare_buff` in `mtk_poll_rx` | `mtk_eth_soc.c` | 2481 / 2482 |
| `ret = mtk_xdp_run(...)` | `mtk_eth_soc.c` | 2486 |
| `goto skip_rx` on non-PASS | `mtk_eth_soc.c` | 2491 |
| `skb = napi_build_skb(data, PAGE_SIZE)` | `mtk_eth_soc.c` | 2493 |
| `eth_type_trans()` | `mtk_eth_soc.c` | 2565 |
| `skip_rx:` label | `mtk_eth_soc.c` | 2585 |
| `mtk_xdp_run()` definition | `mtk_eth_soc.c` | 2336 |
| `prog = rcu_dereference(eth->prog)` | `mtk_eth_soc.c` | 2347 |
| `__xdp_rxq_info_reg(xdp_q, eth->dummy_dev, ...)` | `mtk_eth_soc.c` | 2115 |
| `napi_gro_receive(napi, skb)` | `mtk_eth_soc.c` | 2583 |
| `rx_xdp_pass` / `rx_xdp_drop` ethtool entries | `mtk_eth_soc.c` | 247-248 |
| `old_prog = rcu_replace_pointer(eth->prog, ...)` | `mtk_eth_soc.c` | 4002 |
| `mtk_change_mtu()` | `mtk_eth_soc.c` | 4624 |
| `.ndo_get_stats64 = mtk_get_stats64` | `mtk_eth_soc.c` | 5133 |
| `hw_stats->reg_offset = id * 0x80` | `mtk_eth_soc.c` | 5242 |
| `xdp_features = BASIC\|REDIRECT\|NDO_XMIT\|NDO_XMIT_SG` | `mtk_eth_soc.c` | 5360-5363 |
| `"mediatek,wed"` phandle lookup | `mtk_eth_soc.c` | 5586 |
| `eth->dummy_dev = alloc_netdev_dummy(0)` | `mtk_eth_soc.c` | 5724 |
| `eth->dummy_dev->threaded = 1` (patch 702) | `mtk_eth_soc.c` | 5730 |
| `netif_napi_add(eth->dummy_dev, ...)` tx / rx | `mtk_eth_soc.c` | 5732 / 5733 |
| `MTK_PPE_UNBIND_AGE_MIN_PACKETS` | `mtk_ppe.c` | 1068 |
| `MTK_PPE_BIND_RATE_BIND` | `mtk_ppe.c` | 1087 |
| `mtk_flow_get_dsa_port()` / `PSE_GDM1_PORT` / `PSE_GDM2_PORT` | `mtk_ppe_offload.c` | 170 / 225 / 227 |
| `mtk_wed_device_attach()` | `mtk_wed.h` | 233 |
| `napi_kthread_create` name format | `dev.c` | 1508 |
| `tcx_run(entry, skb, true)` ingress / egress | `dev.c` | 4198 / 4257 |
| `get_rps_cpu()` definition | `dev.c` | 4735 |
| `READ_ONCE(rflow->filter) == filter_id` (RFS) | `dev.c` | 4859 |
| `sd->in_napi_threaded_poll` check in RPS enqueue | `dev.c` | 4919 |
| `enqueue_to_backlog()` definition | `dev.c` | 4988 |
| `netif_get_rxqueue()` definition / call in generic XDP | `dev.c` | 5039 / 5084 |
| `bpf_prog_run_generic_xdp()` | `dev.c` | 5062 |
| `generic_xdp_tx()` | `dev.c` | 5242-5263 |
| `do_xdp_generic()` | `dev.c` | 5267 |
| `EXPORT_SYMBOL_GPL(do_xdp_generic)` | `dev.c` | 5301 |
| `__netif_receive_skb_core()` | `dev.c` | 5588 |
| generic XDP hook in the receive path | `dev.c` | 5621 |
| `sch_handle_ingress()` call | `dev.c` | 5661 |
| `nf_ingress()` call | `dev.c` | 5669 |
| bridge `rx_handler()` call | `dev.c` | 5695 |
| `generic_xdp_install()` | `dev.c` | 5949 |
| `netif_receive_skb_list_internal()` | `dev.c` | 6005 |
| RPS in the list path: `rps_needed` / `get_rps_cpu` / `enqueue_to_backlog` | `dev.c` | 6021 / 6024 / 6029 |
| `napi_threaded_poll_loop()` | `dev.c` | 7004 |
| `local_bh_disable()` / `__napi_poll()` / `local_bh_enable()` | `dev.c` | 7014 / 7021 / 7033 |
| RPS IPI dispatch inside the threaded poll | `dev.c` | 7027-7030 |
| `ndo_bpf ? XDP_MODE_DRV : XDP_MODE_SKB` | `dev.c` | 9457 |
| `"Underlying driver does not support XDP in native mode"` | `dev.c` | 9714 |
| `init_dummy_netdev_core()` | `dev.c` | 10699 |
| ifindex assigned (`dev_index_reserve`) | `dev.c` | 10571-10574 |
| `netif_elide_gro()` definition | `netdevice.h` | 2433 |
| `if (netif_elide_gro(skb->dev))` in `dev_gro_receive()` | `gro.c` | 488 (fn at 477) |
| `gro_cells_receive()` | `gro_cells.c` | 13 |
| `xdp_do_generic_redirect_map()` | `filter.c` | 4570 |
| `xdp_do_generic_redirect()` | `filter.c` | 4628 |
| `generic_xdp_tx()` call, ifindex redirect path | `filter.c` | 4655 |
| `xdp_md.ingress_ifindex` conversion | `filter.c` | 10246-10255 |
| `dev_map_generic_redirect()` | `devmap.c` | 692-724 |
| `generic_xdp_tx()` call in the devmap path | `devmap.c` | 721 |
| `NDO_XMIT_SG` frags refusal | `devmap.c` | 491-492 |
| `netif_receive_skb_list(&list)` | `cpumap.c` | 364 |
| `nf_flow_table = nf_flowtable_by_dev(dev)` | `nf_flow_table_bpf.c` | 43 |
| `bpf_xdp_flow_lookup()` | `nf_flow_table_bpf.c` | 59 |
| `bpf_xdp_flow_tuple_lookup(xdp->rxq->dev, &tuple, proto)` call | `nf_flow_table_bpf.c` | 59-107 |
| `BTF_ID_FLAGS(func, bpf_xdp_flow_lookup, ...)` | `nf_flow_table_bpf.c` | 108 |
| `nf_flowtable_by_dev()` definition, keyed on the `net_device *` pointer | `nf_flow_table_xdp.c` | 27-33 |
| `nf_flow_offload_xdp_setup()` call | `nf_flow_table_offload.c` | 1259 |
| `flow_offload_add()` | `nf_flow_table_core.c` | 274 |
| `nf_flow_table_bpf.o` gated on BTF, `ifeq`/`else ifeq` | `net/netfilter/Makefile` | 147-151 |
| `skb = napi_build_skb(data, q->buf_size)` | mt76 `dma.c` | 1045 |
| `napi_gro_receive(napi, skb)` | mt76 `mac80211.c` | 1550 |
| `grep -c xdp` = 0 | mt76 `dma.c`, `mt76.h`, `mac80211.c` | - |
| `debugfs_create_file("preempt", ...)`, needs `CONFIG_SCHED_DEBUG` | `kernel/sched/debug.c` | 506 |
| `netif_elide_gro(dev)` test, falls back to bare `netif_rx()` | `gro_cells.c` | 23 (fn at 13) |
| `cell = this_cpu_ptr(gcells->cells)` | `gro_cells.c` | 28 |
| `generic_xdp_install()` full extent | `dev.c` | 5949-5976 |
| `tun_netdev_ops` / `tap_netdev_ops` | `tun.c` | 1246 / 1330 |
| `__skb_push(skb, skb->mac_len)` | `cls_bpf.c` | 99 |
| `NETDEV_XDP_ACT_HW_OFFLOAD` - the only two setters in the tree | `netdevsim/netdev.c` / `nfp_net_common.c` | 639 / 2767 |
| `nf_flow_offload_xdp_setup()` definition | `nf_flow_table_xdp.c` | 133 |
| `mtk_wed_add_hw(np, eth, ...)` | `mtk_eth_soc.c` | 5592 |
| `ieee80211_deliver_skb()` | backports `mac80211/rx.c` | 2677 |
| `ieee80211_deliver_skb_to_local_stack()` (new in 6.18) | backports `mac80211/rx.c` | 2626 |
| `ieee80211_rx_list()` | backports `mac80211/rx.c` | 5337 |
| `ieee80211_rx_napi()` | backports `mac80211/rx.c` | 5474 |
| `napi_gro_receive()` in the 802.11 rx path | backports `mac80211/rx.c` | 5497 |
| the three `net_device_ops` tables, none with `ndo_bpf` | backports `mac80211/iface.c` | 896 / 934 / 1002 |
| `grep -rl xdp net/mac80211/*.c *.h` = **no matches** | backports 6.18.39 | - |

**Still not resolved.** One: `nf_tables_api.c:8460`, cited in section 9 for the
`hooknum != NF_NETDEV_INGRESS` rejection. The hook validation that returns
`-EOPNOTSUPP` is at `2300`, `2311` and `2315` in this tree, and the claim the doc
makes is consistent with that code, but I could not map it to a single line - so
treat the address as unverified and the claim as read from the hook-validation
block rather than from one statement.

Everything else previously listed here is now resolved above, including the
entire `net/mac80211/` chain against backports 6.18.39.

## 20. Hardware audit of 990-993 and the BPF platform, 2026-09-11

Prompted by a reasonable worry that the kernel patches might be wrong. They are
not. Every item below is **measured on the running box** or read from the
prepared source that was compiled, not from an earlier session's notes.

### 20.1 All four patches applied

Signature strings that exist only if the patch landed, grepped in
`build_dir/.../linux-6.12.103`:

| patch | signature | hits |
|---|---|---|
| 990 | `MODULE_VERSION(__stringify(BBR_VERSION))` in `net/ipv4/tcp_bbr.c` | 1 |
| 990 | `bbr_version` in `include/uapi/linux/inet_diag.h` | 1 |
| 991 | `select GRO_CELLS` in `drivers/net/wwan/Kconfig` | 1 |
| 991 | `gro_cells_receive(&link->gcells` in `mhi_wwan_mbim.c` | 1 |
| 992 | `mhi_mbim_ndo_bpf` | 2 (definition + `.ndo_bpf =`) |
| 992 | `xdp_set_features_flag` | 1 |
| 993 | `force_db_brst_disable` in `drivers/bus/mhi/host/init.c` | 4 |

### 20.2 990 is BBRv3, proven from the module's own BTF

`modinfo tcp_bbr` shows no `version:` field, which looked like a failure and is
not: `CONFIG_MODULE_STRIPPED=y` and `# CONFIG_MODULE_SRCVERSION_ALL is not set`,
so OpenWrt strips `version`, `srcversion`, `author` and `description` from every
module while keeping `vermagic`, `name`, `intree`, `license` and `depends`. That
also explains the absent `srcversion` on `mhi_wwan_mbim`.

`DEBUG_INFO_BTF_MODULES=y` gives a better proof.
`bpftool btf dump file /sys/kernel/btf/tcp_bbr format c` prints a `struct bbr`
carrying `bw_hi[2]`, `bw_lo`, `bw_latest`, `inflight_hi`, `inflight_lo`,
`inflight_latest`, `undo_bw_lo`, `undo_inflight_lo`, `undo_inflight_hi`,
`bw_probe_up_cnt`, `bw_probe_up_acks`, `bw_probe_up_rounds`, `bw_probe_samples`,
`probe_wait_us`, `loss_round_start`, `loss_round_delivered`,
`loss_events_in_round`, `ack_phase`, `ecn_alpha`, `startup_ecn_rounds` and
`struct tcp_plb_state plb`. All are v3-only, and PLB does not exist in v1.

What is **absent** is equally decisive: no `struct minmax bw`, no `rtt_cnt`, no
`lt_is_sampling` / `lt_rtt_cnt` / `lt_use_bw` / `lt_bw` / `lt_last_*`, no
`packet_conservation` - the long-term bandwidth sampling machinery BBRv3 removed.
`mode` and `cycle_idx` are also narrowed to 2 bits from v1's 3.

Selected and active: `net.ipv4.tcp_congestion_control = bbr`, available list
`reno cubic bbr`, pinned by `/etc/sysctl.d/12-tcp-bbr.conf`. Module is 20,712
bytes, about half again what v1 measures on this architecture.

### 20.3 991 and 992 verified end to end by the repo's own verifier

`x3000/docs/verify-992a.sh --traffic`: **PASS=25, FAIL=0, skipped=3.** The skips
are the optional `--with-drop` and `--with-tc` paths, plus "this iproute2 does
not print xdp-features", which is a tooling limitation and explains why
`ip -d link show wwan0` lists no `xdpfeatures` line.

| test | result |
|---|---|
| `bpf_xdp_flow_lookup` kfunc present | yes - BTF gates it and it compiled |
| GRO baseline, no program attached | **2.09x** aggregation on `wwan0` |
| attach `xdp_pass` in DRV mode | succeeded, `prog/xdp id 288` - 992's `ndo_bpf` took it |
| **GRO survives the attach** | **2.12x vs 2.09x baseline** |
| `rx_errors` while attached | steady at 0 |
| detach | clean |
| AF_XDP oops path | no `dmesg-ramoops-*` in `/sys/fs/pstore/` |

The GRO-survives-attach result is the one worth keeping. 992 deliberately stores
the program on `link->xdp_prog` rather than `dev->xdp_prog` so that
`netif_elide_gro()` never sees it - 16.1 and 18.4 explain the mechanism, and this
measures the outcome. Had it been stored on `dev->xdp_prog`, aggregation would
have collapsed to 1.0x on attach.

### 20.4 993 is live and firing

`/sys/module/mhi/parameters/force_db_brst_disable` exists and reads `Y`, and the
kernel log shows it taking effect on both MBIM channels:

    mhi-pci-generic 0000:01:00.0: ch100 IP_HW0_MBIM: forcing doorbell writes
    mhi-pci-generic 0000:01:00.0: ch101 IP_HW0_MBIM: forcing doorbell writes

The patch's own default is 0, so something must set it. It is
`/etc/modules.d/mhi-doorbell` line 30, `mhi force_db_brst_disable=1`, and that
file is tracked at `x3000/files-common/etc/modules.d/mhi-doorbell` - so it is
baked into the image and survives sysupgrade rather than being a local edit.

### 20.5 The platform, as shipped

Every kernel symbol the overlay claims, read from `/proc/config.gz` on the box:
`BPF`, `BPF_SYSCALL`, `BPF_JIT`, `BPF_JIT_DEFAULT_ON`, `BPF_EVENTS`,
`BPF_UNPRIV_DEFAULT_OFF`, `CGROUP_BPF`, `DEBUG_INFO_BTF`,
`DEBUG_INFO_BTF_MODULES`, `GRO_CELLS`, `IKCONFIG`, `IKCONFIG_PROC`, `KPROBES`,
`PERF_EVENTS`, `NET_SCH_CAKE=m`, `NET_ACT_BPF=m`, `NET_CLS_BPF=m`,
`NF_FLOW_TABLE=m`, `NF_FLOW_TABLE_INET=m`, `NFT_FLOW_OFFLOAD=m`,
`TCP_CONG_BBR=m`, `XDP_SOCKETS=y`, `XDP_SOCKETS_DIAG=m`, `PAGE_POOL=y`,
`ZRAM=m`, `ZRAM_BACKEND_{LZO,LZ4,ZSTD}=y`, `ZRAM_DEF_COMP="lzo-rle"`.

All thirteen userland packages present: `xdp-filter`, `xdp-loader`, `xdpdump`,
`bpftool-full`, `libbpf`, `tc-bpf`, `irqbalance`, `zram-swap`, `mwan3`,
`luci-app-mwan3`, `kmod-tcp-bbr`, `kmod-zram`, `kmod-nft-offload`.

Both working trees clean, both tracking
`github.com/therealahrion/openwrt-glinet-x3000`.

### 20.6 Things this audit corrected

- The zero-byte BPF objects were busybox lacking `base64`, not a paste failure
  (18.1, now fixed).
- `/sys/class/net/wwan0/threaded` reads 0. 991 gives `wwan0` real NAPI instances
  through gro_cells, which is what makes the `threaded` control meaningful at all
  - it does not turn threading on. Measured: `napi/mtk_eth-5`, `napi/mtk_eth-6`
  and six `napi/phy0-*` threads exist; there is no `napi/wwan0-*`.
- `napi/mtk_eth-5` **and** `-6` both exist, confirming 18.4's reading that the
  driver registers one NAPI per direction on `eth->dummy_dev`.
- The eBPF suite dropped on 2026-09-07 is recoverable: `git log --all --
  x3000/ebpf` returns `2c45f07780` (creation) and `654de33149` (package
  conversion, which *was* applied and later dropped). Sources are at
  `git show 654de33149:package/x3000-ebpf/src/`.

## 21. Feature interaction matrix

Every feature in this build was added for its own reasons, but what matters in
practice is whether they survive each other: whether GRO still works once XDP is
attached, whether the flowtable kfunc is reachable from a program, whether a
redirect still passes through the shaper. Those answers are scattered across
sections 9 to 20. This is the single table.

The untested rows are the useful part. They are the places the build currently
rests on an assumption.

### 21.1 Pairs that interact

**Compatible** means verified to coexist. **Incompatible** means one silently or
explicitly disables the other. Evidence column points at the section or the
`file:line` from section 19.

| A | B | verdict | evidence |
|---|---|---|---|
| GRO | native XDP on `eth0`/`eth1` | **compatible** | program runs on an `xdp_buff` at `mtk_eth_soc.c:2486`; `napi_build_skb` 2493 and `napi_gro_receive` 2583 are reached only on `XDP_PASS`, so the program never sees a coalesced frame (16.1) |
| native XDP | HWLRO | **mutually exclusive**, driver-enforced | `mtk_xdp_setup()` returns `-EOPNOTSUPP` "XDP not supported with HWLRO". A successful `xdp-filter load -m native eth1` therefore proves HWLRO is off here (18.4) |
| GRO and LRO | generic / skb XDP, any device | **incompatible**, silently | `generic_xdp_install()` (`dev.c:5949-5976`) stores on `dev->xdp_prog` and calls `dev_disable_lro()`; `netif_elide_gro()` (`netdevice.h:2433`) is true for any `dev->xdp_prog`; `dev_gro_receive()` tests it at `gro.c:488` (17.1) |
| `gro_cells` | `dev->xdp_prog` | **incompatible. Measured.** | `gro_cells_receive()` tests the same predicate at `gro_cells.c:23` and drops to bare `netif_rx()`. measured twice - **1.00x skb against 24.8x detached** (2026-09-09, recorded in `lean-overlay.md`) and 1.06x against 2.20x at a lower link rate (2026-09-11). Correct-but-silent, and not fixable in the core: see 22 |
| `gro_cells` | 992's hook | **compatible by construction. Measured.** | program held on `link->xdp_prog`, invisible to `netif_elide_gro()`. verify-992a section 6 |
| BTF | BPF CO-RE tooling | **required, present** | `DEBUG_INFO_BTF=y`, `_MODULES=y`; `/sys/kernel/btf/vmlinux` 3846 KB; per-module BTF present (20.5) |
| BTF | `bpf_xdp_flow_lookup` kfunc | **required** | `net/netfilter/Makefile:147-151` gates `nf_flow_table_bpf.o` on `DEBUG_INFO_BTF_MODULES` / `DEBUG_INFO_BTF`. Without this repo's BTF platform the kfunc does not exist at all |
| flowtable kfunc | native XDP on `eth0`/`eth1` | **incompatible, structurally** | `bpf_xdp_flow_lookup()` ends in `bpf_xdp_flow_tuple_lookup(xdp->rxq->dev, ...)` then `nf_flowtable_by_dev()`, keyed on the `net_device *` **pointer** (`nf_flow_table_xdp.c:27-33`). The rxq carries `eth->dummy_dev` (`mtk_eth_soc.c:2115`), never inserted in any flowtable. Permanent `-ENOENT`; a correct `fib_tuple->ifindex` does not help, because the *table* is selected by the pointer (16.2, 18.7) |
| hardware flow offload (PPE) | flowtable kfunc | **mutually exclusive** | 10.2 |
| software flow offload | any per-packet netfilter rule on the same traffic | **mutually exclusive** | an offloaded flow is intercepted at the ingress hook and stops reaching prerouting and forward, so a per-packet rule sees the opening packets of each connection and then nothing. Observed 2026-09-12 with the flowtable on `br-lan`, `eth0` and `wwan0` and 10 of 34 conntrack entries in `OFFLOAD`. This is what rules out NFQUEUE-style inspection while offload is on; MSS clamping is unaffected because it acts at SYN |
| software flow offload | GRO, and the driver RX path generally | **compatible** | offload shortcuts conntrack and the netfilter chains, not the driver or `gro_cells`. So it changes nothing measured here: every throughput and aggregation run terminated on the router through INPUT, which is never offloaded |
| NFQUEUE | GRO on `wwan0` | **works, but not per datagram** | netfilter hooks run after GRO, so a queue rule hands userspace the coalesced skb - 12,524 to 16,509 bytes measured (18, 21.3). One verdict covers the whole aggregate, and a consumer with a 1500-byte copy range truncates. `ethtool -K wwan0 gro off` is the escape hatch |
| NFQUEUE | XDP | **XDP wins** | XDP runs ahead of netfilter entirely, and on `wwan0` 992's hook is in the driver, so anything `XDP_DROP`ped never reaches a queue |
| PPE hardware NAT | `wwan0` | **impossible** | egress PSE port resolved only from `eth->netdev[0..2]`: `mtk_flow_get_dsa_port` 170, `PSE_GDM1_PORT` 225, `PSE_GDM2_PORT` 227 (10.1) |
| `XDP_REDIRECT` | cake / SQM | **incompatible** | both paths end in `generic_xdp_tx()` then `netdev_start_xmit()` with no qdisc: `filter.c:4655` for `bpf_redirect()`, `devmap.c:721` for `bpf_redirect_map()` (17.2) |
| **992's `XDP_TX`** | **cake / SQM** | **incompatible** - see 21.3 | `do_xdp_generic()` dispatches `case XDP_TX` to `generic_xdp_tx()` at `dev.c:5287`, which is the same qdisc-bypassing path |
| XDP | tc ingress | **XDP wins** | `do_xdp_generic` at `dev.c:5621`, `sch_handle_ingress` at 5661 - so a redirect escapes tc ingress shaping too (17.2) |
| AF_XDP | 992 | **compatible, deliberately** | libxdp's `xsk_def_prog` emits only `bpf_redirect_map()`, so refusing `XDP_REDIRECT` would refuse AF_XDP. Routing through `do_xdp_generic()` provides it. verify-992a section 11: no pstore crash records |
| AF_XDP | cake / SQM | **incompatible** | it is a redirect, so the row above applies |
| wireless (mt76 + mac80211) | XDP of any kind | **generic only** | no mac80211 source file mentions `xdp` in backports 6.18.39, and none of its three `net_device_ops` tables has `ndo_bpf`; `grep -c xdp` is 0 for mt76's `dma.c`, `mt76.h`, `mac80211.c`. So attaching costs GRO and LRO by the row above, for a hook that runs after decrypt, defrag and A-MSDU split (17.1) |
| WED | flows crossing `wwan0` | **unreachable** | WED's forwarding half cannot carry a flow that crosses the modem (17.3) |
| RPS | threaded NAPI | **compatible** | `dev.c:4919` skips raising `NET_RX_SOFTIRQ` when `sd->in_napi_threaded_poll`; `dev.c:7027-7030` dispatches pending RPS IPIs inside the bh-disabled region of `napi_threaded_poll_loop()` (18.4) |
| RPS | `XDP_DROP` | **RPS disappears** | no skb is built, so nothing is enqueued to any backlog. Observed across the #114 runs |
| threaded NAPI | `/proc/stat` accounting | **interferes with measurement** | the poll runs under `local_bh_disable()`, so the same microseconds appear as `softirq` in `/proc/stat` and as the thread's `stime`. Compounded by 18.3 |
| zram, irqbalance, mwan3 | the datapath | **orthogonal** | no interaction; mwan3 ships inert |

### 21.2 Untested - this is the work queue

Each of these is a claim the build currently rests on without evidence.

| A | B | what is assumed | how to settle it |
|---|---|---|---|
| software nft flow offload | cake | that offloaded flows still traverse the egress qdisc, so cake keeps shaping. `lean-overlay.md` says in as many words to verify this before trusting it | bufferbloat run with `flow_offloading` on and off, latency under load |
| BBRv3 | cake / `fq_codel` | that BBR's internal pacing and the qdisc's do not fight | throughput and latency A/B against `cubic` at the same shaper settings |
| ~~flowtable kfunc~~ | ~~XDP on `wwan0`~~ | **Settled - 23.1.** The assumption held: generic XDP takes its rxq from `netif_get_rxqueue(skb)` (`dev.c:5039`, called 5084), the real netdev, and `wwan0` is in the fw4 flowtable | **Done.** `xdp-ft-wwan.sh probe` calls the kfunc on `wwan0`. 98.8% to 99.0% hit across seven windows, both families, and `l3proto` and `iifidx` read back from the returned tuple agree with the packet on every lookup |
| AF_XDP | native XDP on `eth0`/`eth1` | that XSK redirect works on the wired path as it does on `wwan0` | bind a socket, check for pstore records as verify-992a section 11 does |
| aggregation | arrival rate | that `gro_cells` aggregation scales with load. A 60x reading was withdrawn because it implies an 84 KB skb against a 65536 ceiling, but it is possible if those datagrams were under 1092 bytes, which was never measured | one run at a fast link with the fixed `gro_measure()`, which now reports bytes per skb and `rx_dropped`. **Partly read, 23.11:** a 63x window implies a mean datagram near 1040 bytes, which is consistent with the ceiling and small for a speedtest. Still unexplained, and it belongs to the GRO work rather than to section 23 |

### 21.3 Two things this table clarified

**`XDP_TX` bypasses the shaper, not just `XDP_REDIRECT`.** Section 17.2 established
that both redirect paths end in `generic_xdp_tx()`. The same is true of `XDP_TX`:
992 routes every verdict through `do_xdp_generic()`, whose `case XDP_TX` calls
`generic_xdp_tx()` at `dev.c:5287`, which goes to `netdev_start_xmit()` under
`HARD_TX_LOCK` with no qdisc (`dev.c:5242-5263`).

So the rule, and it is the most useful line in this section: **only `XDP_PASS` and
`XDP_DROP` coexist with SQM.** Any fastpath built on `XDP_TX` or `XDP_REDIRECT`
leaves cake behind, on `wwan0` and on the wired ports alike.

**The skb-mode collapse was measured twice, a day apart, and the earlier figure is
the stronger one.** `lean-overlay.md`'s 992 row has recorded since 2026-09-09 that
attaching the same program with `xdpgeneric` measures **1.00x aggregation against
24.8x detached**. The 2026-09-11 run reproduced it at a lower link rate: 1.06x
against 2.20x. Both are the same phenomenon; quote whichever matches the rate
being demonstrated.

That pair also settles a question 18.5 left open. A 24.8x reading is arithmetically
comfortable - about 34.7 KB per delivered skb against a 65536 ceiling - so
aggregation genuinely is far higher at higher arrival rates than the 2.1x measured
at 3.3 Mbit/s. The 60x reading withdrawn in 18.5 therefore needs only datagrams
averaging under 1092 bytes to be real, rather than being impossible. It stays
unquoted until a run with the instrumented `gro_measure()` reports bytes per skb
alongside it, but the rate-scaling behaviour itself is no longer in doubt.

**2026-09-13 closes the bytes-per-skb condition this section set.** The first
full-platform run after the patch set was regenerated with quilt reported, from
`verify-992a.sh` section 4 at an offered load of about 119 Mbit/s: `aggregation=8.11x`
with `bytes per delivered skb=11606`. That is the instrumented reading 21.3 was
waiting for, so the arithmetic can now be closed rather than bounded from one side.

A mean datagram of `11606 / 8.11 = 1431` bytes puts the ceiling at
`65536 / 1431 = 45.8x` on this link. So **24.8x was never arithmetically
suspect** - it needs datagrams no larger than 2643 bytes and these are 1431 - but
**the 60x reading withdrawn in 18.5 is not reachable at this datagram size**,
because 60x would need a mean under 1092 bytes. 18.5 was right to withdraw it, and
it should stay withdrawn unless a run shows datagrams that small. Three rates now
line up the way rate-scaling predicts: 2.20x at the low 2026-09-11 rate, 8.11x at
119 Mbit/s, 24.8x at the 2026-09-09 rate.

The same run reproduced the skb-mode collapse a third time - 1.00x attached in skb
mode against an 8.11x baseline, recovering to 6.75x on detach - and the driver-mode
attach held GRO at 7.37x, with `rx_errors` steady at 0 across both. 27 checks
passed, none failed. Worth recording for what it verifies beyond 992: this was the
first run against the quilt-regenerated 990/991/992/993/995, so it is also the
hardware evidence that regenerating those patches changed nothing observable.

One caveat on all three figures: the load generator defaults to
`https://proof.ovh.net/files/1Gb.dat` and reported only 119 Mbit/s on a 5G WAN, so
the source is very likely the ceiling rather than the link. Treat 8.11x as a floor
for that rate, not the achievable maximum - see the work queue item on pointing the
harness at a faster source.

### 21.4 Design rules that fall out

1. **Never attach in skb mode on this box.** It costs GRO and LRO everywhere, and
   on `wwan0` it costs the whole point of 991. Use native mode, which on the wired
   ports is genuinely pre-skb and on `wwan0` is 992's hook.
2. **A drop is the only verdict that is free.** `XDP_PASS` keeps everything;
   `XDP_DROP` additionally skips the skb, the stack and RPS. `XDP_TX` and
   `XDP_REDIRECT` both cost the shaper.
3. **The flowtable kfunc is reachable from `wwan0` and not from the wired ports.**
   That is the opposite of where the pre-skb saving is, which is why no
   flow-aware fastpath fits this hardware (16.4).
4. **The BTF platform is load-bearing, not decorative.** It is what makes the
   flowtable kfunc exist at all, and what let the BBRv3 identity be proven from
   the module itself when OpenWrt had stripped the version tag (20.2).
5. **Do not evaluate any of this with `/proc/stat`.** See 18.3. Use exact
   counters, or a fixed-work yardstick timed by wall clock.

---

## 22. The gro_cells + XDP ordering problem, settled

21.1 records that `gro_cells` and `dev->xdp_prog` are incompatible, measured. The
open question was whether that is fixable in the core - because if it were, the
driver-side XDP code in 992 could be deleted and every `gro_cells` driver would
get a GRO-preserving XDP hook for free. That was the most valuable thing this work
had found, so it needed an answer from the tree rather than from reasoning.

Answered 2026-09-12. **It is not fixable in the core, and 992's existing design is
the correct one.** Method: a pristine `v6.12.103` checkout, plus a diff of every
patch in this tree against it to establish the offsets in the header table above.
Line numbers below are pristine; add 5 for `net/core/dev.c` to get this build.

### 22.1 A hook inside `gro_cells_receive()` double-executes

Every skb a gro_cell receives reaches `__netif_receive_skb_core()`, and that
function runs `dev->xdp_prog` itself:

    gro_cells.c:61      napi_gro_receive(napi, skb)             in gro_cell_poll()
    gro.c:303/618/710   gro_normal_one(napi, skb, ...)
    gro.h:514-518       gro_normal_list() -> netif_receive_skb_list_internal()
    dev.c:6000          netif_receive_skb_list_internal()
    dev.c:5914          __netif_receive_skb_list()
    dev.c:5848          __netif_receive_skb_list_core()
    dev.c:5583          __netif_receive_skb_core()
    dev.c:5612          if (static_branch_unlikely(&generic_xdp_needed_key)) {
    dev.c:5616              ret2 = do_xdp_generic(rcu_dereference(skb->dev->xdp_prog), &skb);

An skb-mode attach is what turns that static key on - `generic_xdp_install()` does
`static_branch_inc()` at `dev.c:5958-5959` - so a hook added inside
`gro_cells_receive()` runs the program twice: once per datagram going in, once
more on whatever GRO produced coming out. **The second run is the worse half.** It
hands the program a coalesced superframe, which is precisely the input
`netif_elide_gro()` exists to prevent.

The second site cannot be suppressed. There is no per-skb "XDP already ran" marker
anywhere in the core. The only thing that makes `__netif_receive_skb_core()` skip
is `skb->dev->xdp_prog` being NULL, because that is the argument it passes and
`do_xdp_generic()` returns `XDP_PASS` immediately on a NULL program (`dev.c:5266`,
`5290`). Adding a marker means a new skb bit for one niche case.

One nuance, for honesty: the core does not guarantee one run per skb today either.
The `another_round:` label sits at `dev.c:5607`, *above* the generic-XDP block, so
a VLAN untag or an `rx_handler` returning `RX_HANDLER_ANOTHER` re-runs the program
on the same frame. But those re-runs are the same frame after a header
transformation, never a coalesced aggregate, so they do not license the
gro_cells shape.

### 22.2 Letting the driver opt out of the elision is worse, not smaller

The other candidate was a driver flag that `netif_elide_gro()` honours, leaving
the program on `dev->xdp_prog`. Then `gro_cells` coalesces first and the core runs
the program once, at `dev.c:5616`, on the coalesced skb alone. Per-datagram
filtering disappears entirely. That inverts the guarantee rather than narrowing
it.

### 22.3 What works, and the in-tree precedent

Hold the program on a driver-private pointer, run it per datagram through the
core's own helper, leave `dev->xdp_prog` NULL. Then `netif_elide_gro()` stays
false so GRO survives, and the core's own call site sees NULL so nothing runs
twice. `do_xdp_generic()` takes the program as an argument for exactly this
purpose, and is exported for it:

    dev.c:5262   int do_xdp_generic(struct bpf_prog *xdp_prog, struct sk_buff **pskb)
    dev.c:5296   EXPORT_SYMBOL_GPL(do_xdp_generic);

`drivers/net/tun.c` does this, verified rather than assumed - this closes the
"verify the tun.c precedent" item that 992's commit message was resting on:

    tun.c:210    struct bpf_prog __rcu *xdp_prog;          in struct tun_struct
    tun.c:1200   rcu_assign_pointer(tun->xdp_prog, prog);  from ndo_bpf
    tun.c:1926   rcu_read_lock();
    tun.c:1929   ret = do_xdp_generic(xdp_prog, &skb);
    tun.c:2529   ret = do_xdp_generic(xdp_prog, &skb);

`tun` never assigns `dev->xdp_prog` anywhere in the file. So 992's driver-side code
is not a workaround for a missing core feature - **it is the mechanism**, and the
only shape that keeps both halves of the contract. Nothing in it should be deleted
or simplified.

### 22.4 Scale: eight drivers, none of them with XDP

`gro_cells_receive()` callers in 6.12.103: `vxlan_core.c`, `geneve.c`,
`bareudp.c`, `macsec.c`, `amt.c`, `pfcp.c`, `rmnet_handlers.c`, and with 991,
`mhi_wwan_mbim.c`. **None of the first seven implements `ndo_bpf`, and `grep -ci
xdp` returns 0 for every one of them.** So this build is the first `gro_cells`
driver anywhere with an XDP hook, which is why the interaction has gone unnoticed,
and why there is no driver to copy for this specific pairing. `tun` supplies the
call-pattern precedent but does not use `gro_cells` (`grep -c gro_cells
drivers/net/tun.c` is 0).

### 22.5 Two candidate enhancements to 992 that the tree disproved

Both of these looked like real defects and both were checked before being
claimed. Recording them so they are not "found" again.

**A missing `xdp_do_flush()`.** 992 advertises `XDP_REDIRECT` and never calls
`xdp_do_flush()`, which on a NAPI driver would leave redirected frames sitting in
a per-CPU bulk queue. Not so here: every *generic* redirect target completes its
work inline. devmap's `dev_map_generic_redirect()` ends in `generic_xdp_tx()`
(`devmap.c:721`); xskmap calls `xsk_generic_rcv()`, which takes `pool->rx_lock` and
calls `xsk_flush()` itself; cpumap's `cpu_map_generic_redirect()` does
`ptr_ring_produce()` then `wake_up_process()`. Nothing is deferred, so
`xdp_do_check_flushed()` - called from `__napi_poll()` at `dev.c:6899` under
`CONFIG_DEBUG_NET` - cannot fire for this hook. The bulk queues belong to the
*native* redirect helpers, which this path never uses.

**A missing `rcu_read_lock()`.** 992 does `rcu_dereference(link->xdp_prog)` with no
visible lock. The lock is already held, by upstream code, across the whole
datagram loop:

    mhi_wwan_mbim.c:296   rcu_read_lock();
    mhi_wwan_mbim.c:298   link = mhi_mbim_get_link_rcu(mbim, session);
    mhi_wwan_mbim.c:306   for (n = 0; n < nframes; n++, ...)
    mhi_wwan_mbim.c:348       netif_rx(skbn);          <- the call 991 replaces
    mhi_wwan_mbim.c:351   rcu_read_unlock();

992's pointer read and its `do_xdp_generic()` call both sit inside that region.
Adding a second `rcu_read_lock()` would be noise, and claiming the patch needed one
would have been wrong.

### 22.6 What is actually left for the core: visibility, not capability

The elision is correct. What is wrong is that it is silent. `ethtool -k` keeps
reporting `generic-receive-offload: on` while GRO is elided, so an order of
magnitude of aggregation disappears with no user-visible cause. The install path
already switches off the two *visible* neighbours:

    dev.c:5960   dev_disable_lro(dev);
    dev.c:5961   dev_disable_gro_hw(dev);

Clearing `NETIF_F_GRO` through the same `wanted_features` +
`netdev_update_features()` machinery that `dev_disable_lro()` uses would make the
feature bits describe reality, and would make `netif_elide_gro()`'s
`dev->xdp_prog` test redundant rather than load-bearing. That is a small patch
worth one attempt upstream, on its own and not attached to the MBIM series. It
changes nothing for this build - rule 1 in 21.4 already says never to attach in
skb mode here.

### 22.7 What this closes

* **No core-fix patch, and the number 994 is retired.** The fix that was going to
  be the project's one genuinely new patch does not exist. The honest output of
  the investigation is that 992 was already right, for reasons its commit message
  stated correctly and could not cite. The slot reserved for it is deliberately
  left empty so that "994" keeps meaning only this, and an unrelated patch
  written later that day took 995 rather than reusing it.
* **992 is not to be simplified.** The plan to strip its driver-side XDP once a
  core hook existed is void.
* **The tun.c precedent is verified**, in four parts, at the line numbers above.
* **The series is the deliverable**, unchanged in shape:
  `[PATCH net]` for the use-after-free fix currently bundled in 991, then
  `[PATCH net-next 1/2]` gro_cells and `[PATCH net-next 2/2]` the XDP hook. See
  `992-upstream-submission.md`, section 2 onward.

## 23. Shape A built and run - open - 2026-09-14

This heading said "and closed" for a revision. 23.8 withdraws that closure and
the heading now agrees with it.

Section 16.5 named Shape A as the one result on this box buildable with no
kernel patch, and 16.6 asked for a measurement to decide it. Both halves are now
answered. The lookup works better than 16.5 assumed. The redirect fires on
nothing at all, and the reason is structural rather than a bug in the program.

Built as `x3000/docs/bpf/xdp_ft_wwan.bpf.c` with three programs - a counting
probe, a dry run that decides everything and writes nothing, and the fastpath -
driven by `x3000/docs/xdp-ft-wwan.sh`. 23.12 records the IPv6 arm, which came
later and corrects two claims made in 23.11.

### 23.1 The kfunc works on a raw-IP interface

One 30-second sample on `wwan0` with a download in flight:

| counter | value | |
|---|---|---|
| `seen` | 26043 | equal to the `rx_packets` delta, exactly |
| `hit` | 25619 | 98.37% |
| `lookup_err` | 423 | 1.62% |
| `not_ipv4` | 1 | |

25619 + 423 + 1 = 26043, so every packet is accounted for. `seen` matching the
driver counter exactly means the program sits in front of the whole receive
path rather than a sample of it. This is what 16.5 asserted from the gates and
nobody had run: `bpf_xdp_flow_lookup()` resolves on a raw-IP modem interface.

One correction to the probe's own counters. The split between "miss" and
"lookup error" is not real: `bpf_xdp_flow_tuple_lookup()` returns
`ERR_PTR(-ENOENT)` when `flow_offload_lookup()` finds nothing
(`nf_flow_table_bpf.c:49`) and the caller sets `opts->error` from it (`:96`), so
an ordinary miss sets the error too. The 423 are flow misses.

### 23.2 The redirect fires on nothing

The dry run decides everything the fastpath would - direction, container walk,
flags, teardown, `xmit_type`, egress ifindex, both NAT values - counts what it
would have done, and returns `XDP_PASS` without writing a byte. 236046 packets:

| counter | value |
|---|---|
| `seen` | 236046 |
| `hit` | 233120 (98.8%) |
| `miss` | 2784 |
| `parse_skip` | 142 |
| `torn_down` | 27 |
| `not_direct` | **233093** |
| `would_redirect` | **0** |

142 + 2784 + 27 + 233093 = 236046. Every flow on this box is
`FLOW_OFFLOAD_XMIT_NEIGH`; not one is `XMIT_DIRECT`.

That is fatal to Shape A as 16.5 specified it, because the specification reads
"builds an Ethernet header itself from `tuple.out.h_source` / `h_dest`" - and
`tuple.out` is the union arm that only exists for `XMIT_DIRECT`. For a `NEIGH`
flow there are no MAC addresses in the tuple to build a header from. 16.5 did
not check which arm was populated, and neither did I until the dry run counted
it.

### 23.3 Why nothing was ever XMIT_DIRECT here

> **Retracted in part, 2026-09-14 - see 23.13.** The general claim, "every flow
> on this box is `FLOW_OFFLOAD_XMIT_NEIGH`", is false. A dry run over IPv6
> traffic from a WiFi client measured 221258 packets reaching `XMIT_DIRECT`.
> What survives is the specific reading of `:168` below: the hardware-offload
> route to `XMIT_DIRECT` is closed here by construction. The `DEV_PATH_BRIDGE`
> route at `:154` is open, and 23.8 was right that the flowtable device list
> was what closed it.

`nft_dev_path_info()` sets it in exactly two places:

- `case DEV_PATH_BRIDGE` (`nft_flow_offload.c:154`). The forward-path walk has
  to cross a bridge, and `nft_dev_forward_path()` then requires the device it
  lands on to be one `nft_flowtable_find_dev()` finds in the flowtable's own
  hook list (`:202`), or it returns before copying any MAC.
- `nf_flowtable_hw_offload(flowtable) && nft_is_valid_ether_device(...)`
  (`:168`) - **which requires hardware offload to be on.**

The second is closed by construction here, and this is the part worth carrying
forward. Hardware offload has to stay *off* or
`nf_flow_table_offload_setup()` never takes the `nf_flow_offload_xdp_setup()`
branch (`nf_flow_table_offload.c:1258`) and the per-device XDP hashtable is
never populated - so every lookup returns `-ENOENT`. **The setting that makes
the kfunc answer is the setting that forecloses `XMIT_DIRECT`.** Section 10.2
recorded hardware offload and the kfunc as mutually exclusive; this is a second
and sharper edge of the same blade, and it was invisible until something ran the
decision path and counted.

The upload direction cannot reach the first route either: the walk starts at
`dst_cache->dev`, which for a LAN-to-WAN flow is `wwan0`, and
`nft_is_valid_ether_device()` rejects it at `:60` - `ARPHRD_RAWIP`, not
`ARPHRD_ETHER`, with no `ETH_ALEN` address.

### 23.4 What would make it fire, and why that is not worth taking

`bpf_fib_lookup()` is available to XDP (`xdp_func_proto`,
`bpf_xdp_fib_lookup_proto`) and returns `ifindex`, `smac` and `dmac` on
`BPF_FIB_LKUP_RET_SUCCESS`. It resolves precisely what `XMIT_NEIGH` means the
kernel has not cached. That gives a design with no `XMIT_DIRECT` dependency:
use the flowtable for the one thing only it provides, the NAT translation, and
resolve L2 in the program, as the in-tree `xdp_fwd` sample does.

It is not worth building, and section 14.3 already said why: this router is not
CPU-bound and will not be on this WAN. A fast path that shortens the per-packet
forwarding cost is attacking a resource that is three quarters idle. 23.6 covers
the independent confirmation.

And 17.2 is the other half: any flow taking an XDP redirect leaves the ingress
shaper and the egress qdisc behind, on exactly the link that needs the AQM. So
the redesign would buy a resource this box has spare, at the cost of the one it
does not.

### 23.5 Two techniques worth keeping

Both came out of getting the fastpath to load, and both generalise beyond it.

**A CO-RE type-id relocation cannot resolve against a type defined in more than
one loaded BTF; a field or size relocation can.** The fastpath was rejected with

```
libbpf: relo #7: relocation decision ambiguity: success 90056 != success 90242
```

from `relo_core.c:1369`. `struct flow_offload` is defined in four loaded BTFs
here - measured with `bpftool btf dump`: `nf_flow_table`,
`nf_flow_table_inet`, `nf_tables` and `nft_flow_offload`. libbpf compares
candidates on `bit_offset` first (`:1361`), and identical definitions agree
there, so every `FIELD_*` relocation resolved; but a BTF type id is an index
into one particular BTF, so the candidates can never agree. Dumping the
object's `.BTF.ext` showed 28 relocations, exactly one of them
`TYPE_ID_TARGET`, and it was relo #7:
`bpf_core_type_id_kernel(struct flow_offload)`, the second argument to
`bpf_rdonly_cast()`.

The cast was unnecessary. Nothing dereferenced the pointer - every read went
through `bpf_core_read()`, which is `bpf_probe_read_kernel()` and takes an
arbitrary kernel address, reachable from XDP under `CAP_PERFMON`
(`helpers.c:1892`, `:2017`). Removing it left 27 relocations, all `FIELD_*`.
Where a size is needed, `bpf_core_type_size()` is safe for the same reason the
field relocations are: its value comes from the layout, which every candidate
agrees on, not from an index.

**`container_of()` has to be written as a branch with constant offsets, not as
arithmetic on an index.** `th - dir * sizeof(tuplehash)` compiles to
`r1 *= -88`, and the verifier cannot carry a bound through a multiply by a
negative constant - a register known to hold 0..3 came back with `smin` at
`S64_MIN`, which `check_reg_sane_offset()` (`verifier.c:12895`, message at
`:12916`) rejects. The same function explicitly permits a known constant offset,
negative included, so one branch per direction passes. The `dir <= 1` test three
instructions earlier does not help: llvm applies it to a copy of the register,
and the masking in between breaks the link back to the original.

### 23.6 What is new, and what only confirmed what this document had

Worth separating, because two of the four things I set out as findings were
already recorded here and I re-derived them.

**New:**

- The kfunc hits on `wwan0`, measured - 23.1.
- Every flow is `XMIT_NEIGH`, so Shape A as specified redirects nothing - 23.2.
- The hardware-offload trap that makes `XMIT_DIRECT` unreachable while the
  kfunc is usable - 23.3.
- Both relocation and verifier techniques - 23.5.
- A correction to 9.3, below.

**Already here, and re-derived:**

- *The qdisc bypass.* 17.2 documents it in more depth than I reached,
  including the kernel's own comment at `dev.c:5231` and the
  `sch_handle_ingress()` gap. 16.5 already carried the pointer: "It *does*
skip the egress qdisc, which
  is not a bonus; see section 17.2."
- *This box is not CPU-bound.* 14.3 measured it on 2026-09-10 across four
  alternating 60-second legs at roughly 250 Mbps, and concluded CPU0 would not
  saturate until near 1 Gbps. I re-measured it with one 12-second window at
  103.8 Mbps and reached the same answer.

The re-measurement is not worthless, and the reason is specific: 14.3 carries
an instrument warning because its figures come from `/proc/stat`, which 18.3
showed does not conserve time on this box. My window read `time_squeeze` from
`/proc/net/softnet_stat` instead - a count, not a time, incremented when NAPI
exhausts its poll budget - and it stayed at 0 with `rx_dropped` and
`softnet_dropped` also 0 at 23% busy. That is an independent confirmation using
an instrument that does not share the discredited one's failure mode. The
conclusion of 14.3 stands on firmer ground than it did, which is the only thing
the re-derivation bought.

What it did not buy was time. Both facts were in this file before I started, and
reading 14.3 and 17.2 first would have made 23.4 a paragraph rather than a
measurement.

### 23.7 Correction to 9.3

9.3 says nothing can redirect *into* `wwan0`, citing the
`NETDEV_XDP_ACT_NDO_XMIT` gate at `devmap.c:488`. That is true of the native and
devmap paths and not of the generic one. A generic-mode program redirecting by
ifindex never reaches devmap: `xdp_do_generic_redirect()` (`filter.c:4533`)
applies only `xdp_ok_fwd_dev()` (`:4554`), which checks `IFF_UP` and the MTU,
then calls `generic_xdp_tx()`. So the core does not refuse `wwan0` or an AP
netdev as a generic redirect target.

That is a narrower correction than it sounds. The core permitting the redirect
says nothing about whether `mbim_tx_fixup()` can do anything sensible with the
skb it is handed, which is untested. What changes is the reason: "the core
refuses it" is wrong, and "the driver has never been asked" is right.

### 23.8 Status - open, not closed

An earlier revision of this section closed Shape A. That was wrong twice over
and is withdrawn.

**It rested on 14.3 and 17.2 being taken as settled the moment they were
found.** 14.3 carries its own instrument warning: its figures come from
`/proc/stat`, which 18.3 showed does not conserve time on this box, and its
headline - CPU0 not saturating until near 1 Gbps - is a linear extrapolation
from 25.8% at roughly 250 Mbps that nothing has tested. My own window ran at
103.8 Mbps, less than half that rate, so it corroborates a weaker claim than
14.3 makes, not the same one. "This box is not CPU-bound" is better supported
than it was and is still not established at the rates that matter.

**And it rested on an explanation with two candidates and no test.** 23.3 gives
the hardware-offload trap, which is solid, but it does not explain why the
*download* direction is `NEIGH`. That direction egresses through `br-lan`, so
the walk should reach `DEV_PATH_BRIDGE` and set `XMIT_DIRECT` at `:154`. One
mechanism fits and has not been checked:

`nft_dev_path_info()` sets `info->indev` from the `DEV_PATH_ETHERNET` entry -
the **physical** LAN port - and `nft_dev_forward_path()` then discards the whole
result unless `nft_flowtable_find_dev(info.indev, ft)` finds that device in the
flowtable's own hook list (`:202`). This tree's firewall4 patch
`001-flowtable-fall-back-to-l3-device` builds that list from **L3 devices**, so
it holds `br-lan` and `wwan0`. If the physical ports are absent, the walk sets
`XMIT_DIRECT` and the caller throws it away two lines later.

That is read from source, not measured, and it is settled by one command:

```sh
nft list ruleset | sed -n '/flowtable/,/}/p'
```

If `devices` names `br-lan` and `wwan0` rather than `lan1`, `lan2` or `eth1`,
the hypothesis holds - and the fix is a flowtable device-list change, not a
kernel patch or the `bpf_fib_lookup()` rewrite. It would also mean the patch
that put `wwan0` into the list is what took the physical ports out, which is a
regression this tree owns.

> **Answered, and only half right - 2026-09-14.** 23.9 read the list and the
> three bridge ports were indeed absent, so the first half holds. The second
> half does not: the ports were then **added live** and seven subsequent
> windows, on fresh flows from both a wired and a Wi-Fi client, still read
> `XMIT_NEIGH` on 100% of hits. A device-list change is therefore necessary and
> **not sufficient** in its live form. 23.16 carries the measurement and the
> two untested candidates for why. What is left is the `fw4` template, which
> creates the flowtable with the ports already in it so no flow can predate
> them.

### 23.9 The device list, read - and three windows that measured nothing

**Answered, and the hypothesis holds.** The flowtable device list was:

    devices = { "br-lan", "eth0", "wwan0" }

`eth1` absent, and so are `phy0-ap0` and `phy1-ap0`. Those three are the bridge
ports - the devices `info->indev` resolves to after the walk - and none of them
was in the list. So the walk reaches `DEV_PATH_BRIDGE`, sets `XMIT_DIRECT`, and
`nft_dev_forward_path()` discards the result at `:202` because the device it
landed on is not one `nft_flowtable_find_dev()` can find.

fw4 builds that list from **zone** devices: the wan zone gives `eth0` and
`wwan0`, the lan zone gives `br-lan`. A bridge port is not a zone device, so it
is never a candidate. That is the same gap
`001-flowtable-fall-back-to-l3-device` already fixed from the other direction -
and it means this tree's own patch, which added `wwan0` because it had only an
`l3_device`, sits beside a case nobody looked for.

Worth stating plainly about `br-lan`: it is a real `net_device` - bridge master,
own ifindex, `ARPHRD_ETHER`, valid MAC - so it is a legitimate entry for hook
registration, which is the list's first job. The list's second job at `:202` is
to answer "is the device this packet will physically leave on in here", and the
answer for a bridged client is always a port, never the bridge. One list, two
jobs, and `br-lan` can only satisfy the first.

**Three windows measured nothing before one measured this.** Each failure mode
is a live trap and none announced itself:

| window | what it showed | why it was worthless |
|---|---|---|
| dry run after adding `eth1` | `parse_skip` 145880 of 146062 | the download resolved AAAA; this program is IPv4-only |
| `curl -4` on the router | 66108 `lookup_err` of 66114 | `curl` ran *on the box*, so those connections terminated locally and never entered the flowtable, which only holds forwarded flows |
| both | `hit` 6 and 16 | with the table empty of the traffic, `not_direct` had nothing to count |

The preconditions, in order: **IPv4**, **forwarded through the box**, and
**flows created after the flowtable change** - the route is computed once, at
flow creation, so existing conntrack entries keep their old verdict. The dry
run's counters now name all three failures separately rather than pooling them
into one slot, which is what made the first of these take a whole cycle to
diagnose.

### 23.10 Box state, 2026-09-14, and what it contradicts

Captured with `boxstate.sh`, which exists because none of the windows above
recorded the configuration they ran under:

- **No shaper on `wwan0`.** `qdisc fq_codel 0: root`, no rate limit, and no
  ingress qdisc. fq_codel does not shape; it manages a queue that only forms if
  the bottleneck is local, and on a cellular link it is not. A download's
  bufferbloat is downstream, which needs ingress shaping through an IFB, and
  there is none. This tree carries `cake-wan.init` and 55 KB of
  `qos-latency-research.md`, and **cake is not running**. That is the most
  likely source of the 33.5 ms average and 124 ms tail in 23.4, and it is a
  configuration problem rather than a kernel one. It also empties W0006, which
  exists to preserve cake through an XDP redirect.
- **`packet_steering` is 2, and every interface reads `rps_cpus 3`** - both
  CPUs. Section 14.3 records this box as `packet_steering='1'` with
  `packet-steering.uc` assigning `wwan0` to CPU1. The configuration has changed
  since that measurement, so 14.3's legs were taken under a steering setup this
  box no longer runs.
- **Every MHI interrupt lands on CPU0 despite an affinity mask of `3`** - irq 90
  at 94895/0, irq 91 at 114834/0. The mask permits both CPUs and the hardware
  uses one. That is a *measured* confirmation of the `MSI_FLAG_NO_AFFINITY`
  behaviour W0001 rests on, which had been read from source only. It also fixes
  what W0001 actually does: `threadirqs` works because it turns the handler into
  a schedulable thread, not because it moves an interrupt. Rewriting the mask
  alone would do nothing.
- **`irqbalance` is running**, managing those masks live. Any IRQ-placement
  test has to account for it or it will be fought mid-window.
- **`eth0` is down.** The wired WAN is inert, so its flowtable entry does
  nothing and every wired result on this box is `eth1` only.
- **`threaded=0` on every interface**, so W0002 is not applied. GRO on
  everywhere, LRO off, `gro_max_size` at the 65536 default,
  `netdev_max_backlog` at the 1000 default.

### 23.11 This link is 464XLAT, and one window measured IPv4 at 0.8% of it

> **The headline figure is retracted, 2026-09-14 - see 23.13.** 0.8% was one
> window of one workload, not a property of the link. Later windows on the same
> box within the hour measured 99.99% IPv4 and 99.7% IPv6. Everything below
> about the 464XLAT topology and the DNS64 evidence stands; any claim that this
> link *has* a family ratio does not. The heading said "IPv4 is 0.8% of it" and
> has been changed to say which window.

The 464XLAT topology is the single most important fact about this WAN, and it
was not in any document until now.

`wwan0` carries `inet 192.0.0.2/27` with `default via 192.0.0.1`. That is the
RFC 7335 IPv4 Service Continuity prefix - the standard CLAT address in a
464XLAT deployment. There is no `nat46` module, no `clatd`, no separate
interface: **the CLAT is inside the modem**. Linux hands IPv4 to `192.0.0.1`
and the RM520N translates it to IPv6 before it goes over the air.

So the XDP program is on the right interface and sees genuine IPv4 for IPv4
flows. That part is fine.

The resolvers are `192.0.0.30` and `fd00:976a::9`, carrier DNS doing **DNS64**.
Confirmed by decoding an answer: `ipv4.download.thinkbroadband.com`, a host
whose entire naming convention promises IPv4-only, resolved to
`2607:7700:0:40::50f9:6394` - and the low 32 bits of that address are
`0x50f9:0x6394` = `80.249.99.148`, its own A record. The prefix is the NAT64
prefix and the address is synthesized.

The consequence is that every dual-stack-capable client picks IPv6 for
essentially everything. Measured over a 30-second speedtest:

| | |
|---|---|
| `wwan0` rx_packets | 340418 |
| IPv4 `InReceives` | 44 |
| IPv6 `Ip6InReceives` | 5329 |
| **IPv4 share** | **0.8%** |

**This caps W0038 at under one percent of traffic**, independently of every
other blocker. The program is IPv4-only by an explicit decision in its own
header - "the rewrite for v6 is a different function and getting one right is
worth more than getting two nearly right" - which was a reasonable call made
without knowing the link is 464XLAT with DNS64. On this network it is backwards.

Two things make the correction cheap rather than costly:

- **The kfunc already handles IPv6.** `bpf_xdp_flow_lookup()` has a
  `case AF_INET6:` arm filling `src_v6`/`dst_v6` (`nf_flow_table_bpf.c`). Same
  lookup, no kernel change.
- **The IPv6 fast path is simpler, not harder.** ~~Native IPv6 has no NAT, so
  the address and port rewrite and all of its checksum arithmetic disappear.~~
  **Wrong, corrected in 23.12:** the flowtable implements NAT66
  (`nf_flow_snat_ipv6()` at `nf_flow_table_ip.c:516`), so the address and port
  rewrite is needed and is implemented. What is true is the narrower claim -
  IPv6 has no *header* checksum and `hop_limit` is not in the L4
  pseudo-header, so the decrement is bare and only the L4 checksum is ever
  repaired. Simpler, not absent.

One anomaly recorded and deliberately not chased: 340418 raw datagrams against
5373 IP-layer receives is about 63x aggregation, where MTU-sized packets into a
65536-byte `gro_max_size` would cap near 43x. That implies a mean datagram
around 1040 bytes, which is small for a speedtest. It does not affect the
family ratio, since both families take the same path, but it is unexplained and
it bears on the GRO work rather than on this section.

**Open questions, in the order they should be answered:**

0. ~~Should the program be made IPv6-capable before anything else?~~ **Answered
   and done - 23.12.** Both programs now parse both families.
1. ~~Does adding the three bridge ports produce `XMIT_DIRECT` on a forwarded
   download?~~ **Answered - no.** The device list was changed live and reads
   `br-lan, eth0, eth1, phy0-ap0, phy1-ap0, wwan0`. Seven windows since, from a
   wired LAN client and a Wi-Fi client, read `XMIT_NEIGH` on 100% of hits -
   `myxmit_direct` is zero in every one. The live addition is not sufficient;
   see 23.16. The remaining form of the question is whether putting the ports
   in the **fw4 template** changes it, which is the only live lead left.
2. Why is cake not running on `wwan0`, and what does
   `qos-latency-research.md` already conclude about it? This is the only
   genuinely poor measurement on the box and it is not an XDP question.
3. Independently of Shape A: is 14.3 still true at the rates this link reaches,
   and under the steering this box actually runs today?
   A saturating window with `time_squeeze` - a count, not a `/proc/stat` time -
   is the instrument 18.3 says to use, and nothing has run one at ~277 Mbps.

**What is settled:** the lookup half, at 98.8% hit, and both techniques in 23.5.
Any future program wanting NAT state for a modem flow can have it.

The harness stays: `xdp-ft-wwan.sh check | probe | dryrun | status | off`. The
dry run in particular is worth reusing - it decides everything and writes
nothing, so the next idea of this shape can be costed before it is trusted with
a packet.

### 23.12 The IPv6 arm, built - 2026-09-14

23.11 measured this link as 0.8% IPv4 and named the IPv4-only scope as the
thing to fix first. Both objects now parse both families. Nothing has been run
yet: this section records what was built and what building it turned up, and
`would_redirect` is still 0 for the reason 23.3 gives, which is not a family
question.

New checksums, and the build reproduces byte for byte with
`-fdebug-compilation-dir=.`:

```
99851352f1cf32ae71987f5de58fcc99ee44bfff262e7fba67731cd98179419c  bpf/xdp_ft_probe.bpf
f8684e26d7d2009f981083d401d1aa6ff3d8e9515242b87e136fee1aba023b1d  bpf/xdp_ft_wwan.bpf
```

The probe's old object rebuilt to its recorded `c4371b7a...` before the source
was touched, which is the first end-to-end confirmation that the reproducibility
claim in `xdp-ft-wwan-sources.md` is true rather than argued.

#### What is cheaper about v6, read from source

- `bpf_xdp_flow_lookup()` already has the family. `case AF_INET6:` fills
  `src_v6`/`dst_v6` from `fib_tuple->ipv6_src`/`ipv6_dst`
  (`nf_flow_table_bpf.c:84-88`). No kernel change of any kind.
- No header checksum. IPv6 has none and `hop_limit` is not covered by the L4
  pseudo-header, so the kernel decrements it bare at `nf_flow_table_ip.c:682`
  and so does this program. The v4 arm has to repair `iph->check` after both
  the address change and the TTL decrement.
- No extension-header walk to write, because there is none to match.
  `nf_flow_tuple_ipv6()` switches on `nexthdr` and returns −1 on anything that
  is not TCP, UDP or GRE (`:593-608`), so a packet behind a hop-by-hop or
  fragment header is not in the flowtable at all and walking past it could only
  produce a lookup that cannot hit.
- The kfunc ignores `tos` and `tot_len` entirely. It builds its
  `flow_offload_tuple` from `iifidx`, `l3proto`, `l4proto`, the two ports and
  the addresses (`nf_flow_table_bpf.c:63-92`) and reads neither field.
  `struct bpf_fib_lookup` is a carrier here, not a FIB request.

#### Correction to 23.11: IPv6 does have NAT here

23.11 said "native IPv6 has no NAT, so the address and port rewrite and all of
its checksum arithmetic disappear." That is wrong, and it is corrected in place
above as well as here, because it was the load-bearing reason the v6 arm was
called the easy one.

The flowtable implements NAT66 for v6 exactly as it does for v4:
`nf_flow_snat_ipv6()` at `nf_flow_table_ip.c:516`, `nf_flow_dnat_ipv6()` at
`:539`, both reading the same peer-tuple fields, with
`inet_proto_csum_replace16()` (`net/core/utils.c`) repairing the L4 checksum
across four 32-bit words. A program that ignored `NF_FLOW_SNAT` on a v6 flow
would forward it untranslated - which is a silent wrong-destination bug, not a
missed optimisation.

The rewrite is implemented. A `nat66` counter records whether it ever fires on
this box; on a routed prefix it should stay at zero, and now that is a
measurement rather than an assumption.

What survives of the original claim is the narrower version: **the v6 rewrite is
the simpler one, not the absent one.**

#### A defect in the shipped IPv4 rewrite, found by reading its v6 twin

Modelling `xlate6()` on `nf_flow_nat_ipv6_udp()` meant reading the v4 original,
which does this and the program did not:

```c
	if (udph->check || skb->ip_summed == CHECKSUM_PARTIAL) {
		inet_proto_csum_replace4(&udph->check, skb, addr, new_addr, true);
		if (!udph->check)
			udph->check = CSUM_MANGLED_0;
	}
```

A UDP checksum that lands on `0x0000` after a rewrite reads on the wire as *no
checksum present*, so the kernel writes the numerically identical `0xffff`
instead. The program wrote the zero. That is a one-in-65536 corruption per
rewritten datagram, in a path no test would ever have reached, and the same
guard is in `nf_flow_nat_port_udp()` for the port rewrite. Both arms have it
now. TCP is excepted on purpose: `0x0000` is a legal TCP checksum.

It is worth naming what found this. Not a test, not a review of the v4 code, and
not the compiler - reading the kernel function that the *other* family's code had
to match. The pattern generalises: the cheapest audit of a hand-written kernel
imitation is writing a second one against the same reference.

#### Two traps in writing it, both worth keeping

**A field name that is a macro cannot be relocated.** The obvious way to read a
v6 address out of the peer tuple is `other->tuple.src_v6.s6_addr`. That does not
load. `s6_addr` is a `#define` over `in6_u.u6_addr8`
(`include/uapi/linux/in6.h`), so there is no BTF field of that name for CO-RE to
resolve against, and the local mirror declaring one would not change the target.
The fix is to relocate only as far as the enclosing field and read the bytes:
`bpf_core_read(dst, 16, &other->tuple.src_v6)` needs the offset of `src_v6`,
which exists, and nothing inside `struct in6_addr`, which does not. The general
rule: **CO-RE relocates BTF field names, and a macro is not one** - where a
kernel header defines the name being reached for, check it is a member and not
a `#define` before assuming a relocation exists.

**Two families cannot share a typed header pointer across the branch.** Holding
`struct iphdr *` and `struct ipv6hdr *` in one `struct parsed` and setting the
unused one to NULL does not verify: the two arms spill different types into one
stack slot, the merge marks the slot scalar, and the next dereference is
rejected outright. The shape that works is to keep only scalars across the
branch - `data`, `data_end`, `family`, `l4proto` - and re-derive the header with
its own bounds check at each use site. Two compares per use, and every access is
locally provable. The same reasoning covers the port pointer: both arms compute
it at a *constant* offset, so both produce the same pointer type and the merge
is fine, where a variable offset would not be.

That is the third distinct verifier-shape rule this program has produced, after
the `container_of()` branch in 23.5. They have a common root: **the verifier
reasons per path, and anything that merges two paths' pointer provenance loses
what it knew about both.**

#### Counters

Twenty slots, up from seventeen, and three of them are observations rather than
exits:

| slot | |
|---|---|
| `not_ip` | was `not_ipv4`; now means the version nibble was neither 4 nor 6 |
| `v4`, `v6` | observations - what the window contained |
| `nat66` | observation - a v6 flow carrying SNAT or DNAT |

`v4` and `v6` do not sum with the rest: a packet counted in `v6` is counted
again in whichever exit it took. They exist because three windows in 23.9 were
thrown away for measuring the wrong family or the wrong scope, and the family
split on this link changes hour to hour. Reading it from the same dump as the
result removes one whole class of misreading, rather than requiring a separate
`boxstate.sh mix` run alongside.

The probe object declares ten slots and the fastpath object twenty, which is how
`status` knows which program left the map behind when nothing is attached.

#### What is verified and what is not

Verified, statically:

- Both objects compile with no warnings under
  `-Wall -Wextra`, and the probe rebuild reproduced its recorded sha256.
- The fastpath carries 62 CO-RE relocations, all `FIELD_*` or `TYPE_SIZE`, and
  **no `TYPE_ID_TARGET`** - the relocation class 23.5 showed cannot resolve
  against a type present in four BTFs. A rebuild that produces one has
  reintroduced that bug.
- The probe still carries **zero** relocations, which is the whole reason it
  stays a separate object now that the original reason is gone.
- No multiply appears anywhere in the generated code, so the
  `check_reg_sane_offset()` rejection in 23.5 cannot recur.
- The generated code was read back for the three things most likely to be
  silently wrong: the `0xffff` mangled-zero guard gated on `IPPROTO_UDP`, the
  `hop_limit` decrement at offset 7 with no checksum arithmetic after it, and
  the EtherType select between `0x0800` and `0x86dd`.
- The harness's counter parser was re-tested against twenty slots in all four
  output shapes it handles - JSON with `formatted`, JSON pretty-printed, JSON
  without BTF, and plain text - and agrees with the fixture in every one.

Not verified, and this is the whole of it:

- **Neither object has been loaded on the box at this revision.** Relocation and
  verification are both claims about a kernel this container does not have.
- **The rewrite has still never executed, in either family.** `not_direct`
  accounts for every hit, so the dry run has never reached the commit stage.
  Every checksum path in this program has been through a compiler and a
  disassembler and nothing else.
- **Whether the flowtable holds IPv6 flows on this box at all is unmeasured.**
  Everything measured so far was IPv4. `probe` answers it in one window and
  should be the first thing run.

#### Next, in order

1. `xdp-ft-wwan.sh check`, then `probe 30` under an ordinary download. This
   answers whether the kfunc hits for IPv6 - the one fact the whole v6 arm
   assumes and nothing has tested.
2. `dryrun 30` under the same load. The first window on this link that measures
   the traffic that is there rather than 0.8% of it. Watch `not_direct` against
   `hit`: this re-runs 23.9's device-list question without needing manufactured
   IPv4 traffic.
3. Only if `would_redirect` is non-zero does anything about the fastpath matter.
   If it is still 0, the blocker is 23.3 and no amount of program work moves it.

### 23.13 Four windows, one retraction, one impossible counter - 2026-09-14

The both-families build ran on the box. Four windows, and they overturn two
things this document asserted. The numbers are recorded here as data; the one
that needs an explanation does not get a guess.

| | W1 LAN | W2 LAN paired | W3 WiFi | W4 WiFi |
|---|---|---|---|---|
| `seen` | 136164 | 134850 | 456861 | 103562 |
| `v4` | 136163 | 134842 | 1510 | 872 |
| `v6` | 1 | 8 | 455351 | 102690 |
| `hit` | 134792 | 133378 | 447488 | 102435 |
| `not_direct` | - | - | 934 | 214 |
| `bad_dir` | - | - | 225163 | 42043 |
| **`would_redirect`** | - | - | **221258** | **60217** |

W1 and W2 are probe windows, so they carry no decision counters.

#### The family ratio is a property of the workload, not the link

23.11 recorded 0.8% IPv4 and reversed this program's scope on it. W1 and W2
measured 99.99% **IPv4** on the same box. Both are right about their own window
and neither describes "the link".

W2 settles that it is not an instrument artefact, by running both instruments
over the same thirty seconds:

| | IPv4 | IPv6 |
|---|---|---|
| probe, wire packets on `wwan0` | 134842 | 8 |
| `InReceives`, host-wide, post-GRO | 4414 | 14 |

They agree on the family. So 23.11's window genuinely carried IPv6 - a speedtest
to a dual-stack host - and W1/W2 genuinely carried IPv4. What changes between
them is what the clients were doing.

Two things fall out of that paired window:

- **GRO on `wwan0` aggregates at least 30x.** 134842 wire packets became 4414
  IP-layer receives. At least, because `InReceives` is host-wide and counts
  LAN-side receives too, which inflates the denominator. That is most of the 63x
  anomaly 23.11 flagged and left unexplained, now measured per-family instead of
  inferred across both.
- **`Ip6InReceives` is the wrong instrument for a WAN family mix.** 14 IPv6
  receives against 8 wire packets on `wwan0`: the excess is LAN-side chatter.
  `boxstate.sh mix` reads it host-wide and will overstate IPv6 whenever WAN IPv6
  is low.

**So building both families was right for a different reason than the one
given.** Not "IPv4 is 0.8%" but: a single-family program measures nothing about
the other half, and which half is live changes with the workload. Two windows,
two opposite answers, is the whole argument.

#### XMIT_DIRECT is reachable, and 23.3's general claim is false

`would_redirect` has been 0 in every previous run. W3 and W4 put it at 221258
and 60217 - 48% and 58% of what was seen. The `DEV_PATH_BRIDGE` route at
`nft_flow_offload.c:154` is open, which is what 23.8 predicted when it withdrew
the closure and named the flowtable device list as the suspect.

**Three variables move together between the windows that redirect and the ones
that do not**, and no measurement yet separates them:

| | W1/W2 | W3/W4 |
|---|---|---|
| family | IPv4 | IPv6 |
| client | wired LAN | WiFi |
| bridge port | `eth1` | `phy0-ap0` / `phy1-ap0` |

"IPv6 flows are DIRECT" fits. So does "flows created after the ports were added
are DIRECT", and so does "some bridge ports are in the flowtable list and others
are not" - the additions were made live with `nft` and do not survive
`fw4 reload`. One variable at a time will sort it; asserting the family
explanation now would be the same mistake as 23.11.

#### An impossible counter, and why it is not being explained yet

`bad_dir` counts lookups whose `tuple.dir` read back outside 0..1. It was 41%
and 50% of hits in the two IPv6 windows.

That value cannot exist in the kernel. `dir` is written in exactly one place,
`nf_flow_table_core.c:27`, only ever 0 or 1, and `flow_offload_lookup()` then
uses it as a `container_of` index. A 2 or a 3 there would compute a wild pointer
inside the kernel on the way to returning the tuplehash. The kernel does not
fault. **So the kernel's value is fine and this program's read of it is wrong.**

It matters because `dir` selects the `container_of` walk and the NAT peer
fields. A read that is wrong 41% of the time is not reliably right the other
59%; it is landing on a legal value. **So `would_redirect` is not yet a number
to trust**, and the first non-zero redirect count this program has ever produced
has to be treated as provisional.

Two mechanisms fit the generated code and each predicts something the data
denies:

- *The eight-byte bitfield probe read lands in the trailing union rather than on
  the bitfield byte.* For an `XMIT_NEIGH` flow the union holds a kernel pointer,
  so `dir` would come back effectively random - but W1's IPv4 traffic is almost
  entirely `NEIGH` and its `bad_dir` is 0.05%, not 50%.
- *The read is correct and something else is at fault.* Then the IPv6 windows
  have no explanation at all.

41% in one window and 50% in another also rules out a fixed mis-shift, which
would be constant.

Naming a third candidate would not be thoroughness. The build now carries the
measurement that discriminates instead:

| slot | what it settles |
|---|---|
| `dir2` / `dir3` | a constant wrong value means something different from a varying one |
| `l3_ok` / `l3_bad` | `tuple.l3proto` against the packet's own family |
| `iif_ok` / `iif_bad` | `tuple.iifidx` against `ctx->ingress_ifindex` |
| `baddir_xmit_direct` / `baddir_xmit_other` | `xmit_type`, read from the **same byte** as the bad `dir` |

`l3proto` and `iifidx` are plain scalars beside the bitfield, read through the
`FIELD_BYTE_OFFSET` relocation class already proven good here, and both are part
of the lookup key - so a tuplehash that comes back disagreeing with either is
not the one that was asked for. Both agreeing means the pointer and the offsets
are right and the fault is in the two-bit extraction alone. Either disagreeing
means `th` is not what it should be and every value read through it is void,
`would_redirect` included.

#### A harness defect the same windows exposed

W4's exit counters summed to 39 more than its hits, where every earlier window
closed exactly. The cause is in the harness, not the program: `dump` ran while
the program was still attached, so a packet arriving mid-dump could bump `hit`
after that slot had been read and bump its exit slot before that one was. Small,
and it is exactly the kind of discrepancy that gets blamed on the program.
`unhook` is now split out of `detach` and runs before the dump.

### 23.14 The impossible counter, answered - 2026-09-14

23.13 recorded 41-50% of lookups reading `tuple.dir` back as a value the kernel
cannot hold, and declined to explain it. The diagnostic build answers it, and
the answer is the good one.

One window, 456173 packets, 99.99% IPv6:

| | |
|---|---|
| `hit` | 444040 |
| `l3_ok` / `l3_bad` | **444040 / 0** |
| `iif_ok` / `iif_bad` | **444040 / 0** |
| `dir2` / `dir3` | **0 / 186297** |
| `baddir_xmit_direct` / `baddir_xmit_other` | **0 / 186297** |
| `not_direct` | 17 |
| `would_redirect` | **257706** |

`186297 + 20 + 17 + 257706 = 444040`, so every hit is accounted for.

**The returned tuplehash is the right one.** `l3proto` agreed with the packet's
own family and `iifidx` agreed with the ingress ifindex on every one of 444040
lookups, with not a single disagreement. Both are part of the lookup key, so a
tuplehash that came back disagreeing with either would not be the one that was
asked for. It always was. **`th` is sound, the `FIELD_BYTE_OFFSET` relocations
are sound, and `would_redirect` is not void** - which was the outcome to rule
out first and is now ruled out by measurement rather than by argument.

**The wrong value is a constant.** `dir2` is zero and `dir3` is all of it. Not a
race, not random bits: the same wrong answer every time. A race would have split
between 2 and 3.

**And `iif_ok` pins what the right answer must have been.** Every matched
tuplehash has `iifidx` equal to the `wwan0` ingress ifindex. For a
LAN-initiated flow that is `tuplehash[FLOW_OFFLOAD_DIR_REPLY]`, so `dir` should
read 1 on essentially all 444040. 186297 of them read 3.

So: the pointer is right, the plain-field reads through it are right, and the
two-bit bitfield extraction beside them is wrong in a fixed way. That is a bug
in this program, in one expression, and it is fixable.

#### What it costs, and what it does not

The 257706 packets counted as `would_redirect` read `dir` as 0 or 1 and
`xmit_type` as `DIRECT`. Those are not proven correct - a read that is
systematically wrong can land on a legal value - but they are no longer
suspected of coming from the wrong memory. The honest statement is that
**`would_redirect` is a floor, not a figure**: 186297 packets were rejected on
a `dir` value that should have been 1, and had the extraction been right they
would have gone on to the `xmit_type` test like the rest.

`baddir_xmit_other` being all 186297 is consistent with that and with nothing
else obvious: on the packets whose `dir` came back 3, `xmit_type` read as
something other than `DIRECT`, even though `not_direct` on the packets with a
good `dir` is 17 out of 257723. Two reads out of the same byte disagreeing that
sharply is the signature of the extraction, not of the data.

#### Not yet explained, and deliberately not guessed at

Why the extraction is wrong is still open. What is now excluded, by
measurement rather than by reasoning:

- the pointer (`l3_ok`, `iif_ok`)
- a race (`dir2` is exactly zero)
- the `FIELD_BYTE_OFFSET` relocation class (the same class carries `l3proto`
  and `iifidx`)

What remains is the bitfield relocation quartet -
`BYTE_OFFSET`/`BYTE_SIZE`/`LSHIFT_U64`/`RSHIFT_U64` as libbpf patches them
against this kernel's BTF - and the eight-byte probe read the macro builds from
them. The next build reports those four patched constants and the raw byte, so
the arithmetic can be checked against the kernel's real layout instead of
inferred from the local mirror's.

#### 23.14 is itself partly wrong - see 23.15

> The relocation dump of the same evening contradicts the reading above. The
> byte the `dir` bits live in is **5 on every one of 267510 hits**, which is
> `dir` 1 and `xmit_type` NEIGH - so `would_redirect` should have been zero,
> and calling it "a floor, not a figure" was still too generous. 23.15 has the
> decode. What survives from this section is the part that was measured rather
> than inferred: `th` is sound, the plain-field relocations are sound, and the
> wrong value is a constant rather than a race.

#### The measurement that settled it, as a method

Worth keeping separately from the result. The question was "is `th` wrong or is
the extraction wrong", and the instrument was two ordinary scalar reads of
fields that are *part of the lookup key*. A field the caller supplied and the
kernel matched on is a free self-check: if it comes back different from what
was asked for, the answer is not about the question. That works for any kfunc
or map lookup that takes a key, costs two probe reads, and needs no knowledge
of the bug being chased.

### 23.15 The relocation dump, and a fourth thing I got wrong - 2026-09-14

The build that reports what CO-RE actually patched in ran. It settles the
layout completely and it contradicts 23.14's conclusion.

```
  dir_off  58    dir_sz  1    dir_lshift  62    dir_rshift  62
  xmit_off 58    xmit_sz 1    xmit_lshift 59    xmit_rshift 61
  l3_off   48    iif_off 44   tuple_off   8     rhash_sz    88
  raw_lo   98304005   raw_hi  2147483647
```

and the byte histogram had exactly one non-zero bucket:

```
  b5              267510          <- equal to hit, to the packet
```

#### The layout is confirmed, beyond argument

`tuple_off` 8 plus `l3_off` 48 puts `l3proto` at tuple+40 and `iifidx` at
tuple+36, which is where they are. Decoding `raw_lo`/`raw_hi` as the eight
bytes at `th+58`:

| address | value | |
|---|---|---|
| tuple+50 | `0x05` | the bitfield byte |
| tuple+51 | `0x00` | `in_vlan_ingress` |
| tuple+52..53 | `0x05dc` | **mtu = 1500** |

An mtu of exactly 1500 at exactly tuple+52 is not something that lands there by
accident. The offsets are right, the pointer is right, and `dir_off` 58 is the
bitfield byte and not the union beyond it - which was the mechanism 23.13
proposed and can now be discarded outright.

#### And the byte says NEIGH

Byte 5 is `0b101`: `dir` = bits 0-1 = **1** (REPLY), `xmit_type` = bits 2-4 =
**1** (`FLOW_OFFLOAD_XMIT_NEIGH`), `encap_num` = 0. Applying the patched shifts
to it by hand - `(5 << 62) >> 62` and `(5 << 59) >> 61` - gives 1 and 1.

Every hit in the window had that byte. So:

- `dir3` = 136122 should be **0**. The byte says `dir` is 1.
- `would_redirect` = 131209 should be **0**. The byte says `xmit_type` is
  NEIGH, so nothing in that window was ever a redirect candidate.

**23.3's original claim stands and my retraction of it in 23.13 was wrong.**
Every flow on this box is `FLOW_OFFLOAD_XMIT_NEIGH` after all. That is the
fourth claim of mine this day to be overturned by a better measurement, and it
is the one I most wanted to be true - `would_redirect` going non-zero for the
first time was the result the whole of W0038 had been waiting for. Wanting it
is exactly why it needed the harder check, and it did not get one until now.

#### What is now the open question

Deterministic arithmetic on a constant byte cannot produce two different
answers, and the two instruments in the same window did. One of them is not
reading what it says it is reading, and the decode says which one to trust: the
eight-byte read produced mtu 1500 at the right offset, which the other cannot
match as evidence.

So the suspect is `BPF_CORE_READ_BITFIELD_PROBED` itself, not the relocations
it is given. The next build settles that too, and settles it as a fix rather
than only a diagnosis: `mydir_*` and `myxmit_*` extract the same two fields by
hand from the eight-byte read, with the same patched shift amounts, differing
only in that the upper 56 bits are provably zero where the macro reads one byte
into a `u64` and trusts the rest of that word to be the zero it initialised.

- If `mydir_1` and `myxmit_neigh` account for every hit while `dir3` and
  `would_redirect` stay where they are, the macro is the fault, the hand
  extraction is the fix, and it goes in permanently.
- If both agree, then the byte changes between the two reads, and the question
  becomes what writes it.

#### A note on how this went wrong

Three rounds of this were spent proposing mechanisms from the local struct
mirror's layout. The mirror is not what the program runs against - CO-RE
replaces every offset from the kernel's own BTF at load - so every one of those
mechanisms was reasoning about a layout that does not exist on the box. The
instrument that settled it in one window was four `__builtin_preserve_field_info`
calls reporting what the loader actually wrote. **Where a value is patched at
load time, print the patched value before theorising about it.**

### 23.16 The macro was the bug, and XMIT_DIRECT was never reachable - 2026-09-14

The hand extraction ran beside the macro on the same packets. One window,
363290 packets, 99.9% IPv6:

| reading | value |
|---|---|
| `hit` | **354468** |
| `mydir_1` (hand) | **354468** |
| `myxmit_neigh` (hand) | **354468** |
| byte histogram `b5` | **354468** |
| `dir3` (macro) | 197509 |
| `would_redirect` (macro's `xmit_type`) | 156892 |

`mydir_0`, `mydir_other`, `myxmit_direct`, `myxmit_other`, `l3_bad` and
`iif_bad` are all zero. Four independent readings - the hand extraction of
`dir`, the hand extraction of `xmit_type`, the raw byte, and `hit` itself -
agree to the packet.

**`BPF_CORE_READ_BITFIELD_PROBED` is the fault.** It split a constant input
55.7% / 44.3% between two answers, which deterministic arithmetic on a fixed
byte cannot do, so its result depends on something that varies between packets.
Everything it produced in 23.13, 23.14 and 23.15 - the impossible `dir` values
and every `would_redirect` - was an artefact of the instrument.

#### What this settles

- **23.3 stands.** Every flow on this box is `FLOW_OFFLOAD_XMIT_NEIGH`, measured
  now rather than argued. `would_redirect` is zero and always was. The
  retraction in 23.13 is withdrawn, and so is 23.14's "a floor, not a figure":
  there was no floor.
- **The `dir`/`xmit_type` reads are fixed, not just diagnosed.** `read_bits()`
  replaces the macro: same relocated offsets, same patched shift amounts, on a
  value masked to its low byte so the upper bits are provably zero rather than
  assumed to be. The macro reads `BYTE_SIZE` bytes into a `u64` and relies on
  the rest of that word still holding the zero it was initialised with, and
  `BYTE_SIZE` is patched from 8 down to 1 at load - so seven eighths of that
  word is whatever the previous packet left on the stack. Whether that is the
  mechanism is **not established** and is not asserted here; it is the only
  difference between the two versions, and one of them is right in every window
  and the other in none.
- **`FIELD_SIGNED` relocations are gone from the object**, because the macro was
  their only user. The object now carries 50 `FIELD_BYTE_OFFSET`, 4 `TYPE_SIZE`
  and 4 each of the shift and size relocations, and still no `TYPE_ID`.

#### Why there is a nat66 counter and no nat64 one

Raised as an observation and worth writing down, because the answer is not
obvious on a 464XLAT link and the asymmetry looks like an oversight.

**No NAT64 state exists in this kernel to count.** 464XLAT puts the two halves
of the translation at opposite ends of the path and neither end is this box:

- the **CLAT**, IPv4 to IPv6, is inside the RM520N modem - `wwan0` carries the
  RFC 7335 address `192.0.0.2/27` and Linux hands native IPv4 to `192.0.0.1`
- the **NAT64**, IPv6 back to IPv4, is in the carrier's network behind the
  synthesized prefix the DNS64 resolver hands out

So a flow in this flowtable is one of exactly two things: native IPv4, which
carries ordinary **NAT44** because the LAN prefix is translated to the
`192.0.0.2` CLAT address, or native IPv6, which on a routed prefix carries no
NAT at all. A NAT64 counter would be permanently zero for a reason that has
nothing to do with the program.

What the observation did expose is a real gap: **NAT44 was not counted either.**
`nat66` existed and its v4 counterpart did not, so the v4 path's translation -
the one that actually fires here - was invisible. Both are counted now.

The one case that would change this is moving the CLAT onto the router, with
OpenWrt's `464xlat` package and a `nat46` device. Then translated flows would
be in this flowtable and the program's assumptions about what a tuple means
would need re-reading. `boxstate.sh` already detects that device, which is why
it enumerates interfaces rather than listing them.

#### Where W0038 now stands

The lookup half is proven and reusable: 98.8% to 99.0% hit rate across every
window, both families, with `l3proto` and `iifidx` agreeing with the packet on
every single lookup. The redirect half has never fired and, on this box as
configured, cannot: `XMIT_DIRECT` needs either hardware offload on - which
empties the XDP hashtable and makes every lookup miss - or a forward-path walk
that lands on a device in the flowtable's own hook list.

**The bridge ports are in that list and it did not help.** `eth1`, `phy0-ap0`
and `phy1-ap0` were added live after 23.9 read them absent, the list read back
with all six devices, and every window since has still been 100% `XMIT_NEIGH`.
So the live addition is necessary-at-best, and why it is not sufficient is not
established. Two candidates, neither tested:

- `nft` adding a device to an **existing** flowtable may not register the hook
  that `nft_flowtable_find_dev()` searches at `nft_flow_offload.c:202`, in which
  case the walk still finds nothing to match and discards `XMIT_DIRECT`.
- The flows measured in those windows may have been matched against state built
  before the change. The forward path is computed once, at flow creation, so a
  flow created earlier keeps the decision made earlier.

The `fw4` template removes both doubts at once - the flowtable is created with
the ports in it, so no flow can predate them and no live `add` is involved. That
is the only live lead left, and it is a firewall4 change rather than anything in
this program.

> **Followed, and it worked - 23.17.** Creating the flowtable with the ports in
> it rather than adding them live moved a wired client from 0 to 100%
> `XMIT_DIRECT` on every flowtable hit. The redirect half of W0038 is real, and
> its scope is narrower than that number suggests. Both are in 23.17.

### 23.17 XMIT_DIRECT fires, and the bridge port decides it - 2026-09-14

**The redirect half of W0038 works.** 23.16 said it "has never fired and, on
this box as configured, cannot", and named the `fw4` template as the only live
lead. Following that lead settled it.

#### What changed

`nft delete flowtable inet fw4 ft` is refused with `Resource busy`: the forward
chain's `flow add @ft` rule holds a reference, and nft will not drop a flowtable
a rule points at. But `fw4 print`'s own output opens with

```
table inet fw4
flush table inet fw4
delete flowtable inet fw4 ft
```

so fw4 can do what a bare delete cannot - it flushes the table in the same
transaction, which drops the referencing rule first. Editing one line of that
generated ruleset and loading it back with `nft -f` creates the flowtable with
the three bridge ports already in it, atomically, with nothing written to disk.
`x3000/docs/flowtable-ports.sh` is that, with the guards.

#### The measurement

Five windows on 2026-09-14, all with the ports in the list. Every one closes its
accounting exactly - the exits sum to `seen`, and the byte histogram sums to
`hit`:

| # | client | port | mix | seen | hit | DIRECT |
|---|---|---|---|---|---|---|
| 1 | phone | Wi-Fi | 99% v6 | 250340 | 237646 | 2150 |
| 2 | phone | Wi-Fi | 99.9% v6 | 342956 | 342578 | 81 |
| 3 | PC | **wired** | 100% v4 | 251709 | 247820 | **247820 - all of them** |
| 4 | PC | Wi-Fi | 100% v4 | 356040 | 351416 | **0** |
| 5 | phone | Wi-Fi | 99.96% v6 | 358070 | 348233 | **0** |

Window 3 read `not_direct` **0**, and `b13` on every one of 247820 hits. That is
98.45% of all packets crossing `wwan0` in the window and 100% of the flows the
lookup found.

**Windows 3 and 4 are the controlled comparison, and they are the finding.**
Same PC, same IPv4-only stack, same kind of transfer, ~250k against ~356k
packets. The only variable is which bridge port the client sits on, and the
result goes 100% to 0%.

So the variable is the **port**, not the address family. Two hypotheses died
here: that the families behave differently, and that neighbour state at
`nft_flow_offload.c:73` explains it - the phone held three `REACHABLE` global v6
addresses going into window 5 and still produced nothing.

**Three windows were misread before the client was pinned down.** Windows 1 and
2 were phone speedtests, and both produced a small IPv4 `DIRECT` count I
attributed to the phone. It was the wired PC's background traffic in the same
window. Nothing in the counter dump says which client a flow belongs to, and I
did not check until `/proc/net/nf_conntrack` was read for the LAN-side source.
**A window that mixes clients cannot attribute a per-client result**, and this
one had two clients in it throughout.

#### Why the port decides it, read from source

`dev_fill_forward_path()` (`net/core/dev.c`) walks while a device has an
`ndo_fill_forward_path`, and **returns -1 the moment one of them errors**:

```c
while (ctx.dev && ctx.dev->netdev_ops->ndo_fill_forward_path) {
        ret = ctx.dev->netdev_ops->ndo_fill_forward_path(&ctx, path);
        if (ret < 0)
                return -1;
        ...
}
if (!ctx.dev)
        return ret;
path->type = DEV_PATH_ETHERNET;
path->dev = ctx.dev;
```

Only a device with **no** callback reaches that last branch - and
`DEV_PATH_ETHERNET` is the one case in `nft_dev_path_info()` that sets
`info->indev`, which is exactly what `nft_flowtable_find_dev()` then looks for.

- **`eth1` is a plain netdev with no `ndo_fill_forward_path`.** The walk falls
  through, `info->indev = eth1`, that device is now in the flowtable list, and
  `xmit_type` becomes `XMIT_DIRECT`. Window 3.
- **A Wi-Fi vif on the 802.3 data path has one.** `mac80211/iface.c:956`
  attaches `.ndo_fill_forward_path` to `ieee80211_dataif_8023_ops` and to no
  other ops struct; it delegates to the driver at `:942` and returns
  `-EOPNOTSUPP` at `:902` when the driver has none. mt76 has one, and at the
  pinned commit `39c960c3` it opens with `mt7915/main.c:1776`:

  ```c
  if (!mtk_wed_device_active(wed))
          return -ENODEV;
  ```

  WED is off on this box (section 11), so it fails, the walk returns -1,
  `nft_dev_path_info()` is never reached, `info.indev` stays NULL, and
  `nft_dev_forward_path()` returns before setting anything. Windows 4 and 5.

#### WED would not fix it, and that is the counterintuitive part

The obvious next move is W0032 - enable WED so the driver callback succeeds. It
does not help. With WED active the callback sets

```c
path->type = DEV_PATH_MTK_WDMA;
...
ctx->dev = NULL;
```

and `nft_dev_path_info()` has **no case for `DEV_PATH_MTK_WDMA`**. It handles
`DEV_PATH_ETHERNET`, `DSA`, `VLAN`, `PPPOE` and `BRIDGE`, and nothing else. So
`info->indev` stays NULL and the walk is discarded exactly as before.
`DEV_PATH_MTK_WDMA` exists for the PPE hardware-offload path, which is consumed
elsewhere. **W0032 is not a prerequisite for W0038 after all.**

What would work is the opposite of an optimisation. A Wi-Fi vif with **no**
`ndo_fill_forward_path` at all - 802.3 encap offload off, so the vif uses
`ieee80211_dataif_ops` rather than `ieee80211_dataif_8023_ops` - falls through to
the `DEV_PATH_ETHERNET` branch, and `phy0-ap0` is already in the flowtable list.
**Turning a hardware offload off is what would turn this software fast path on**
for Wi-Fi clients. That is reasoned from these four functions and untested;
there may be no runtime knob for it at all.

#### Version alignment, because half of this is not read against this tree

`mt76` was read at `39c960c3`, which is this tree's pinned commit, and
`nft_flow_offload.c` and `net/core/dev.c` at v6.12, which resolve as written.
**`mac80211` here is `backports-6.18.39`, not the kernel's own**, and `iface.c`
was read at v6.12 - so the `ieee80211_dataif_8023_ops` half is E2 against the
wrong tree until it is checked against backports.

#### Where W0038 stands now

- **The lookup half**: proven and reusable. 94.9% to 99.9% hit across every
  window, both families, with `l3proto` and `iifidx` agreeing with the packet on
  every single lookup.
- **The redirect half**: **works, for clients on a wired bridge port**, at 100%
  of flowtable hits and 98.45% of packets. For a client on a Wi-Fi port it
  cannot work in any configuration currently reachable here.
- **The rewrite itself has still never executed.** `would_redirect` counts flows
  where every check passed, not packets that were translated. The NAT, the
  checksum arithmetic, the L2 construction and the redirect have been through a
  compiler and a verifier and nothing else. A wrong checksum shows up as clients
  losing connectivity, so `probe` comes first and `off` stays to hand.
- **The change does not persist.** All of it lives in the running ruleset and
  dies on `fw4 restart` or a reboot. Making it survive is W0039, a firewall4
  patch of the same shape as `001-flowtable-fall-back-to-l3-device.patch`.
- **The payoff argument is unchanged, and still weak.** 14.3 and 18 say this box
  is not cycles-bound, the one poor number is latency, and a generic-mode
  redirect bypasses the qdisc (17.2). W0038 now optimises a resource the box has
  spare, for the wired half of its clients, at the cost of the resource it does
  not have. It works. That is not the same as being worth attaching.

### 23.18 Why a Wi-Fi client never reaches XMIT_DIRECT - 2026-09-14

23.17 measured that the bridge port decides it and proposed a mechanism. The
mechanism had a hole: it assumed the AP vifs use `ieee80211_dataif_8023_ops`,
and nothing had checked. If they used the plain ops there would be no callback
at all, the walk would fall through to `DEV_PATH_ETHERNET`, and Wi-Fi would have
worked - so the assumption was load-bearing and unverified. A second cause fit
the same symptoms just as well: if `br_fill_forward_path()` fails to resolve the
port from the bridge FDB, the walk dies at the bridge and mac80211 is never
reached.

Both are now settled, one by reading and one by prediction.

#### The vifs do use the 802.3 ops, by construction

`ieee80211_set_vif_encap_ops()` assigns `ieee80211_dataif_8023_ops` when encap
offload is enabled, and `ieee80211_set_sdata_offload_flags()` enables it unless
one of three things fails:

1. the driver does not set `SUPPORTS_TX_ENCAP_OFFLOAD`,
2. the driver lacks `SUPPORTS_TX_FRAG` while a fragmentation threshold is set,
3. `local->virt_monitors` is non-zero.

mt7915 sets **all three** relevant flags at `mt7915/init.c:410-414` -
`SUPPORTS_TX_ENCAP_OFFLOAD`, `SUPPORTS_RX_DECAP_OFFLOAD` and `SUPPORTS_TX_FRAG`.
That third one disarms disqualifier 2 outright, whatever the fragmentation
threshold is. With no monitor interface up, disqualifier 3 is inert too. So
encap offload is on, the vif carries `.ndo_fill_forward_path`, and the callback
is reached on every walk.

#### The prediction, and the window that confirmed it

Disqualifier 3 is a lever. `ieee80211_do_open()`'s `NL80211_IFTYPE_MONITOR` case
increments `virt_monitors` for any monitor that is not `MONITOR_FLAG_ACTIVE` on
any driver that does not set `NO_VIRTUAL_MONITOR` - mt7915 sets neither - and
calls `ieee80211_recalc_offload()` immediately after. So a plain monitor
interface should strip the callback from the AP netdev and make Wi-Fi clients
redirectable.

Measured, with the bridge ports in the flowtable and a monitor on each phy,
driven from the phone over IPv6 - the exact combination that had produced zero
three times:

| reading | value |
|---|---|
| `seen` | 154390 |
| `v6` | 154213 (99.9%) |
| `hit` | 153085 |
| `not_direct` | **0** |
| `would_redirect` | **153085 - every hit** |
| byte histogram | `b13` only; `b5` absent entirely |

20 + 63 + 1222 + 153085 = 154390, so the accounting closes exactly, and
`b13` equals `hit`. **0% to 100% on one variable.**

That confirms the chain end to end and kills the bridge-FDB alternative at the
same time: with the callback gone the walk runs straight through the bridge to
`DEV_PATH_ETHERNET`, so `br_fill_forward_path()` was resolving the Wi-Fi port
correctly all along. It also closes the version caveat 23.17 carried - the
prediction only holds if backports-6.18.39's `iface.c` behaves as v6.18's does,
and it did.

#### Whose defect this is

**Not OpenWrt.** The nineteen patches in `package/kernel/mac80211/patches/subsys`
are minstrel, DFS, AQL and MLO; none touches `iface.c` or the forward path. mt76
is pinned to an unmodified upstream commit.

**Not mt76.** `mt7915_net_fill_forward_path()` returns `-ENODEV` when WED is
inactive, which is the correct answer: it is asked to describe a hardware
forwarding path and there is not one. It writes nothing to `path` before
declining.

**Not mac80211.** It returns `-EOPNOTSUPP` at `iface.c:951` as its ordinary
"the driver does not implement this" answer, also before touching `path`.

**The kernel core.** `dev_fill_forward_path()` treats every callback error as
fatal to the whole walk:

```c
ret = ctx.dev->netdev_ops->ndo_fill_forward_path(&ctx, path);
if (ret < 0)
        return -1;
...
if (!ctx.dev)
        return ret;
path->type = DEV_PATH_ETHERNET;   /* reached only when NO callback exists */
```

A device with no callback gets `DEV_PATH_ETHERNET` and works. The same device
declining by return code kills the walk. Those two are the same statement, and
`-EOPNOTSUPP` in particular means exactly what a missing callback means. The
fix is three lines - W0040:

```c
ret = ctx.dev->netdev_ops->ndo_fill_forward_path(&ctx, path);
if (ret == -EOPNOTSUPP)
        break;                    /* no special path; use DEV_PATH_ETHERNET */
if (ret < 0)
        return -1;
```

This is worth posting upstream. It is not specific to this board: any bridged
Wi-Fi client on any driver without WED-equivalent support hits it, and the
symptom is silent - flow offload simply never reaches `XMIT_DIRECT` and nothing
reports why.

### 23.19 What disabling encap offload costs: nothing measurable - 2026-09-14

The monitor lever is a diagnostic, but it is also the only way to get Wi-Fi
coverage for W0038 without a kernel patch, so its cost matters. Before the
measurement I argued it would "plausibly cost more than an XDP redirect buys".
**That was wrong and is withdrawn.**

The test has to be LAN-side. A download over this WAN tops out near 280 Mbit/s,
far below the radio, so the Wi-Fi TX path would never be the bottleneck and
every condition would read the same. `wifiload.py` serves an endless stream from
the wired PC to a page on the phone that discards each chunk as it arrives -
no client storage, no restart gaps.

Conditions alternate under one continuous transfer rather than running one block
then the other, so client rate adaptation shows up as cycle-to-cycle spread
instead of as a fake result.

| cycle | ON Mbit/s | OFF Mbit/s | ON-OFF | ON ret/1k | OFF ret/1k |
|---|---|---|---|---|---|
| 1 | 989 | 956 | +33 | 10 | 13 |
| 2 | 980 | 976 | +4 | 10 | 10 |
| 3 | 589 | 607 | -18 | 15 | 15 |
| 4 | 942 | 1005 | -63 | 4 | 1 |

Means: ON 875, OFF 886. **The differences change sign** - +33, +4, -18, -63 -
and the largest is 63 against a within-condition spread of 400 (589 to 989 on ON
alone). The effect is well under the noise floor. Retries per 1000 frames are
identical at 9.75 either way, so throughput is not being propped up by
retransmissions. Both counters agree to within 1 Mbit/s and `time_squeeze`
stayed 0 throughout, so the router never became the bottleneck.

**Cycle 3 is the justification for the design.** Both conditions collapsed to
~600 together, which makes it external - interference, rate adaptation, thermal.
On a single before/after it would have landed inside one condition and read as a
real effect.

**The ceiling is the wire, and it bounds the claim.** The sustained rate sat at
~989 Mbit/s while the client negotiated 2401.9 Mbit/s, and `ethtool eth1` reports
**1000Mb/s**. The wired source was the limit, not the radio, so the honest
statement is **no measurable cost up to ~1 Gbit/s** - not "no cost at the radio's
limit". Above that, untested.

For the decision that bound does not bite: this WAN delivers around 280 Mbit/s,
so if software encap is free at 950 it is free by a wide margin at 280.

**What it changes.** Wi-Fi coverage for W0038 is available at no cost worth
measuring - but through W0040 rather than this lever, because the kernel fix
needs no encap sacrifice at all and survives a reboot. What it does not change
is whether W0038 is worth attaching: 14.3 and 18 still say this box is not
cycles-bound, 17.2 still says a generic-mode redirect bypasses the qdisc, and
latency is still the only poor number here.

### 23.20 Threaded NAPI took the WAN down, twice, and the mechanism is not established - 2026-09-14

**Do not run `gro-backlog-ab.sh --napi` or `--threaded`.** Both are gated behind
`NAPI_I_ACCEPT_A_REBOOT=1`. Two runs, two dead WANs, two reboots, and no
mechanism to show for it.

W0002 asks whether threading the gro_cells NAPI on `wwan0` reduces latency under
load. The test toggles `/sys/class/net/wwan0/threaded` and measures throughput,
`rx_dropped` and rtt in alternating windows.

#### What reproduced (E1, twice)

Both runs behave identically in the four ways that matter:

1. The downlink stops within seconds of the first write to `threaded`.
2. Setting `threaded` back to 0 does not bring it back.
3. The box needs a reboot. Nothing short of one was tried in run 1; run 2 was
   rebooted before the ladder ran.
4. `logread` carries nothing about it in either run - no warning, no reset, no
   MHI message. The kernel is silent while the link is dead.

Run 1, all six windows:

| window | throughput | rx_dropped | rtt |
|---|---|---|---|
| softirq #1 | 157.2 Mbit/s, 14069 dgram/s | 0 | 32.2 / 50.2 / 107.8 ms |
| thread #1 | 0.0 | 88 | n/a |
| thread-pin #1 | 0.0 | 50 | 100% loss |
| softirq #2 | 0.0 | 78 | 100% loss |
| thread #2 | 0.0 | 48 | 100% loss |
| thread-pin #2 | 0.0 | 44 | 100% loss |

Run 2, the part that survived: `rx_dropped` read 0, 0, 27, 52, 52 across the
dead windows, modem delivery fell to 5-7 datagrams per second, and both NAPI
kthreads were found on CPU 1. The full window table was not kept off the box
before the reboot; only these figures are recorded, and I am not reconstructing
the rest.

`softirq #2` in run 1 remains the important row: `threaded` was back at 0 and
the link was still dead. Whatever breaks is not the mode.

#### Retraction: the gro_cells backlog wedge

The previous revision of this section named a mechanism: `gro_cells_receive()`
schedules its NAPI only on the 0-to-1 queue transition, so a single missed poll
never re-arms, the queue passes `max_backlog`, and every later packet is dropped
at `dev_core_stats_rx_dropped_inc()`. **That reading is withdrawn.** The source
reading is correct - the edge-triggered re-arm is real, at
`net/core/gro_cells.c:32` - but it does not fit the counters.

The arithmetic kills it. Run 1's live window carried 14069 datagrams per second.
If the queue were full and discarding a stream still arriving at that rate,
`rx_dropped` would climb by roughly fourteen thousand per second - order 170,000
across a twelve-second window. It moved by 88. Run 2 moved it by 0 across the
first two dead windows. Both are three to four orders of magnitude below what
the mechanism predicts. A counter ticking at five to seven per second is a
trickle arriving at a host with nowhere to put it, not a full queue shedding a
live stream.

The same arithmetic removes the argument I built on top of it. I wrote that
`rx_dropped` moving proved the radio was still up, because a dead modem delivers
nothing to drop. Run 2 recorded 0 in two dead windows, which is exactly what a
modem delivering nothing looks like. **That argument is withdrawn too.** Nothing
in either run distinguishes a host-side stall from a modem-side one.

This is the second mechanism I have proposed and withdrawn for this failure. The
first was that `dev_set_threaded()` disables and re-enables NAPI; it does
neither - it creates the kthreads, writes `dev->threaded`, and flips
`NAPI_STATE_THREADED` on each instance, carrying an upstream comment that the
switch "should not cause hiccups/stalls to the live traffic". Two withdrawn
explanations for one unexplained failure is a signal to stop proposing them.

#### The confound that invalidates both runs: irqbalance was running

`irqbalance` was active for the whole of both runs. It moves IRQ affinity masks
on its own schedule, and the entire subject of W0002 is which CPU the receive
work lands on. Neither run measured a controlled configuration.

This is my error, and a specific one rather than an oversight. The script's
preflight warns about irqbalance; the revision that actually stops it - and
restores it afterwards - exists, is 22024 bytes, and was written at 21:52 UTC on
2026-09-14. It never reached the box. The copy in the tree and the copy served
from GitHub are both 20627 bytes and contain the string `irqbalance` zero times.
I had already been told irqbalance was on, acknowledged it, put the fix in a file
that did not ship, and then ran the test twice.

Run 2 found both NAPI kthreads on CPU 1. Whether the script's own pinning put
them there or irqbalance did is not determinable after the fact, which is what
an uncontrolled variable costs.

#### A separate correction: the tree was not stale, my commit was wrong

I attributed the missing script revision to GitHub's CDN serving a cached copy,
and then to `curl`'s quiet flags. **Both were wrong.** Measured 2026-09-14
22:10 UTC: the bytes GitHub serves for `gro-backlog-ab.sh` and the bytes on disk
in the checkout have the same length and the same MD5. GitHub publishes exactly
what is committed to it; the commit carried the wrong content. `curl -fsSL` has
nothing to do with it either - `-s` suppresses the progress meter and `-f` makes
an HTTP error a non-zero exit instead of a saved error page, and neither touches
caching.

The failure signature worth remembering: the file on disk carries an mtime of
21:52:12 UTC, the newest of the fourteen files in that directory, while holding
the older content. A write landed and wrote stale bytes. The remaining thirteen
files match my working copies byte for byte, so this was one bad commit rather
than a broken pipeline.

**A commit is not verified until the bytes on disk are read back and hashed.**
Size alone was what I checked before, and size alone is what let this through.

#### What is NOT established

Where the downlink stops. The candidates are a host-side stall in the receive
path, something in the MHI or modem path, and the radio itself. Nothing measured
separates them:

- The kernel logs nothing in either run, so no host-side fault announced itself.
- `rx_dropped` is too small in both runs to identify a queue overflow, and reads
  0 in run 2's first dead windows.
- Nothing sampled the radio during a failure window. A reading taken after run
  1's reboot showed `rsrp=-107 dBm`, one bar. That describes the radio in
  general, **not** the failure, and it is context rather than evidence.

The correlation with the `threaded` write is strong - twice, within seconds,
from a healthy 157 Mbit/s - and the lack of recovery on `threaded=0` says the
write is a trigger rather than a state. That is as far as the evidence goes.

#### What would settle it, at what cost

**Superseded by 23.21 as far as running it again goes.** The source says
threaded NAPI on a gro_cells device is unsafe by construction, so none of the
steps below is worth a third reboot. They are kept because they describe what
this section would have needed, and because step 2 is still worth doing for the
993 stall on its own account.

Ordered by what each costs to run:

1. **Toggle `threaded` on an idle link, with irqbalance stopped, capturing
   `logread -f` to a file throughout.** If the link dies with no traffic in
   flight, the load is not involved and the trigger is the write itself. This is
   the cheapest discriminator and it is what the 22024-byte revision does.
2. **Sample the modem during the failure** - `dlwatch` is already in the image at
   `/usr/bin/dlwatch` and `kptr_restrict=1` ships, so the `dl_qd` / `dl_free`
   ring state is readable. `dl_qd=127` with `dl_free=0` is the host-not-draining
   signature `downlink-stall.md` records; healthy ring counters with no traffic
   points the other way, at the modem or the radio.
3. **Sample `rsrp` inside the failure window**, not after the reboot, to retire
   the radio as a candidate rather than arguing about it.

W0002 has no measurement and this section has no mechanism. 23.21 explains why
it is not going to get either: the configuration under test is racy by
construction, so there is no correct number hiding behind these two failures.

#### What this changes

- **W0002 is unmeasured, and both attempts at measuring it were invalid.** Not
  inconclusive - invalid, because irqbalance was moving the variable under test.
- **The cost of the next attempt is a reboot of the house router**, so it is
  worth running only with the logging and the idle-link staging in place.
- **The pre-existing `--threaded` mode's warning was probably wrong.** It said
  the throughput collapse it produced was the on-box `curl` starving the NAPI
  kthread of CPU. The same collapse happened twice with nothing competing on the
  box. A symptom attributed to contention may have been this all along.
- **The link to the 993 downlink stall is now a question, not a claim.** I wrote
  that a wedged gro_cells queue stops draining, the MHI ring fills, and the modem
  stalls - the `dl_qd=127` / `dl_free=0` signature. With the wedge withdrawn,
  what remains is that both failures look like a downlink that stops while the
  box stays up. Whether they share a cause is untested, and step 2 above is the
  cheap way to find out.

### 23.21 Threaded NAPI cannot be safe on `wwan0`: gro_cells has no lock - 2026-09-14

W0002 is not a tuning knob with an unmeasured cost. On a gro_cells device it is
an **unsafe configuration**, and that is readable in source without running
anything. This section supersedes 23.20's "cause not established" on the
question of whether to try again: the answer is no, and the reason does not
depend on either failed run.

#### First, the provenance: `wwan0` is a gro_cells device because 991 is mine

Stock `mhi_wwan_mbim` is not a gro_cells driver and has no NAPI at all. At
`v6.12.103` the entire receive delivery path is one call - `netif_rx()` at
`drivers/net/wwan/mhi_wwan_mbim.c:348` - and the file contains zero occurrences
of `napi` or `gro`. On a stock kernel `/sys/class/net/wwan0/threaded` is
therefore **inert**: `dev_set_threaded()` walks an empty `dev->napi_list`,
creates no kthreads, and sets a flag nothing reads.

`991-net-wwan-mhi_wwan_mbim-gro-cells-rx.patch` in this tree is what put per-CPU
gro_cells NAPIs on that netdev, and it is my patch. Its own commit message named
"a working `/sys/class/net/<dev>/threaded` toggle" as a side benefit of the
switch. **That line was wrong** and has been removed: the toggle it enabled is
the one behaviour change 991 makes that is not an improvement. 991 now carries
the hazard in its message instead.

So the ordering is: 991 moved `wwan0` into the gro_cells class, the class has an
upstream defect, and W0002 walked into it. The defect is not 991's to fix, but
it was 991's to disclose.

The upstream users of `gro_cells` at `v6.12.103` are `amt`, `bareudp`,
`geneve`, `macsec`, `pfcp`, `vxlan`, `ip_tunnel` and
`rmnet_vnd` - the last of which is Qualcomm's own modem netdev, so the hazard
reaches shipping modem hardware without anyone applying a local patch first.

#### What gro_cells relies on, at 6.12.103

`net/core/gro_cells.c` in the kernel this box runs has **no lock of any kind**:

| line | what happens |
|---|---|
| `:28` | `cell = this_cpu_ptr(gcells->cells)` - the producer always takes the running CPU's cell |
| `:30` | `skb_queue_len(&cell->napi_skbs) > max_backlog` - unlocked read |
| `:38` | `__skb_queue_tail(&cell->napi_skbs, skb)` - the **unlocked** enqueue, not `skb_queue_tail()` |
| `:39` | `if (skb_queue_len(...) == 1) napi_schedule(...)` - the edge-triggered re-arm |
| `:50` | `/* called under BH context */` - the contract, written as a comment |
| `:58` | `skb = __skb_dequeue(&cell->napi_skbs)` - the **unlocked** dequeue |

The `__` variants do not take `napi_skbs.lock`. So the entire mutual exclusion
between producer and consumer is: **both run on the same CPU with BH disabled.**
Per-CPU data plus BH-disable is the lock.

This is not my reading imposed on the code. Upstream states it directly in
commit `25718fdcbdd2` ("net: gro_cells: Use nested-BH locking for gro_cell",
Sebastian Andrzej Siewior, first in **v6.18**):

> The gro_cell data structure is per-CPU variable and relies on disabled BH for
> its locking. [...] This change adds only lockdep coverage and does not alter
> the functional behaviour for !PREEMPT_RT.

Two things follow. The invariant is confirmed by the maintainer who touched it
most recently. And the `local_lock_t` that v6.18 adds is a **PREEMPT_RT and
lockdep change only** - it is explicitly a no-op for a non-RT build like this
one, so backporting it would fix nothing here.

The lock was not always absent. `f8e8f97c11d5` (Eric Dumazet, 2013) added a
`spin_lock` to `gro_cell_poll()` for a different race, and its reasoning was the
same invariant: plain `spin_lock` sufficed "since both producer and consumer run
in Bottom-Half context". That lock is gone and the invariant is all that is left.

#### What `threaded` does to that invariant

`gro_cells_init()` at `:78` walks `for_each_possible_cpu` and at `:85` calls
`netif_napi_add(dev, &cell->napi, gro_cell_poll)` on the **real** netdev. So the
per-CPU gro_cells NAPIs sit on `wwan0`'s own `dev->napi_list`, alongside anything
the driver registered. Two possible CPUs on this SoC means two of them.

Then, in `net/core/dev.c`:

- `:6688` `dev_set_threaded()` iterates **every** entry on `dev->napi_list` and
  creates a kthread for each. There is no filter - not for
  `NAPI_STATE_NO_BUSY_POLL`, not for gro_cells, not for anything.
- `:1508` `napi_kthread_create()` calls plain `kthread_run()`. **Unbound.** The
  only CPU-bound NAPI thread anywhere in that file is the backlog NAPI at
  `:12287`, which is a different mechanism and does not apply here.
- `:7009` the thread calls `local_bh_disable()`, and `:7012` takes
  `this_cpu_ptr(&softnet_data)` - BH is disabled on whatever CPU the scheduler
  put the thread on, which has nothing to do with which cell it is draining.

So CPU 0's gro_cell can be drained by a kthread running on CPU 1 while
`gro_cells_receive()` on CPU 0 is enqueueing into it. That is an unlocked
`__skb_queue_tail()` racing an unlocked `__skb_dequeue()` on the same
`sk_buff_head` from two cores. The SCHED bit serialises pollers against each
other; it does not serialise the poller against the producer, because the
producer never takes it.

**Evidence grade: E2.** Every line above was read in the tree this build ships,
`v6.12.103`, not inferred from a counter.

*Four line numbers in this section were off by one and were corrected on
2026-09-15; see 23.28 for the list. The argument is unaffected.*

#### Two objections worth closing, because both sound reasonable

**"gro_cells NAPIs are dummies - surely `threaded` skips them."** It does not.
`dev_set_threaded()` (`dev.c:6688`) iterates `dev->napi_list` with no filter of
any kind and calls `napi_kthread_create()` for every entry that lacks a thread.
gro_cells puts its NAPIs on that exact list with `netif_napi_add(dev, ...)`
(`gro_cells.c:85` at 6.12.103, `:96` at master). So one kthread is created per
possible CPU. **This is not only a source reading: run 2 observed exactly two
kthreads on this two-CPU board**, which is what one-per-possible-CPU predicts.

**"`napi_schedule()` from `gro_cells_receive()` will just fall back to softirq
or ksoftirqd."** It will not, once the bit is set. `____napi_schedule()` at
`dev.c:4637`:

```c
if (test_bit(NAPI_STATE_THREADED, &napi->state)) {
        thread = READ_ONCE(napi->thread);
        if (thread) {
                if (use_backlog_threads() && thread == raw_cpu_read(backlog_napi))
                        goto use_local_napi;
                set_bit(NAPI_STATE_SCHED_THREADED, &napi->state);
                wake_up_process(thread);
                return;
        }
}
use_local_napi:
        list_add_tail(&napi->poll_list, &sd->poll_list);
```

The threaded arm **returns**. It never reaches `sd->poll_list`, so the work never
goes near a softirq or `ksoftirqd`. The single carve-out at `:4653` is for the
backlog NAPI - the one per-CPU NAPI the kernel does bind to its CPU - which is
the same asymmetry W0041 is about, showing up again in a second place.

#### How this sits against the two outages

It fits, and I am **not** grading that fit above E3. What the race would produce
is a list whose linkage or `qlen` no longer agree:

- **Silent.** No `WARN`, no `pr_err`, nothing to log. Both runs: `logread` empty.
- **Permanent.** If `qlen` stops passing through 1, the `:39` re-arm edge never
  recurs, and writing `threaded=0` cannot repair a corrupted list. Both runs: no
  recovery from `threaded=0`, reboot required.
- **`rx_dropped` either way.** Whether the corrupted `qlen` lands above or below
  `max_backlog` decides whether drops are counted at all. Under 23.20's overflow
  reading, run 1's 88 and run 2's 0 contradicted each other. Under corruption
  they are just two different corrupt states, and neither is informative.

One observation from run 2 looked like more than the rest: **two kthreads, both
on CPU 1.** Two possible CPUs give two gro_cells NAPIs and therefore two
kthreads, which matches - and both on CPU 1 would mean CPU 0's cell was being
consumed from CPU 1.

The reading depends on datagrams being in the cells at all, which 23.22 first
denied and then confirmed: `dev_xdp_mode()` (`dev.c:9444`) resolves to DRV
whenever the driver owns `ndo_bpf`, 992 does, and a DRV-mode program leaves
`dev->xdp_prog` NULL. So GRO was live and the cells were in the path on the
shipped image either way. The kthread placement is consistent with the race
without establishing it - which is what it was worth all along.

It also lines up with the box's IRQ placement, which was measured separately.
Every MHI interrupt lands on CPU 0 here regardless of the affinity mask, so
`gro_cells_receive()` runs on CPU 0 and enqueues into CPU 0's cell. The wake
comes from `____napi_schedule()` on CPU 0 via `wake_up_process()`, and a wake
issued from a CPU that is saturated with receive work is exactly the case where
the scheduler places the woken task on the *other* core. On a two-core box that
makes the cross-CPU drain the likely outcome rather than the unlucky one.

**The scheduler half of that is E3 - reasoning, not a trace.** The two facts it
sits between are E1: the MHI IRQ lands on CPU 0, and both kthreads were observed
on CPU 1.

#### Against the documented framing

The NAPI documentation describes threaded NAPI as changing only the execution
context: the same poll loop, run in a kthread instead of a softirq. For a driver
NAPI that is a fair summary - the work is the same and it stays attached to the
same hardware queue.

For gro_cells it understates the change, because "context" there includes
**which CPU**. A driver's NAPI protects its ring with the NAPI SCHED bit and its
own locking, so moving the poll to another core is a scheduling decision. A
gro_cell has neither: its queue is per-CPU and its primitives are the unlocked
`__skb_*` ones, and the SCHED bit serialises pollers against each other without
ever serialising a poller against the producer. gro_cells is the one NAPI user
for which "same loop, different context" is not a safe restatement, and that is
precisely where this lands.

#### Why no harness can make the toggle safe

Pinning the kthreads afterwards does not close the hole. `dev_set_threaded()`
creates each thread with `kthread_run()`, which **starts it immediately**, and
sets `NAPI_STATE_THREADED` a few lines later at `:6722`. Between those two
points no userspace `taskset` has run yet, and traffic arriving in that window is
already being handed to an unbound thread. Both failures happened within seconds
of the write, which is what that window looks like.

An idle-link toggle narrows the window but does not remove it, and "narrower"
is not a property worth another reboot of the house router.

#### What this changes

- **W0002 is retired as a workaround**, not deferred. There is nothing to
  measure: the configuration is unsafe by construction on this interface, so a
  latency number obtained from it would not be a number worth having.
- **23.20's "cause not established" stands for the outages themselves.** This
  section does not close that; it removes the reason to reopen it.
- **W0041 is the fix**, and it is upstream-shaped rather than local. Two forms:

  1. Bind each gro_cells NAPI kthread to the CPU whose cell it serves. Preserves
     the feature and restores the invariant exactly.
  2. Have gro_cells opt its NAPIs out of threaded mode, so writing `threaded=1`
     on such a device threads only the driver's own NAPI.

  Form 1 is the better fix if threaded gro_cells is wanted at all; form 2 is
  smaller and is what I would send first, because it cannot regress anything
  that works today.

- **991 is amended, not withdrawn.** The GRO batching it buys is the thing it
  was written for and none of that is in question. What changed is that its
  commit message no longer advertises a toggle that is unsafe on the class it
  moves the netdev into, and now warns instead.

- **The defect is not specific to this box, and not specific to 991.** Every
  upstream gro_cells user - `amt`, `bareudp`, `geneve`, `macsec`, `pfcp`,
  `vxlan`, `ip_tunnel`, `rmnet_vnd` - exposes a writable `threaded` in sysfs and
  has the same exposure on any non-RT kernel. `rmnet_vnd` matters most for the
  report: it is a modem netdev in mainline, so the bug is reachable on stock
  hardware by writing one sysfs file. That makes W0041 reportable on its own
  merits, and the GL-X3000 is the reproducer rather than the subject.

### 23.22 How GRO is actually handled on the WAN, and why my instrument could not see it - 2026-09-14

I had not checked this. 23.21 reasons about what happens once a datagram is in a
gro_cell without ever establishing that datagrams on this box reach one. They
often do not, the condition that stops them is one this tree creates on purpose,
and the reader I was using to watch it is blind to that condition.

#### The predicate

`gro_cells_receive()` does not always use its cells. At `gro_cells.c:23`:

```c
if (!gcells->cells || skb_cloned(skb) || netif_elide_gro(dev)) {
        res = netif_rx(skb);
        goto unlock;
}
```

and `netif_elide_gro()`, at `include/linux/netdevice.h:2423`, is:

```c
if (!(dev->features & NETIF_F_GRO) || dev->xdp_prog)
        return true;
```

`dev->xdp_prog` is written in exactly one place - `generic_xdp_install()` at
`net/core/dev.c:5944` - so it means **a program attached in skb mode**. Native
XDP is held by the driver and does not set it.

So on `wwan0` there are two ways for a datagram to miss the gro_cells path
entirely, and the second one is invisible to `ethtool`.

#### What that means for 991

**A generic-mode XDP program on `wwan0` does not reduce GRO. It turns 991 off.**
Every datagram goes to `netif_rx()`, which is the exact call 991 replaced. The
per-CPU cells sit allocated and empty, the NAPIs stay on `dev->napi_list`, and
the WAN runs its pre-991 receive path while `ethtool -k wwan0` still reports
`generic-receive-offload: on`.

The capability grid already carried this as "GSK01 costs GRO+991", so the
interaction was known. What was missing is that nothing on this box ever checked
which mode was live.

#### Two places that could not tell, including mine

**`bs_gro()` reads the wrong half of the predicate.** It runs `ethtool -k` and
takes `generic-receive-offload:`. That is `dev->features & NETIF_F_GRO` and
nothing else. It cannot see `dev->xdp_prog`, so it prints `on` while GRO is
elided. Both W0002 runs printed that value in their opening line, and I read it
as confirmation that GRO was in the path.

**`xdp-ft-wwan.sh` does not record which mode it got.** It attaches at `:240`
with

```sh
"$IP" link set dev "$IFACE" xdp pinned "$PINDIR/$PROGNAME"
```

Plain `xdp` is best-effort: native where the driver has an `ndo_bpf`, generic
otherwise. Its verify at `:191` and `:249` then greps for `prog/xdp` - and
iproute2 renders the skb attachment as `prog/xdpgeneric`, which that pattern also
matches. Its own teardown at `:577`-`:578` clears both spellings, under a comment
saying "a program attached in skb mode is not cleared by `xdp off`". The script
knows the ambiguity exists at the end and never resolves it at the start.

#### What this does to 23.21: nothing, and I said otherwise

The first revision of this section claimed the elision undermined 23.21's
corroboration - that if a generic-mode program had been attached during the
W0002 runs, no datagram reached a cell and the race could not have fired.
**That was an over-correction, and 992 is why.**

`dev_xdp_mode()` at `net/core/dev.c:9444` is not a fallback. It is a capability
check with no retry:

```c
if (flags & XDP_FLAGS_HW_MODE)  return XDP_MODE_HW;
if (flags & XDP_FLAGS_DRV_MODE) return XDP_MODE_DRV;
if (flags & XDP_FLAGS_SKB_MODE) return XDP_MODE_SKB;
return dev->netdev_ops->ndo_bpf ? XDP_MODE_DRV : XDP_MODE_SKB;
```

992 implements `ndo_bpf`, so on the shipped image a bare `ip link set dev wwan0
xdp ...` resolves to **DRV**, the program lands on `link->xdp_prog`, and
`dev->xdp_prog` stays NULL. GRO is not elided. 992's own commit message says
this, cites `dev_xdp_mode()` by name, and gives it as the reason for owning
`ndo_bpf` at all. I rediscovered a hazard that patch had already closed and then
wrote it up as though it were open.

So on the shipped build (`990/991/992/993/995`) there are two possibilities for
the W0002 runs - no program attached, or a DRV-mode one - and `dev->xdp_prog` is
NULL in both. The cells were in the path. **23.21's run-2 corroboration is
restored**, at the strength it originally had: consistent with the race, not
proof of it.

What survives from this section is narrower and still worth having: the elision
is reachable by an explicit `xdpgeneric`, and on any build without 992 it is the
default. The instruments could not see either case, which is the part that
needed fixing.

#### The fix, in the durable tool

`boxstate.sh` goes to API 3 and gains two readers; all five callers were bumped
in the same pass.

- **`bs_xdp_mode <dev>`** returns `none`, `native`, `generic` or `offload`. The
  cases are ordered longest-spelling-first, because a `case` glob has no word
  boundary and `*prog/xdp*` would otherwise swallow `prog/xdpgeneric`. It goes
  through `bs_pick_ip` rather than a bare `ip`: busybox's applet does not
  understand xdp and prints nothing about it, so a bare call would report `none`
  for a device that has a program attached - the exact bug `bs_pick_ip` was
  written to kill, which I reintroduced in the first draft of this function and
  caught on re-read.
- **`bs_gro_effective <dev>`** evaluates the real predicate and returns `on`,
  `off (feature bit ...)`, `off (elided by generic XDP)`, or an explicit
  `unknown` when `ethtool` or an xdp-capable `ip` is missing. Absent tooling
  reports as unknown rather than off, which is the same distinction this function
  exists to make.

`gro-backlog-ab.sh` now opens and closes with `gro=$(bs_gro_effective ...)` and
`xdp=$(bs_xdp_mode ...)` instead of the feature bit.

#### A better argument for W0041, found on the way

The elided path is the safe one. `netif_rx()` delivers to the per-CPU backlog,
and the backlog NAPI's kthread **is** bound to its CPU: `backlog_napi_setup()`
at `net/core/dev.c:12287` does `napi->thread = this_cpu_read(backlog_napi)`,
where `backlog_napi` is an `smp_hotplug_thread` with `thread_comm
"backlog_napi/%u"` - one thread per CPU, bound by the hotplug machinery.

**The kernel already does exactly what W0041 asks, for its own per-CPU NAPI.**
That is the strongest available argument that gro_cells' unbound threads are an
oversight rather than a design decision, and it is what the upstream posting
should lead with: not "here is a race", but "the one other per-CPU NAPI in the
tree is CPU-bound, and this one was missed."

### 23.23 gro_cells is the wrong abstraction for this driver, and what to do about it - 2026-09-14

The question is whether 991 can be made to work correctly threaded as well as
unthreaded. It can, but not by fixing how it uses gro_cells. **It uses gro_cells
correctly. gro_cells is the wrong tool for a driver shaped like this one**, and
replacing it with a single driver-owned NAPI fixes threading by construction and
drops the dependency on W0041 landing upstream.

#### One producer CPU, `nr_cpu_ids` cells

gro_cells splits a queue per CPU because its intended users cannot predict which
CPU a packet will arrive on. vxlan, geneve, IPsec and `ip_tunnel` all receive
from *some other device's* NAPI - whichever hardware queue of the underlying NIC
got the frame - so the producer CPU varies per packet and per-CPU cells are what
keep those producers off each other.

`mhi_wwan_mbim` is not shaped like that. The chain is fixed at every link:

- MHI dispatches downlink work with `tasklet_schedule(&mhi_event->task)` -
  `drivers/bus/mhi/host/main.c:475` - one tasklet per event ring, and this link
  has one event ring.
- `__tasklet_schedule_common()` at `kernel/softirq.c:744` enqueues onto
  `this_cpu_ptr(headp)` and calls `raise_softirq_irqoff()`, so the tasklet runs
  on the CPU that scheduled it, which is the CPU that took the MHI interrupt.
- Every MHI interrupt on this board lands on **CPU 0**, measured, regardless of
  the `smp_affinity` mask - the `MSI_FLAG_NO_AFFINITY` behaviour W0001 rests on.

So `gro_cells_init()` allocates one cell per possible CPU and exactly one of them
is ever used. The second cell on this dual-core SoC has never held a packet.

What the unused half costs is not memory. It is that `gro_cells_init()` puts a
NAPI per possible CPU onto `dev->napi_list` (`gro_cells.c:78`, `:85`), and those
extra NAPIs are the entire reason `/sys/class/net/wwan0/threaded` is unsafe:
`dev_set_threaded()` threads all of them with unbound kthreads, and the cells
they drain are per-CPU and lockless. 991 pays the hazard of a per-CPU design for
a workload with one producer CPU.

#### What gro_cells does not do, since the opposite is widely believed

A confident account of this architecture reached me on 2026-09-14 claiming that
gro_cells "uses a hashing or steering mechanism to instantly distribute these
SKBs across the system's per-CPU software queues", and that threading `wwan0`
moves the MBIM de-aggregation into the kthread. Both are false here, and if
either were true the section above would be wrong - so they are worth nailing
down rather than waving away.

**gro_cells performs no steering of any kind.** The only CPU selection in its
receive path is `gro_cells.c:28`:

```c
cell = this_cpu_ptr(gcells->cells);
```

The other two per-CPU references in the file, `:78` and `:113`, are
`gro_cells_init()` and `gro_cells_destroy()` walking every cell to create and
tear them down. There is no hash, no `get_rps_cpu()`, no `smp_processor_id()`
arithmetic, nothing that could place a packet on another CPU's queue. "Per-CPU"
in gro_cells means *producers on different CPUs do not contend with each other*.
It does not mean work is spread. Every packet arriving on CPU 0 queues to CPU 0's
cell and is polled on CPU 0.

**The MBIM unpacking is not in a NAPI poll, and threading cannot move it.**
`napi_struct` appears **zero** times in `drivers/net/wwan/mhi_wwan_mbim.c` and
zero times in `drivers/net/mhi_net.c`; there is no custom poll function in either.
De-aggregation is `mhi_mbim_rx()` at `:255`, called from `:456` inside
`mhi_mbim_dl_callback()` at `:423`, which is registered as `.dl_xfer_cb` at
`:658` and runs in MHI's tasklet. Writing 1 to `threaded` threads the gro_cells
polls, which sit *downstream* of the unpacking. The unpacking stays exactly where
it was, on the CPU that took the interrupt.

**What actually spreads receive work across cores here is RPS.**
`get_rps_cpu()` is called from `netif_rx_internal()` (`net/core/dev.c:5313`) and
from `netif_receive_skb_list_internal()` (`:6019`). GRO's completed output
flushes into the latter at `:6081`, so RPS applies *after* GRO merging on the
gro_cells path, and directly on the `netif_rx()` path. This box already runs it:
`packet_steering=2` with every interface at `rps_cpus 3`.

So the ledger for 991 is smaller than the story suggests, and still worth having:
**gro_cells buys exactly one thing, a NAPI context in which `napi_gro_receive()`
is legal for a driver that owns no NAPI.** Stock had no GRO at all. The
distribution, the parallelism and the threaded unpacking are not happening.

The account is not nonsense - it is an accurate description of a different
machine. A tunnel riding a multiqueue NIC, or rmnet on a host with several
receive queues, genuinely does have a varying producer CPU, and there the
per-CPU cells do exactly the job described. The error is transplanting that onto
a single-event-ring MHI link whose producer never varies.

#### The replacement: one driver-owned NAPI

This is the shape every ordinary driver uses, and it is what 991 should have
done:

- `netif_napi_add(ndev, &link->napi, mhi_mbim_poll)` and `napi_enable()` in
  `ndo_init`, where `gro_cells_init()` is today; `napi_disable()` and
  `netif_napi_del()` in `ndo_uninit`, where `gro_cells_destroy()` is. 991 already
  got that lifetime pairing right and the reasoning carries over unchanged.
- A driver-owned `struct sk_buff_head` drained by the poll, enqueued with the
  **locked** `skb_queue_tail()` and dequeued with `skb_dequeue()` - not the `__`
  variants. Producer and consumer may legitimately be on different CPUs once the
  poll can run in a kthread, so the queue has to carry its own lock. This is
  exactly what `f8e8f97c11d5` (Dumazet, 2013) had in gro_cells before the lock
  was dropped.
- The DL callback de-aggregates as it does now, queues each datagram, and calls
  `napi_schedule(&link->napi)` **unconditionally** rather than on a queue-length
  edge. The 0-to-1 re-arm in `gro_cells_receive()` is the design detail that
  makes a single missed poll permanent; `napi_schedule()` is idempotent through
  `napi_schedule_prep()`, so calling it every time is both correct and cheap.
- `mhi_mbim_poll()` drains up to `budget` with `napi_gro_receive()` - the same
  call `gro_cell_poll()` makes, so GRO itself is unchanged - then
  `napi_complete_done()`.

#### What that buys

- **Threaded NAPI becomes correct by construction.** One NAPI is serialised
  against itself by the SCHED bit, the queue carries its own lock, and the
  kthread may run anywhere. W0002 becomes measurable rather than destructive, and
  W0001 becomes meaningful.
- **No dependency on W0041.** That patch stays worth posting for the eight
  upstream gro_cells users, but this tree stops waiting on it.
- **Fewer NAPIs**: one per link instead of one per possible CPU.
- **Better degradation under generic XDP.** Today a skb-mode attach sends every
  datagram to `netif_rx()`, which is the whole pre-991 path. With a driver NAPI,
  `napi_gro_receive()` still runs and only the merging is skipped, because
  `netif_elide_gro()` is tested inside `dev_gro_receive()` at `gro.c:488` rather
  than at the delivery call. The `ethtool -K wwan0 gro off` kill switch keeps
  working through the same test.
- **992 is barely touched.** It hooks `mhi_mbim_rx()` before delivery; only the
  final `gro_cells_receive()` call becomes a queue-and-schedule.

#### What it costs, stated before it is measured

A spinlock per datagram on enqueue. `skb_queue_tail()` takes `list->lock` with
interrupts saved, and at roughly 21 datagrams per 32KB NTB that is 21
uncontended lock round-trips per transfer where there are currently none. I
expect that to be lost in the noise on a path that currently walks
conntrack per datagram, but **that is a prediction and it has not been
measured.** The A/B is the same rig 23.19 used.

If it does show, the next step is a `ptr_ring` rather than an `sk_buff_head` -
what `tun.c` does for the same reason - at the cost of a fixed ring size that
has to be chosen and a good deal more code.

#### The tier above, named but not recommended

The full conversion is to make the MHI event ring itself the NAPI: disable the
event tasklet while the poll runs and process completions from `mhi_mbim_poll()`
under a real budget. That is what would deliver IRQ coalescing,
`napi_defer_hard_irqs` and `gro_flush_timeout` - the knobs that would actually
move the latency number this box is short on.

It is not the next step, because the MHI core does not export the hooks for it.
`main.c:475` schedules the tasklet unconditionally and there is no
poll-or-disable interface for an event ring; `mhi_poll_reg_field()` is a
register-polling helper and unrelated. Getting there means changing
`drivers/bus/mhi/host`, which is a much larger upstream conversation than a
driver-local NAPI, and it should not be started before the driver-local version
has shown what the ceiling is.

#### Where this leaves the work

- **W0042** is the 991 rewrite: replace gro_cells with a driver-owned NAPI.
- **W0041** stays open and stays worth posting, on the strength of
  `backlog_napi_setup()` binding the kernel's own per-CPU NAPI thread while
  gro_cells' are left unbound. It is no longer blocking anything here.
- **W0002 stays blocked until W0042 lands.** The answer to "attempt it again" is
  still no; what changed is that there is now a way to make the answer yes.

### 23.24 The GRO feature bit is on by default and means nothing, and one real lever falls out of that - 2026-09-14

A second-hand account arrived claiming that "every standard virtual netdevice
natively supports software GRO by default", that `ethtool -k wwan0` showing
`generic-receive-offload: on` proves it, and that this is "an undisputed, proven
fact" for cellular interfaces. The observation is right and the conclusion is
backwards, for the same reason my own `bs_gro()` was wrong in 23.22.

#### The bit is set by the core, for every netdev, always

`register_netdevice()` at `net/core/dev.c:10575`:

```c
dev->hw_features |= (NETIF_F_SOFT_FEATURES | NETIF_F_SOFT_FEATURES_OFF);
dev->features    |= NETIF_F_SOFT_FEATURES;
```

and `NETIF_F_SOFT_FEATURES` is `(NETIF_F_GSO | NETIF_F_GRO)`
(`include/linux/netdev_features.h:237`). No driver involvement at all - which is
why stock `mhi_wwan_mbim.c` contains **zero** lines mentioning `features` and
still reports `generic-receive-offload: on`.

#### The bit does not make GRO happen

GRO exists in exactly one place: inside `napi_gro_receive()`. A driver that calls
`netif_rx()` never goes near it. The path is

```
netif_rx() -> netif_rx_internal() -> enqueue_to_backlog()
           -> process_backlog()  -> __netif_receive_skb()
```

and `process_backlog()` contains **zero** occurrences of the string `gro`. It
dequeues from `sd->process_queue` and calls `__netif_receive_skb()` directly.

So on a stock kernel `ethtool -k wwan0` says GRO is on and **not one packet is
ever aggregated**. That is the entire reason 991 exists, and this tree already
recorded it: "GR01 x NW2, unpatched - inert. The feature bit is settable and does
nothing."

I have no standing to be smug about this. `bs_gro()` read the same bit and drew
the same unwarranted conclusion, in this document, two sections ago.

#### What that account gets right, which is not nothing

- **"Cellular drivers push data up via `netif_rx()` or simple tasklets."**
  Correct: `mhi_wwan_mbim.c:348` is `netif_rx()`, `mhi_net.c:228` is
  `__netif_rx()`.
- **"`echo 1 > threaded` does nothing; there is no low-level driver kthread."**
  Correct **for stock**, and it is the same provenance point 23.22 makes from the
  other direction: an empty `dev->napi_list` means `dev_set_threaded()` creates
  no threads. It is wrong for this tree, because 991 put per-CPU gro_cells NAPIs
  on that list. It also does not "throw an error" - it returns 0 and does
  nothing.
- **`rx-udp-gro-forwarding` and `rx-gro-list` are real.**
  `NETIF_F_GRO_UDP_FWD_BIT` at `netdev_features.h:86` and
  `NETIF_F_GRO_FRAGLIST_BIT` at `:83`, both listed in
  `NETIF_F_SOFT_FEATURES_OFF` (`:240`), so the core exposes them in `hw_features`
  and leaves them off.

#### One claim that is overstated rather than wrong

"Historically, GRO only worked for packets destined for the router itself." That
is true of **UDP only**. `net/ipv4/udp_offload.c:654`:

```c
if ((!sk && (skb->dev->features & NETIF_F_GRO_UDP_FWD)) ||
    (sk && udp_test_bit(GRO_ENABLED, sk)) || NAPI_GRO_CB(skb)->is_flist)
        return call_gro_receive(udp_gro_receive_segment, head, skb);
goto out;   /* no GRO */
```

`!sk` is the forwarded case - no local socket - and without the feature bit it
falls through to no GRO. TCP has no such gate: `NETIF_F_GRO_UDP_FWD` appears zero
times in `net/ipv4/tcp_offload.c` and `net/core/gro.c`. Forwarded TCP has always
been aggregated on ingress and re-segmented by GSO on egress.

#### W0043: the lever this leaves behind

`rx-udp-gro-forwarding` is inert on the interface class it is usually
recommended for, because those drivers have no GRO to forward. **On this box it
is not inert, because 991 supplied the NAPI context.** That makes it the first
zero-risk thing to try in a while:

```sh
ethtool -K wwan0 rx-udp-gro-forwarding on
```

- Runtime only, `ethtool -K`, reversible with `off`, no reboot, and unlike
  `threaded` it cannot wedge the receive path.
- It helps only UDP the router **forwards** rather than terminates - WireGuard,
  QUIC and other tunnelled transit. Traffic to the router itself already had GRO
  through the `sk && udp_test_bit(GRO_ENABLED, sk)` arm.
- The `rx-gro-list off` half of the usual recipe is a no-op here:
  `NETIF_F_GRO_FRAGLIST` is in `NETIF_F_SOFT_FEATURES_OFF` and is already off
  unless something turned it on.
- **Unmeasured.** Worth an A/B on the same rig as 23.19 before it is believed,
  and worth checking how much of this link's traffic is forwarded UDP at all
  before expecting much - 23.11 established the family split, not the protocol
  mix.

### 23.25 The backlog sweep, run at last: no drops at any depth - 2026-09-14

`gro-backlog-ab.sh` has existed since 2026-09-12 and its default mode - the one
it was written for - had never been run. It has now. The result removes the
premise W0002 rests on, at least at the rate this link delivered.

| window | Mbit/s | dgram/s | skb/s | agg | rx_dropped | softnet_dropped | time_squeeze | bytes/skb | rtt min/avg/max |
|---|---|---|---|---|---|---|---|---|---|
| backlog-1000 | 126.0 | 10976 | 2344 | 4.68x | **0** | 0 | 0 | 6718 | 47.4 / 75.9 / 183.6 ms |
| backlog-2000 | 105.8 | 9211 | 2337 | 3.94x | **0** | 0 | 0 | 5657 | 47.2 / 95.1 / 189.3 ms |
| backlog-4000 | 86.9 | 7575 | 2218 | 3.42x | **0** | 0 | 0 | 4898 | 40.2 / 94.7 / 177.4 ms |

#### What cannot be read from this, by the script's own rule

The header says to compare only windows whose `dgram/s` are within about 10% of
each other. These are 10976, 9211, 7575 - **31% from first to last**, three times
the threshold, declining monotonically. So the throughput column and the rtt
column say nothing about backlog depth. The link drifted, the rule caught it,
and the backlog comparison the sweep exists to make did not happen.

#### What can be read, because it does not depend on comparing windows

**`rx_dropped` is 0 in all three windows, `softnet_dropped` is 0, `time_squeeze`
is 0.** Drift cannot manufacture zeros: the *fastest* window, 10976 dgram/s at
the stock backlog of 1000, dropped nothing either.

That is the finding, and it is aimed straight at W0002. The premise is stated in
the script's own header:

> At ~20k datagrams/s this link overflows a queue and drops about 0.2% of them.
> [...] time_squeeze has stayed 0 throughout, so the NAPI is not running out of
> poll budget - the queues fill between polls, which is a scheduling-latency
> problem. That is why threaded NAPI is worth testing at all.

No drops means nothing is filling between polls, which means **there is nothing
for threaded NAPI to fix here.** A deeper backlog cannot reduce zero either,
which is why the knob the sweep exists to turn had nothing to act on.

**This does not refute the premise at 20k dgram/s.** The 0.2% figure was measured
at roughly twice today's peak rate. What the run establishes is narrower and
still useful: at ~11k dgram/s this receive path is not dropping anything, is not
short of poll budget, and has no queue pressure at the shipped backlog.

GRO is working: 4.68x aggregation at the top window, 6718 bytes/skb against a
~1435-byte datagram. That sits between the two figures already on record -
24.8x on 2026-09-09 and 2.20x on 2026-09-11 - and is consistent with the
rate-dependence 22 already describes rather than being a new result.

Latency remains the only poor number. 47 / 76 / 184 ms under load at the stock
backlog, and the average rose to 95 ms at both deeper settings. That is the
expected bufferbloat direction, but with a 31% rate drift across the run I am
not attributing it to the backlog.

#### A defect in the harness, not just in the run

The sweep walks 1000, 2000, 4000 in fixed order and never revisits a setting.
**On a link that degrades monotonically during a run, the first window wins
whatever it was set to.** That is exactly the failure 23.19 dealt with on the
Wi-Fi side, where conditions were made to alternate under one continuous
transfer so drift shows up as cycle-to-cycle spread instead of as a fake result.
`wifi-encap.sh` alternates; this sweep does not, and today it produced a perfect
monotonic decline that is indistinguishable from "deeper backlog is slower".

Two things follow, and both are cheap:

1. `sh /tmp/gro-backlog-ab.sh --baseline` is already a drift control - one
   window under the same load, changing no sysctl. If it returns near 11k
   dgram/s the link recovered and the decline was within-run; if it stays near
   7.5k the link degraded and stayed degraded.
2. `/tmp/.gro_ab_load.log` was written this run - the script reported fetcher
   errors. Streams dying and restarting would produce exactly this decline, and
   that would make it a harness fault rather than a link one.

#### The drift control settles it: the sweep measured the load, not the backlog

`--baseline` was run immediately afterwards - one window, same load generator,
`netdev_max_backlog` left at the restored 1000:

| window | Mbit/s | dgram/s | agg | rx_dropped | rtt avg |
|---|---|---|---|---|---|
| sweep, backlog-1000 | 126.0 | 10976 | 4.68x | 0 | 75.9 ms |
| baseline, backlog-1000 | 91.1 | 7933 | 3.51x | 0 | 81.3 ms |

**Same setting, 28% apart.** And 7933 is essentially where `backlog-4000` landed
(7575). So the monotonic decline across the sweep was the offered load, not the
queue depth. The backlog comparison did not merely fail its comparability rule -
it measured nothing at all, and that is now established rather than suspected.

A second tell points the same way. The pre-window load check reported about
94 Mbit/s before the sweep and about 115 Mbit/s before the baseline - *higher* -
while the measured window went the other way, 126.0 down to 91.1. A steadily
degrading link cannot make both of those move in opposite directions. An
unstable load can.

#### Why the load was unstable: my fetcher, not the far end

`/tmp/.gro_ab_load.log` holds 34 lines, all `fetch exit 8`, in pairs about every
2.5 seconds from 17:37:42 to 17:38:24 - steadily, for the whole run. Exit 8 is a
server error response. Four streams were asked for; two downloaded and two sat
in a retry loop failing immediately, which is what a public speed-test source
limiting concurrent connections from one address looks like.

**The harness reported this as healthy.** `start_load()` printed "load: 4 of 4
stream drivers running", and that count was of live subshell PIDs. The subshell
stays alive *because* its `wget` keeps failing - the `while :;` retry loop is
what keeps it there - so the check was closest to a lie exactly when the load was
worst. The only load gate was "are at least 5 Mbit/s arriving", which two working
streams passed comfortably.

That is the same class of error as `bs_gro()` reading a feature bit: an
instrument that cannot distinguish the state it is supposed to detect. Three of
these have now turned up in this document in one day.

Fixed in `gro-backlog-ab.sh`, in two passes - the first of which was not a fix:

**Attempt one refused to run.** It counted real fetch failures instead of PIDs
and stopped the sweep if any appeared in the first eight seconds, telling the
operator to retry with `STREAMS=2`. That worked - the gate fired on its first
live use and stopped a doomed run in eight seconds - but it left the operator to
discover the source's concurrency limit by hand, and it hard-coded one server's
behaviour into a harness that should not care. A tool that refuses is better
than one that lies, and still worse than one that works.

**Attempt two ramps the load up instead.** `start_load()` now adds one stream at
a time, waits three seconds, and keeps it only if no new failure appeared:

- `STREAMS` becomes a **ceiling rather than a demand**. Whatever the source
  serves is what the run uses, and the number is printed rather than assumed.
- The script never passes through a broken state and never needs to be told the
  limit. Against the default URL it settles at two without being asked.
- Zero streams kept is the only fatal case, and it means the URL or the link is
  wrong rather than busy.
- `load_drift_check()` runs after the windows and warns if any fetch failed
  *after* the ramp settled, baselined at `LOAD_BASE` so the ramp's own probe
  failures are not counted twice. That is the case that invalidates a run: a
  stream that was serving drops out and the offered load moves under the
  windows.

#### What the source actually does, asked rather than assumed

Both attempts above carried a comment asserting that the source "caps concurrent
connections per address". **Nothing had measured that.** All that was observed
was `wget` exiting 8, which means only "server issued an error response" - not
which response, and not why. A probe run on the box on 2026-09-15 settled it:

| test | result |
|---|---|
| one `curl` request | HTTP 206 |
| one `wget` request | streaming normally, no error |
| an extra request with 0 connections held | HTTP 206 |
| with 1 held | HTTP 206 |
| **with 2, 3 and 4 held** | **HTTP 429 Too Many Requests** |
| five rapid *sequential* requests, nothing held | 206, 206, 206, 206, 206 |
| `Range` | `206 Partial Content`, `Content-Range: bytes 5000000-5000100/1073741824`, `HTTP/1.1` |

So: **two simultaneous connections, and the third gets 429.** Not a request-rate
limit - five rapid sequential requests all passed, so frequency is fine and only
simultaneity is capped. Not a `wget` problem either; `wget` streamed happily.

Range is served, and it does **not** help. A ranged GET still opens a
connection, and the response is HTTP/1.1, so there is no multiplexing to hide
extra streams inside. Four streams from this one host was never possible.

One correction to the probe itself: it first reported `wget` as having errored.
It had not - my regex `4[0-9][0-9]`, meant to catch HTTP status codes, matched
the **443** in the IPv6 address `2a01:4ff:1ef::fa57:1:443`. A port number read
as a status code, in the same document that already warns against exactly this
class of mistake.

**So the fix is more sources, not a different request.** `URL` now takes a
space-separated list and `nth_url()` deals streams round-robin across it, so a
per-source cap of two allows four streams across two hosts. `set --` lives
inside that function, where it rebinds the function's parameters and not the
caller's - the containment is deliberate, since doing it at top level is what
once printed a byte counter where a window label belonged. Verified for one,
two and three sources, for the caller's parameters surviving, and for an empty
list.

Only the existing URL is shipped, because it is the only one measured. Anything
added should be checked first:

```sh
curl -s -o /dev/null -w '%{http_code}\n' -r 0-200000 <candidate>
```

The insight the first attempt missed is that **the count was never the problem.**
A stable two streams measures correctly. What ruined the run was churn - streams
thrashing on retry make the offered load wander, which reads as throughput drift
and is indistinguishable from the setting under test mattering.

Verified offline against a stub source that caps concurrency: asked for four,
kept four of four, two of two, one of one, and took the fatal path at zero.
- The sweep now **repeats backlog-1000 as a drift control at the end**, so the
  spread attributable to drift is measured in the same run as the effect. This
  is the cheap form of the alternation 23.19 arrived at for the Wi-Fi A/B.
- The read-it-this-way note now says to compare the control pair *first*.

#### The clean run, 2026-09-14, `STREAMS=2`

The gate fired on the first attempt exactly as designed - 6 fetch failures in
8 seconds, stopped before spending the data - and `STREAMS=2` then produced the
first run of this harness with a load that held:

| window | Mbit/s | dgram/s | skb/s | agg | rx_dropped | rtt min/avg/max |
|---|---|---|---|---|---|---|
| backlog-1000 | 110.5 | 9616 | 2294 | 4.19x | **0** | 38.4 / 71.7 / 140.5 ms |
| backlog-2000 | 135.4 | 11790 | 2370 | 4.97x | **0** | 35.3 / 94.7 / 253.2 ms |
| backlog-4000 | 124.1 | 10801 | 2357 | 4.58x | **0** | 30.6 / 91.8 / 155.7 ms |
| backlog-1000 (drift control) | 76.9 | 6695 | 2183 | 3.07x | **0** | 37.3 / 79.4 / 166.1 ms |

`load: 2 of 2 stream drivers up, 0 fetch failure(s)`. `softnet_dropped` and
`time_squeeze` were 0 in every window, as was `rx_errors`.

**Throughput is still unreadable, and now the harness proves it rather than
implying it.** The two windows at backlog 1000 are 2921 dgram/s apart. The three
*settings* span 2174. **Drift is larger than the effect**, so no ordering of the
settings survives - including the tempting reading that 2000 is best because it
posted the highest number. Unlike the first run the decline is not monotonic
(9616, 11790, 10801, 6695), which says this is ordinary link variance rather
than a systematic artefact.

**Latency is readable, because the same test passes.** The two backlog-1000
windows differ by 7.7 ms; the 1000 pair averages 75.5 ms against 93.3 ms for the
deeper pair - a 17.8 ms gap, 2.3x the within-setting spread, and in the direction
theory predicts. **A deeper backlog costs about 18 ms of latency under load and
buys nothing**, because there were no drops to reduce at any depth. That is the
bufferbloat trade with one side empty. Two samples per condition, so it is
suggestive rather than settled - but it is the first time this sweep has produced
a comparison that survives its own drift control.

**Eight windows now, across two runs, at 6695 to 11790 dgram/s: zero drops
everywhere.** The peak here exceeds the first run's, and W0002's premise still
has nothing under it.

#### What 991 is actually doing, measured

The skb rate barely moves while the datagram rate swings hard:

- `dgram/s` spans 6695 to 11790, **+76%**
- `skb/s` spans 2183 to 2370, **+8.6%**

GRO absorbed nearly all of it. At the top window 11790 datagrams per second
reached the stack as 2370 skbs - **4.97x less per-packet work**, and the stack
saw a nearly constant skb rate across a 76% swing in offered datagrams. This is
the clearest demonstration in the record of what 991 buys, and it is a stronger
argument for the patch than any of the throughput numbers that could not be read.

#### Four streams at last, and they made the measurement worse

The multi-source ramp held: `load: 4 of 4 stream(s) holding, no fetch failures`,
dealt round-robin across four Hetzner hosts that each serve two. First time this
harness has run four streams. The candidate check found `hil`, `ash`, `fsn1` and
`nbg1` all serving 206 at two concurrent apiece, and Cloudflare's endpoint
returning 403 - so the "designed for parallel" source I would have reached for
is not usable from here at all.

| window | Mbit/s | dgram/s | skb/s | agg | rx_dropped | rtt avg |
|---|---|---|---|---|---|---|
| backlog-1000 | 75.7 | 6591 | 3355 | 1.96x | **0** | 61.2 ms |
| backlog-2000 | 86.2 | 7506 | 3149 | 2.38x | **0** | 107.0 ms |
| backlog-4000 | 73.7 | 6415 | 3251 | 1.97x | **0** | 70.0 ms |
| backlog-1000 (drift control) | 88.7 | 7738 | 3853 | 2.01x | **0** | 79.8 ms |

**Throughput fails the drift control for the third consecutive run**: the two
windows at backlog 1000 are 1147 dgram/s apart, the three settings span 1091.

**Latency is tracking the offered load, not the queue depth.** `backlog-4000`,
the deepest setting, came in at 70.0 ms against a 70.5 ms mean for the two
backlog-1000 windows - indistinguishable. `backlog-2000` has both the highest
rate and the worst latency, which is what a fuller pipe looks like rather than a
deeper queue. The 17.8 ms gap measured in the previous run is **not reproduced**,
and there are now two reasons it might not be: a different rate, and - below - a
different flow structure.

#### More streams is not more load: it is less GRO

This is the result worth keeping, and it was not what the run was for.

**First, how this was nearly got wrong.** The obvious comparison is peak against
peak - 11790 dgram/s at 4.97x with two streams, 7738 at 2.01x with four - and it
is worthless. Those windows are 34% apart in rate on a link that varied fivefold
across the session, and aggregation is already known to be rate-dependent (22).
Comparing them is precisely what this section's own drift rule forbids.

**The rate-matched pair is the one that carries weight:**

| | streams | sources | dgram/s | skb/s | agg |
|---|---|---|---|---|---|
| previous run, control window | 2 | 1 | 6695 | 2183 | 3.07x |
| this run, backlog-1000 | 4 | 4 | 6591 | 3355 | 1.96x |

**1.6% apart in datagram rate - inside the 10% this section calls comparable -
and aggregation is 36% lower while the stack takes 54% more skbs.**

And rate alone does not explain it. Run 3 is the control for that: two streams at
~3500 dgram/s also gave agg ~2.0. This run carried **twice that rate for the same
aggregation**, where a purely rate-driven effect would have put it well above.

The mechanism is not subtle once stated. GRO merges consecutive packets **of the
same flow**. With four flows interleaving on one link, the next packet is the
same flow only about a quarter of the time, so each batch that reaches
`napi_gro_receive()` is shorter and aggregation collapses - here from ~5x to ~2x.
The link then hands the stack nearly twice as many skbs while carrying a third
less traffic.

Two of the four sources compound it: `fsn1` and `nbg1` are in Germany, so two of
the four streams were trans-Atlantic. They added flows without adding rate.

#### How far this actually goes, graded

- **The figures**: E1. Read straight off the output, arithmetic on top.
- **"aggregation is lower in the four-stream run"**: E1, on the rate-matched
  pair above.
- **"because GRO merges within a flow"**: E2. That is how `napi_gro_receive()`
  works, not something inferred from these numbers.
- **"more streams *causes* less GRO"**: **E3.** One window per condition, drawn
  from two different runs, and the four-stream run also changed the source count
  *and* the source geography. Two of its four streams were trans-Atlantic, which
  is its own confound - and one I inferred from the hostnames `fsn1` and `nbg1`
  rather than measuring. Nothing here is a controlled experiment.

The mechanism is sound and the rate-matched pair fits it, but the claim is
supported rather than established, and it should not be written down as though
it were measured.

**The controlled test is cheap and has not been run:** the same two sources, the
same session, only `STREAMS` differing, alternated so link drift shows as
spread. Four `--baseline` windows, about two minutes.

**Consequences meanwhile.** Stream count is not a free knob - it plausibly
changes what is being measured, so runs at different counts should not be
compared on `skb/s`, on `agg`, or on anything downstream of per-packet stack
work until this is settled. The instinct that drove this detour, that more
streams means more load and therefore a better test, produced a *lower* datagram
rate here, which is measured and not in doubt.

#### What it changes

- **W0002's premise is unsupported at this rate.** Its argument was
  scheduling-latency evidenced by drops. There were no drops.
- **W0042's case is weaker, not stronger.** Its value was making W0002
  measurable. Measuring something with no demonstrated problem behind it is not
  worth rewriting a working patch for.
- **The sweep has been fixed rather than re-run as-is.** It now refuses a
  partial load and carries its own drift control, so the next run either
  produces a comparable set or says why it cannot.
- **Eight windows now show zero drops**, across both runs and from 6695 to
  11790 dgram/s. The zeros are the one column the load fault never touched,
  because a bad load generator only lowers the rate and drops are
  rate-dependent.
- **`netdev_max_backlog` should stay at 1000.** Deeper depths removed no drops,
  because there were none, and cost about 18 ms of latency under load. That
  closes the question the sweep was written to answer, in the opposite
  direction from the one that motivated it.
- **The gate and the drift control both earned their place on first use** - one
  stopped a doomed run in 8 seconds, the other disqualified a throughput
  ordering that looked clean.
- **Sixteen windows across four runs, 2316 to 11790 dgram/s, zero drops in
  every one.** The backlog question is closed: no depth removed a drop, because
  there was never one to remove.
- **Nothing here reaches 20k dgram/s, and more streams will not get there.**
  Four streams produced a *lower* datagram rate than two. If that rate is worth
  chasing it needs a faster link or fewer, fatter flows - not more fetchers.
  Whether the original 0.2% figure reproduces at 20k remains open and is now
  the only open part of it.
- **Stream count joins the list of things a run must state to be comparable**,
  alongside GRO, backlog, threading and steering.

### 23.26 The controlled test falsifies my own stream-count claim - 2026-09-15

23.25 recorded, at E3, that more load streams means less GRO. The controlled
test it called for has now been run and **the claim is wrong.** Same two US
sources on both legs, same session, alternated 2, 4, 2, 4 so link drift shows as
within-condition spread, run twice.

| # | STREAMS | dgram/s | skb/s | agg |
|---|---|---|---|---|
| A1 | 2 | 4697 | 2165 | 2.17x |
| A2 | 4 | 8299 | 2790 | 2.97x |
| A3 | 2 | 3160 | 1665 | 1.90x |
| A4 | 4 | 3105 | 1669 | 1.86x |
| B1 | 2 | 5495 | 1807 | 3.04x |
| B2 | 4 | 2758 | 1507 | 1.83x |
| B3 | 2 | 1939 | 1056 | 1.83x |
| B4 | 4 | 2780 | 1510 | 1.84x |

**Stream count does not separate them.** Two-stream aggregation spans 1.83 to
3.04; four-stream spans 1.83 to 2.97. The ranges almost entirely overlap, and
the single highest aggregation in the set, 2.97x, is a **four**-stream window -
backwards for the claim. Correlation between stream count and aggregation:
**-0.11**, which is nothing.

**Rate separates them completely.** Sorted by datagram rate, aggregation is
monotonic across all eight windows: 1.83, 1.83, 1.84, 1.86, 1.90, 2.17, 3.04,
2.97. Correlation with rate: **+0.90**.

So aggregation on this link is a function of arrival rate, exactly as 22 already
recorded, and the stream count is irrelevant. **The rate-dependence was the
confound I identified, argued past, and should have deferred to.**

The rate-matched pair that convinced me is worth naming, because it looked
strong and was not. Two streams at 6695 dgram/s gave 3.07x; four at 6591 gave
1.96x - 1.6% apart in rate, 36% apart in aggregation. What that pair also
differed in was **source geography**: the two-stream run used one US host, the
four-stream run used four hosts of which two were in Germany. Trans-Atlantic
paths have their own pacing and loss behaviour. One matched pair from two
different runs, with an uncontrolled variable in it, beat by eight windows that
were actually controlled.

**Withdrawn:** "more streams causes less GRO". **Retained, and now at E1 across
eight controlled windows:** aggregation tracks arrival rate.

#### What the clean-boot capture turned up

Two defects in `boxstate.sh`, both in the document every other measurement is
read against.

**It printed errors between its facts.** Nine `cat: read error: No such file or
directory` lines, interleaved with the RPS values. The guard was `[ -r "$q" ]`,
which tests that `open()` will succeed - and it does. The **`read()`** then
returns `-ENOENT`, which sysfs does for `xps_cpus` and `rps_flow_cnt` on bridges
and wireless vifs where the attribute exists but has no value to show. Replaced
with `bs_qattr()`, which lets the read fail, discards stderr, and contributes
nothing for an empty result.

**It contradicted itself three lines apart.** The snapshot said
`br-lan ports missing from the flowtable list: eth1 ...` and then
`XMIT_DIRECT is reachable for clients on: eth1`. Both cannot be true: 23.17
established the bridge port must be *in* the flowtable device list.
`bs_note_direct_scope()` was splitting ports by whether they are plain netdevs
and never consulting the list. It now reports three groups - reachable now, would
be if added, and never - using `bs_ft_has`.

#### Three facts the capture was missing

Raised by the operator, and the first is the sharpest: `rx-udp-gro-forwarding`
had just been switched on by hand and the snapshot could not see it.

- **`rx-udp-gro-forwarding` and `rx-gro-list`.** Both sit in
  `NETIF_F_SOFT_FEATURES_OFF` (`netdev_features.h:240`), so unlike `gro` - which
  the core sets on every netdev - "on" here means somebody set it. That makes
  them exactly the kind of fact a window has to be read against.
- **The qdisc on every interface, not only the WAN.** The egress discipline
  shapes what leaves each link, and only `wwan0` was being shown.
- **irqbalance enabled vs running.** Only "running" was reported. The uci value
  is what survives a reboot, and on this tree `93-irqbalance` set it, which is
  why a clean boot finds it live.

No API bump: the file's own rule is that adding a reader does not need one, and
no caller's contract changed.

#### Drops, again

Eight more windows, `rx_dropped` 0 in every one. **Twenty-four windows across
five runs now, 1939 to 11790 dgram/s, not one drop.**

### 23.27 A syntax, arithmetic and logic audit of the shipped scripts - 2026-09-15

Six scripts audited with `shellcheck 0.9.0` in POSIX `sh` dialect, parsed in
busybox ash, dash and bash, and then the arithmetic tested numerically. Most of
what the linter raised is noise on this codebase; three real defects came out,
two of them in the measurement math itself.

#### What is clean, and why the linter's complaints are not

- **All six parse in busybox ash** - the shell the router actually runs - as
  well as dash and bash.
- **Five `SC2045` "iterating over ls output is fragile"**: false, and provably
  so. `dev_valid_name()` (`net/core/dev.c:1140`) rejects any name containing
  `/`, `:` or `isspace()`, and caps length at `IFNAMSIZ-1`. Interface names
  cannot contain whitespace, so the word splitting those loops rely on is safe.
- **Four `SC2154` "referenced but not assigned"** on `sb`/`sp`/`sr`/`sf`: they
  are assigned by an `eval` of awk output, which shellcheck cannot see through.
- **Two `SC2140` "suspicious quoting"**: `"A"\<newline>"B"` concatenates into a
  single argument. Verified - `argc=1`, `arg1=[part one part two]`.
- **`BS_FAILED` "appears unused"**: set at `boxstate.sh:60`, initialised at
  `:335` which is before the library return at `:594`, and read by
  `xdp-ft-wwan.sh:224`. An unset value would arithmetic to 0 in any case.
- **busybox shell arithmetic is 64-bit.** `2^40` and `3e9 * 8` both evaluate
  correctly. The `%d` saturation that cost this project three figures is a
  **busybox awk** defect, not a shell one: `awk %d` on 3e9 prints
  `-2147483648` while `%.0f` prints it correctly. No awk `printf %d` in any of
  the six is applied to a raw byte counter.
- **Division-by-zero is guarded everywhere it can occur**, including the site I
  suspected first: `verify-992a.sh:241` wraps its awk in
  `[ "$_ds" -gt 0 ] && [ "$_dp" -gt 0 ]` with an else branch. I was wrong about
  that one.
- **`meas()` captures `_lab=$1` at line 339, before `set --` at 361-362.** The
  bug that once printed `2147483647` where a window label belonged is genuinely
  fixed, not merely moved.

#### Defect 1: a duplicate hex parser that a blank field turns into a crash

`gro-backlog-ab.sh` carried its own `sq()` reading `/proc/net/softnet_stat`:

```sh
_d=$((_d + 0x$_b)); _s=$((_s + 0x$_c))
```

With an empty field that expands to `$((0x))`, which is an **arithmetic syntax
error** - verified - and there was no readability guard on the file either.
`boxstate.sh` has owned this read all along as `bs_hexsum`, which walks the hex
digits by hand (busybox awk has no `strtonum`), skips anything that is not a hex
digit, and returns 0 for an unreadable file. `sq()` now delegates. Both produce
identical output on the same file.

This is the consolidation boxstate's own header describes, finished: that header
already claims `gro-backlog-ab.sh` was the only script reading `time_squeeze`,
and the copy it was consolidating out is the one that was still there.

#### Defect 2: a whole-second clock in the divisor of every rate

`wifi-encap.sh` measured its window with `date +%s`. Whole seconds, so a true
20.0s window reads as 20 **or 21** depending only on where it fell inside a
second - a 5% error, landing directly in the divisor of every throughput it
reports. `gro-backlog-ab.sh` had the opposite problem: it used the *nominal*
`WINDOW` and never measured at all, silently absorbing the seven counter reads
that bracket the sleep on each side.

Neither needed a better idea, only a better clock. busybox `date` has no `%N` -
it prints the literal characters - but `/proc/uptime` is seconds with two
decimals on every Linux. `bs_now_cs()` reads it as centiseconds, and both
scripts now divide by what actually elapsed. Error over a 12s window drops from
8.3% (whole seconds) to 0.008%.

That conversion has its own trap, caught before shipping: concatenating the two
halves of `0.50` gives the string `050`, and `$((050))` is **40**, because a
leading zero means octal. `10#` would fix it and is a bashism busybox merely
tolerates; the halves are added arithmetically instead.

The new throughput expression was checked against the old across four
magnitudes - they agree - and its worst intermediate, 1 Gbit/s for 60 seconds,
is `6e12` against an int64 ceiling of `9.2e18`.

#### Defect 3: a silent double-count if awk is missing

`wifi-encap.sh` summed station counters through `eval` of an awk `END` block.
awk's `END` always fires, so the variables are normally assigned even with no
stations - but if awk itself were absent the `eval` produces nothing and the
*previous* interface's values survive into the next iteration's addition. They
are now reset to 0 before each eval. A zero is a visible wrong answer; a
double-count is an invisible one.

#### Does any of this invalidate a result already taken?

Almost none of it, and the reason is worth stating because it is not luck.

**Defect 1 could not corrupt anything silently.** An empty field would have
produced an arithmetic syntax error on screen, not a wrong number - and
`/proc/net/softnet_stat` carries 15 fields on every line, so it never fired.
Defect 3 needed a missing `awk`, which was always present.

**Defect 2 is the one that touched real numbers**, and which numbers depends on
whether a quantity divides by the window at all:

| quantity | divides by the clock? |
|---|---|
| `rx_dropped`, `softnet_dropped`, `time_squeeze`, `rx_errors` | **no** - raw counter deltas |
| `agg` (`dp/ds`), `bytes/skb` (`db/ds`) | **no** - ratios; the divisor cancels |
| `retries/1k` (`dsr*1000/dsp`), `frames`, `failed` | **no** - ratios and raw deltas |
| `rtt` | **no** - comes from `ping` |
| Mbit/s, dgram/s, skb/s | **yes** |

So every load-bearing conclusion survives:

- **Twenty-four windows, zero drops.** A raw counter delta. Untouched.
- **No backlog depth removes a drop.** Same.
- **Aggregation tracks rate, not stream count.** `agg` is `dp/ds` and has no
  divisor at all; the correlation with `dgram/s` is scale-invariant, so a
  divisor wrong by a constant factor cannot move it.
- **4.97x aggregation, 2370 skbs for 11790 datagrams.** Ratios.
- **The throughput comparisons that failed their drift control three times.**
  Those use the divisor - but `gro-backlog-ab.sh`'s error was the *nominal*
  window, a systematic underestimate of the same size in every window. It
  inflates every absolute rate by the read overhead, well under 1%, and cancels
  out of any window-to-window comparison.

**One result is genuinely weakened: the encap A/B in 23.19.** It ran under
`wifi-encap.sh` with the `date +%s` clock, so its Mbit/s columns carry up to 5%
of *random* per-window error rather than a shared bias. Its conclusion was a null
- 875 against 886, a 1.3% gap, called "no cost worth measuring". That conclusion
still holds, because the A/B alternated four cycles per condition and random
error averages down by the root of the count, leaving roughly 2.5% against a 1.3%
observed gap. **What has to be restated is the resolution, not the verdict:** the
rig resolved worse than it was credited with, so "no measurable cost" means no
cost above a few percent, not no cost above one.

**Nothing needs re-running.** The fix improves every future window; it does not
retire a single past one. The only measurement still outstanding is W0043, and
that is blocked on the wrong *traffic* rather than a bad clock - it touches only
UDP this box forwards, and every window so far has been TCP terminating here.

#### What this does not cover

`shellcheck` finds shape, not meaning. It had nothing to say about any of the
measurement errors this document has had to withdraw - the feature bit read as
behaviour, the peak-to-peak comparison across drifting runs, the PID count read
as a working download. Those were all syntactically perfect.


### 23.28 W0041 form 2 is written, and the same source read found a live defect in 992 - 2026-09-15

Three changes, all from reading `net/core` rather than from a measurement, and
none of them yet on the box:

1. **996** makes gro_cells decline threaded NAPI. This is W0041 form 2 exactly
   as 23.21 proposed it, so writing 1 to `/sys/class/net/wwan0/threaded` is
   inert again rather than fatal.
2. **992 had a real bug** on the `XDP_PASS` return path: generic XDP hands the
   skb back with Ethernet receive metadata derived from the IP header, and on a
   router that silently drops every forwarded datagram. Fixed with three stores.
3. **Two things I expected to be bugs are not**, and both are now written down
   so the next pass does not re-derive them: `bpf_prog_put()` already defers,
   and `mhi_mbim_ip_proto()` needs no length guard.

**Evidence grade for all of it: E2.** Every claim below was read in
`v6.12.103`. Nothing here has been built, flashed or reproduced, which is the
outstanding work.

#### 996: how gro_cells opts out, and why three sites is all of them

23.21 named two possible shapes for W0041 and said form 2 -- have gro_cells opt
its NAPIs out -- is the one to send first, "because it cannot regress anything
that works today". That is what 996 is.

`NAPI_STATE_NO_THREAD` is appended to the state enum, so no existing bit is
renumbered. `gro_cells_init()` sets it beside the `NAPI_STATE_NO_BUSY_POLL` it
already sets, *before* `netif_napi_add()` -- that ordering is load-bearing, and
finding out why is what turned a two-site patch into a three-site one.

`NAPI_STATE_THREADED` can be set from exactly four places. Each had to be
accounted for:

| site | `dev.c` | what it does | how 996 handles it |
|---|---|---|---|
| `dev_set_threaded()` kthread loop | `:6688` | creates a kthread per NAPI on `dev->napi_list`, no filter | skipped by the bit |
| `dev_set_threaded()` assign loop | `:6722` | `assign_bit(NAPI_STATE_THREADED, ...)` on every NAPI | skipped by the bit |
| `netif_napi_add_weight()` | `:6765` | creates the kthread *there and then* if `dev->threaded` is already set | skipped by the bit |
| `napi_enable()` | `:6835` | sets the bit if `n->dev->threaded && n->thread` (`:6843`) | closes on its own: `n->thread` is never non-NULL |

The third row is the one I nearly missed, and it is why the `set_bit()` goes
before `netif_napi_add()` rather than after. A NAPI added to a device whose
`threaded` flag is *already* on never goes through `dev_set_threaded()` at all
-- it gets its kthread from `netif_napi_add_weight()`. Guarding only
`dev_set_threaded()` would have left that path open.

The fourth row then needs no code at all, and that is the whole reason the patch
is small: with no kthread ever created for these NAPIs, `napi_enable()`'s
condition can never be true for one.

Two further references to the bit are *not* sites. `dev.c:6266` and `:11818`
both do `napi->state &= NAPIF_STATE_THREADED`, which would clear `NO_THREAD` --
but both are reached only under `napi->poll == process_backlog`, so they can
never see a gro_cell.

**What the sysfs file means afterwards.** On a device whose every NAPI opts out
-- which is `wwan0` under 991, since the driver registers none of its own --
writing 1 succeeds, reads back 1, and threads nothing. That is exactly what the
file already does on a device with no NAPI at all, which is what `wwan0` was
before 991, so nothing that reads it changes behaviour. I considered returning
`-EOPNOTSUPP` so the write would fail visibly and did not: it is an ABI change
inside a patch whose job is to stop a corruption, and on a mixed device it would
have to answer differently depending on which NAPIs happen to exist when the
write lands.

**One precedent worth recording, because 23.21 got its mechanism slightly
wrong.** The kernel's own per-CPU NAPI does get a thread, and that thread is
CPU-bound -- but `backlog_napi_setup()` (`:12282`) does not create it.
It adopts one from the smpboot per-CPU thread pool registered at `:12356`, and
`kernel/smpboot.c:184` is where `kthread_create_on_cpu()` actually runs. So the
asymmetry 23.21 pointed at is real and is stronger than stated: the kernel does
not merely bind its per-CPU NAPI thread, it declines to use the unbound
`kthread_run()` path for it at all.

#### The 992 defect: generic XDP returns an Ethernet verdict on a raw-IP link

This is the part that was not on the list when the session started.

992's commit message already recorded that a program attached here "will
misparse silently, reading the first two octets of the source address as an
EtherType". What it did not record is that **the core does the same misparse,
on the way back, and acts on it.**

`bpf_prog_run_generic_xdp()` snapshots the packet as if it began with an
Ethernet header:

| `dev.c` | what it reads | what that is on `wwan0` |
|---|---|---|
| `:5093-5095` | `eth->h_dest` (bytes 0..5) and `eth->h_proto` (bytes 12..13), before the program runs | IPv4: version/IHL, TOS, total length, ID -- and the top half of the source address |
| `:5107` | `skb->mac_header += off` after `bpf_xdp_adjust_head()` | shifts the anchor 991 sets, so `mac_len` stops being 0 |
| `:5128` | compares those same bytes after the program ran | any difference reads as "the program rewrote L2" |
| `:5132-5134` | `__skb_push(ETH_HLEN)`, `pkt_type = PACKET_HOST`, `skb->protocol = eth_type_trans()` | runs `eth_type_trans()` over the IP header |

**What actually trips it, and what does not.** The comparison only looks at
bytes 0..5 and 12..13, so the obvious candidates are innocent and the
non-obvious ones are not:

* A TTL decrement (byte 8) and the checksum fixup it forces (bytes 10..11) land
  in the unused `h_source` field. **No trigger.**
* A DSCP remark (byte 1) changes `h_dest` but flips neither the multicast test
  nor the equality test. **No trigger.**
* A source-address rewrite touches bytes 12..13 on IPv4 and IPv6 alike.
  **Triggers.**
* An IHL change (0x45 -> 0x46) flips the low bit of byte 0, which is the
  Ethernet multicast bit. **Triggers.**
* Any `bpf_xdp_adjust_head()` moves what those offsets land on. **Triggers.**

**What it costs when it trips.** `eth_type_trans()` reads the version nibble as
the first octet of a destination MAC. IPv4's 0x45 has the multicast bit set, so
the datagram comes out `PACKET_MULTICAST`; IPv6's 0x60 does not, so it comes out
`PACKET_OTHERHOST`. Neither is `PACKET_HOST`, and `ip_forward()` rejects
anything that is not, at `net/ipv4/ip_forward.c:93`, under a comment reading
`/* that should never happen */`. On this box that is the entire WAN-to-LAN
path, dropped silently, for a program doing something as ordinary as NAT.

**The fix is three stores on the `XDP_PASS` path**: re-anchor the network and
mac headers, and force `PACKET_HOST`. `mac_len` needs no store of its own,
because `skb_reset_mac_len()` recomputes it from those two headers at
`dev.c:5603` and `gro.c:503` and it comes out 0 once they agree. All three are
unconditional -- testing for the case costs more than redoing them -- and they
are applied to `*pskb` rather than the entry skb, because `do_xdp_generic()` may
have replaced it.

The two other raw-IP modem netdevs in tree store `pkt_type` unconditionally on
receive anyway: `iosm_ipc_wwan.c:233` and `rmnet_handlers.c:48`. Stock
`mhi_wwan_mbim` never had to, because `netdev_alloc_skb()` zeroes the field and
`PACKET_HOST` is 0. Adding a hook that lets a program change it is what makes
the store necessary.

**This was never measured, and the harness would not have caught it.**
`verify-992a.sh` and `xdp-ft-wwan.sh` both attach counting or redirecting
programs that do not rewrite bytes 0..5 or 12..13, so every run to date sat on
the safe side of the trigger set by accident.

#### Two things that are not bugs

Both were on the suspect list and both were cleared by reading, which is worth
recording so they are not re-derived:

* **`mhi_mbim_xdp_set()` calling `bpf_prog_put(old)` with no grace period is
  correct.** `__bpf_prog_put()` (`kernel/bpf/syscall.c:2245`) routes the last
  reference through `__bpf_prog_put_noref(prog, true)`, which frees via
  `call_rcu_tasks_trace()` or `call_rcu()` at `:2224`/`:2226`. The RX tasklet
  holds `rcu_read_lock()` across the whole datagram loop, so a concurrent
  `rcu_dereference()` reader is already covered. No `synchronize_rcu()` is
  needed and adding one would be wrong.
* **`mhi_mbim_ip_proto()` needs no length guard.** I expected the post-XDP call
  to be able to see a zero-length skb. It cannot: generic XDP's own helpers floor
  the packet at `ETH_HLEN`. `bpf_xdp_adjust_head()` rejects
  `data > data_end - ETH_HLEN` and `bpf_xdp_adjust_tail()` rejects
  `data_end < data + ETH_HLEN`, both in `net/core/filter.c`. `skb->data[0]` is
  therefore in bounds on both call paths. The reason is now a comment in the
  function so the guard does not get added later.

#### Corrections to 23.21

Line numbers in 23.21's `gro_cells.c` table are off by one in three places, and
one in the body is off by one as well. Re-read against `v6.12.103`:

| 23.21 said | actually | what is there |
|---|---|---|
| `:37` | `:38` | `__skb_queue_tail(&cell->napi_skbs, skb)` |
| `:38` | `:39` | `if (skb_queue_len(...) == 1)`, the re-arm edge |
| `:49` | `:50` | `/* called under BH context */` |
| `dev.c:6721` | `dev.c:6722` | `assign_bit(NAPI_STATE_THREADED, ...)` |

`:28`, `:30`, `:58` and `:85` were right. The argument 23.21 makes is unaffected
-- every cited line still says what it was quoted as saying -- but a citation
that sends a reader one line off is the failure mode this document is supposed
to avoid, so it is corrected in place as well as recorded here.

#### What this changes

* **W0041 moves from proposed to written.** 996 is form 2. Form 1 -- bind each
  kthread to the CPU whose cell it serves -- remains the better fix if threaded
  gro_cells is ever wanted, and remains unwritten.
* **W0002 stays retired.** 996 makes the toggle harmless, not useful: a gro_cells
  NAPI still never runs in a thread, so there is still no threaded-NAPI latency
  number to go and get.
* **W0042 is no longer the price of safety.** 23.21 said the `threaded` control
  "must stay at 0 until W0042 replaces gro_cells with a driver-owned NAPI". With
  996 that is no longer true. W0042 stands or falls on its own merits now, which
  after 23.23 are thin.
* **991's commit message is rewritten**, and the file is ASCII-clean: it carried
  five em-dashes and a section sign, which `checkpatch.pl` flags and which have
  no business in a patch destined for netdev. The diff body is byte-identical
  (`md5` unchanged).
* **Three things are still owed**: a build carrying 996, a flash, and a
  reproduction of the 992 defect -- attach a program that rewrites the source
  address, confirm forwarded traffic dies without the fix and survives with it.
  Until that runs, everything in this section is a source read.

## 24. The outside sweep - 2026-09-15

Everything before this section was read inside this tree or inside `v6.12.103`.
This section is what five parallel investigations found by going outside both:
mainline `master`, the netdev/bpf/linux-arm-msm archives, and MediaTek's own
vendor SDK with its sparse checkout materialised.

It was prompted by a fair challenge - that I had never once searched outside the
tree in this round, and that I had asserted a hardware impossibility from a line
in my own patch header. Both were true. The sweep overturned one of my claims,
confirmed two, and produced a maintainer statement a month old that changes the
calculus for the whole XDP-on-the-modem question.

### 24.1 The position that matters: upstream has declined to make XDP work on non-Ethernet devices, in August 2026

`[PATCH net-next] net: xdp: don't assume an Ethernet header in generic XDP`,
Jiayuan Chen, posted 2026-08-13, is the closest thing to this tree's whole
problem that anyone has sent upstream. It was refused.

Jakub Kicinski, 2026-08-14:

> Let's try. There is no native XDP on any non-ether device, making generic xdp
> work on those is silly. Just attach the BPF in TC. [...] Please don't send
> fixes to net-next :| -- pw-bot: cr

Alexander Lobakin, 2026-08-18:

> Most XDP programs expect Ethernet header at the beginning of a frame. Unless
> you write a custom one which doesn't. But then you may face that XDP_TX,
> XDP_REDIRECT won't work properly -- cpumap Rx, each .ndo_xdp_xmit()
> implementation -- all expect Ethernet header at the beginning.

Toke Hoiland-Jorgensen, 2026-08-18:

> Yeah, I don't think we should start messing with the "XDP is Ethernet only"
> assumption at this point...

Status: `pw-bot: cr`, no v2 found. **E4** for the archive read, **E2** for the
quotes being verbatim from the page I opened.

Three things follow, and they are uncomfortable.

* **The 992 defect from 23.28 is the exact bug upstream declined to fix.**
  Generic XDP reading bytes 0..5 and 12..13 as an Ethernet header on a raw-IP
  link is precisely what that patch addressed. So the repair 992 now carries is
  not a local nicety: it is the workaround for something the core will not do,
  by explicit decision, a month ago.
* **"Just attach the BPF in TC" is Method D**, which this document tested and
  recorded as working at section 4. The maintainers' recommendation and this
  tree's own fallback are the same thing.
* **Any native-XDP-on-cellular submission walks into this.** Not as a technical
  objection but as a stated position from three maintainers, one of whom runs
  the tree.

### 24.2 I was wrong about headroom, and the real hazard is `frame_sz`

In conversation I reasoned that native XDP over an NTB is blocked because the
datagrams are packed with no headroom between them, so `data_hard_start` for
datagram N would point into datagram N-1. **That is wrong, and it is wrong in a
way worth recording precisely.**

Zero headroom does not stop a native XDP program running. `xdp_prepare_buff()`
(`include/net/xdp.h:121-139`) is pure pointer arithmetic - no assert, no clamp,
no `WARN`. `bpf_prog_run_xdp()` validates nothing. And the verifier never lets a
program reach `data_hard_start` at all: `xdp_is_valid_access()`
(`net/core/filter.c:9133-9158`) permits only `data_meta`, `data` and `data_end`.
**E2.**

What zero headroom actually costs is narrower and sharper than "it cannot work":

| consequence | mechanism | citation |
|---|---|---|
| `bpf_xdp_adjust_head()` fails for **any** offset below 40 - including `0` and including positive, shrinking offsets | the floor is the absolute address `data_hard_start + sizeof(struct xdp_frame)`, not a delta from `data` | `net/core/filter.c:4020-4038` |
| `XDP_TX` and non-XSK `XDP_REDIRECT` become impossible | `xdp_convert_buff_to_frame()` writes an `xdp_frame` into the headroom and returns NULL when `headroom - metasize < sizeof(*xdp_frame)` | `include/net/xdp.h:267-314` |
| `XDP_DROP`, `XDP_PASS`, `XDP_ABORTED` and AF_XDP redirect are unaffected | AF_XDP redirect copies | `net/xdp/xsk.c:204-232` |

So the minimum headroom that unlocks everything is **40 bytes**, not 256.

**And the real hazard is not headroom at all - it is `frame_sz`.**
`bpf_xdp_adjust_tail()` bounds growth at `data_hard_start + frame_sz -
SKB_DATA_ALIGN(sizeof(struct skb_shared_info))` and then **memsets that region**
(`net/core/filter.c:4283-4309`, macro at `include/net/xdp.h:147-149`). Nothing
correlates `frame_sz` with the actual packet or with where the next datagram
starts. Hand a mid-NTB datagram `frame_sz = 32768` and a program can legally
grow its tail thousands of bytes into the following datagrams and zero them.
`frame_sz` must describe the per-datagram slot. **E2.**

The same applies to the frags path, and harder: `skb_shared_info` lives at
`data_hard_start + frame_sz - SKB_DATA_ALIGN(...)`, and
`bpf_xdp_frags_increase_tail()` writes through it (`net/core/filter.c:4191-4211`).
Setting the frags flag on a shared buffer requires real, private tailroom per
datagram.

### 24.3 The precedent I said did not exist, does

Two in-tree counterexamples to "one packet per page", both of which I should have
found before reasoning from first principles:

* **octeontx2 runs native XDP over a page-pool fragment shared with other
  packets.** `otx2_common.c:533` allocates each RX buffer with
  `page_pool_alloc_frag()`; `otx2_txrx.c:1424-1430` runs `bpf_prog_run_xdp()`
  over that fragment with 128 bytes of per-fragment headroom and
  `frame_sz = pfvf->rbsize` - the fragment size, **not** `PAGE_SIZE`. That is the
  exact shape W0026 would need. **E2.**
* **mlx5e multi-packet-per-page merged in 2026-04.** `[PATCH net-next V2 0/5]
  net/mlx5e: XDP, Add support for multi-packet per page`, Tariq Toukan, merged by
  Kicinski. Reported 22.0% and 17.5% XDP_DROP gains at 1500/9000 MTU on 64K-page
  aarch64. It splits the linear XDP page into fixed-size fragments and tracks
  usage with a page_pool `frags` counter. **E4.**

The caveat that keeps this honest: mlx5's fragments are laid out by *hardware*
that knows the geometry, each with its own headroom. An NTB is laid out by modem
firmware that leaves no gaps. The precedent breaks the rule; it does not solve
the case.

Four in-tree drivers also pass literal zero headroom in a supported
configuration - ice, igb, i40e, ixgbe in legacy-rx mode. ice is the instructive
one: `xdp_prepare_buff(xdp, hard_start, offset, size, !!offset)`
(`ice_txrx.c:1257`) - it passes `meta_valid = !!offset`, deliberately disabling
metadata when headroom is zero. **E2.**

### 24.4 Why clone-based de-aggregation is dead, and what replaces it

`iosm` is the only in-tree WWAN de-aggregator that avoids the copy:
`skb_clone()` + `skb_pull()` + `skb_trim()`
(`iosm_ipc_mux_codec.c:366-382`). It is tempting and it is a trap here, three
ways, and the second is specific to this tree:

1. **Truesize.** `__skb_clone()` does `C(truesize)` - each clone inherits the
   parent's full 32 KB. Twenty-one clones account ~672 KB for ~30 KB of payload,
   which wrecks rcvbuf accounting and TCP window autotuning. iosm never corrects
   it. `cdc_ncm` - the same NTB format over USB - copies *deliberately* for this
   reason, and says so in the code: `/* create a fresh copy to reduce truesize */`
   (`cdc_ncm.c:1817-1823`). **E2.**
2. **It would silently disable 991's GRO.** `gro_cells_receive()` bails to plain
   `netif_rx()` when `skb_cloned(skb)` (`gro_cells.c:23`). Every clone would skip
   GRO entirely. **E2.** This is the one that settles it for this tree.
3. **It would not avoid a copy anyway.** `do_xdp_generic()` deep-copies cloned
   skbs (`net/core/dev.c:5202`). Clone plus XDP equals clone *and* copy.

The pattern that gets in-place de-aggregation **without** the truesize problem is
mlx5's striding RQ: `page_pool_fragment_page(page, MLX5E_PAGECNT_BIAS_MAX)` on
refill (`en_rx.c:285`), `frag_page->frags++` per packet carved out (`:539`),
`skb_add_rx_frag()` (`:540`), and crucially `unsigned int truesize =
pg_consumed_bytes;` (`:1991`) - each skb charged only the bytes it consumed,
so the sum over N skbs equals the buffer exactly. Unused references are drained
at retire with `page_pool_unref_page(page, MLX5E_PAGECNT_BIAS_MAX -
frag_page->frags)` (`:295-303`). **E2.**

That is the mechanism W0026 should copy. It is also the answer to the objection
that killed the clone idea.

### 24.5 The MHI plumbing for W0026 already exists

`mhi_queue_dma()` (`bus/mhi/host/main.c:1194-1211`) takes a `struct mhi_buf` and
sets `buf_info.pre_mapped = true`; `mhi_gen_tre()` then skips `map_single`
(`:1245-1249`), and the DL completion path skips the unmap and hands the
`cb_buf` back through `result.buf_addr` (`:643-646`). It is `EXPORT_SYMBOL_GPL`.
**So a page-pool-backed DL refill needs no MHI core change at all.** **E2.**

Three constraints that come with it: MHI never syncs for CPU on the pre-mapped
path, so the driver calls `dma_sync_single_for_cpu()` itself; the pool must be
created with `pp.dev = mhi_cntrl->cntrl_dev`, because that is what
`dma_map_single()` uses (`main.c:187`); and this modem is configured 32-bit DMA
(`pci_generic.c:1210`).

None of the three queue APIs takes scatter-gather - one TRE, one contiguous
region - so a 32 KB NTB still needs an order-3 page-pool page. `MHI_CHAIN`
(`include/linux/mhi.h:59`) is honoured by `mhi_gen_tre()` (`:1253`) and the DL
event parser is chain-aware (`:628`), but **no in-tree client has ever set it**.
**E2** for the plumbing, **E4** for whether real modem firmware honours it.

### 24.6 A smaller MRU is not an aggregation knob, and would make things worse

Worth recording because it is the obvious idea and it is actively harmful.

MRU is only the host buffer length written into the TRE (`main.c:1258`). **The
modem decides NTB size, not the host.** When the NTB exceeds the buffer, MHI
reports `MHI_EV_CC_OVERFLOW` (`main.c:581-599`) and the driver chains buffers
into a `frag_list` via `mhi_net_skb_agg()` (`mhi_wwan_mbim.c:366`, called
at `:437` and `:452`). `mhi_mbim_rx()` then issues three
`skb_copy_bits()` calls per datagram against a chained skb, and `skb_copy_bits()`
re-walks `skb_walk_frags` from the head every time. **That is O(n^2) in chain
length.** Smaller MRU means more chaining means slower. **E1/E2.**

This also raises a question worth a counter on the live box: whether the modem
ever exceeds 32 KB and triggers the chaining path *today*. If it fires at all,
that path costs more than anything else on the list.

### 24.7 WED, closed properly

The tree recorded "WED cannot be repurposed for the modem" at E3, reasoned from a
second-hand command enumeration. It is now **E2**, and the reason is stronger
than the one recorded.

First, a correction: **`struct mtk_wed_wlan_device` does not exist.** The client
contract is an anonymous `wlan` sub-struct inside `struct mtk_wed_device`,
`include/linux/soc/mediatek/mtk_wed.h:133-190`, marked `/* filled by driver: */`.

Of its 26 obligations, about five are mechanically suppliable by any PCIe device.
The rest are not, and two are structurally fatal:

* **`wpdma_phys`, `wpdma_int`, `wpdma_mask`, `wpdma_tx`, `wpdma_txfree`,
  `wpdma_rx_glo`, `wpdma_rx`, `wpdma_rx_rro[]`, `wpdma_rx_pg`** (`:144-152`) are
  physical addresses of **MediaTek WPDMA ring-control registers inside the
  client**. WED writes them into its own CSRs (`mtk_wed.c:1222-1252`) and then
  drives those registers as a bus master. WED does not accept packets; it
  *operates the client's DMA engine*. An MHI device has channel and event rings
  with CHDB/ERDB doorbells and a state machine - there is nothing to point WED at.
* **`init_buf`** (`:181`) is called for every TX buffer (`mtk_wed.c:700`) and
  mt76's implementation writes a MediaTek **TXWI plus a firmware TXP descriptor**
  into each one (`mt7915/mac.c:816-837`). Nothing but an 802.11 MAC consumes that.

The rest are `wcid_512` (station table size), `hw_rro` (802.11 reordering),
`amsdu_max_len`/`amsdu_max_subframes` (A-MSDU), the `*_tbit` fields (bit
positions in the WLAN chip's interrupt status register), and `ind_cmd` (Block-Ack
session state, 1024 session elements).

The attach path validates almost nothing - `mtk_wed_attach()` at
`mtk_wed.c:2378-2391` checks only the PCIe domain number and `try_module_get()`.
It is a trust contract, which is why the answer has to be argued from what
happens after rather than from a gate. Further down it branches on chip ID
(`:625`, `dev->wlan.id == 0x7991`) and loads `mediatek/mt7981_wo.bin`
(`mtk_wed_mcu.c:340-341`).

The WO command set is 26 entries (`mtk_wed.h:20-47`): two config, one state
machine, six logging, nine dumps, three statistics, and five that are explicitly
802.11 object models - `BSS_INFO`, `STA_REC`, `STA_BA_DUMP`, `BA_CTRL_DUMP`,
`RRO_SER`. **No command anywhere takes an IP address, port, protocol or any
5-tuple.** The vendor SDK adds none.

**And on this board it is doubly moot.** MT7981 has exactly one WED unit
(`117-complete-mt7981b-dtsi.patch:319-331`, `grep -c "wed@"` returns 1) and the
radio is `wifi@18000000` - **on-SoC, AXI-attached**, so mt76 sets
`wed->wlan.bus_type = MTK_WED_BUS_AXI` (`mt7915/mmio.c:679`). The Quectel is on
PCIe. They are not on the same bus, and `mtk_wed_assign()` (`:489-519`) hands out
each unit exactly once.

One naming trap, recorded so nobody chases it: **the WO's IPC block is called
CCIF, and MediaTek's modem stack (CCCI) also uses CCIF.** Shared IP, shared name,
no shared data path.

MediaTek does not do this for its own modem either: `drivers/net/wwan/t7xx/` is
MediaTek's CLDMA 5G modem driver on MediaTek silicon, and grepping it for
`wed|wdma|mtk_ppe|hnat|offload` returns nothing.

### 24.8 The vendor SDK does have a generic 5-tuple offload - and it is NETSYS v3 only

This is the find that would have overturned the assumption if the silicon
matched, and it is worth recording precisely because it is so close.

It is not WED. It is **TOPS/NPU** (Tunnel Offload Processing System) plus **PCE**
(Packet Classification Engine). In `mtkfeed`:

* `999-net-02-netdevice-add-npu-device-path-type.patch` adds a generic tunnel
  descriptor to `enum net_device_path_type` carrying **MAC addresses, source and
  destination IPs, and ports** - a real 5-tuple - with a
  `/* Extend other tunnel here */` union and a hook
  `extern int (*mtk_flow_tnl_offloadable)(const struct net_device_path *path);`.
* `999-eth-46-mtk_eth_soc-add-tnl-offload-support.patch` routes
  hardware-decapsulated packets to an arbitrary netdev via
  `tops_crsn = RX_DMA_GET_TOPS_CRSN(trxd.rxd6)`.
* `999-tnl-07-l2tp-add-fill-forward-path.patch` adds `pppol2tp_fill_forward_path`
  to `ppp_channel_ops` - a **non-802.11 driver producing a forward path**, which
  upstream has no equivalent of.
* `mtkfeed/feed/kernel/pce/` is a whole packet-classification-engine driver.

Why it cannot run here, three independent gates: `rxd6` exists only in
`struct mtk_rx_dma_v2`, and MT7981 uses the 4-word `struct mtk_rx_dma`
(`mtk_eth_soc.c:5344`); the crypto/NPU TX path is gated on
`mtk_is_netsys_v3_or_greater()` and MT7981 is v2 (`:5330`); and
`"mediatek,pce"` is declared only in MT7988 device trees. **E2.**

So the honest statement is not "MediaTek never built a generic offload". It is
**"MediaTek built it for NETSYS v3 and it never came back to v2."** If
hardware-assisted modem forwarding is ever the goal, that is the lineage - on
MT7988/MT7987, not this board.

**Can it be backported? I do not know, and my first answer overstated the
case.** Recording both the answer and the overstatement, because the
overstatement is the more instructive half.

The gate itself is one line. `mtk_is_netsys_v3_or_greater()` is
`return eth->soc->version > 2` (`mtk_eth_soc.h:1349-1352`) and
`mt7981_data.version` is the literal `2` (`mtk_eth_soc.c:5330`).

I then named three things behind it and called them silicon. **All three are
readings of what the shipped driver configures, not of what the hardware
contains**, and the difference is exactly the one this page's own header warns
about: "nobody has done it" and "it cannot be done" are different claims.

| what I verified (E2) | what I asserted (E3, overstated) | what would actually settle it |
|---|---|---|
| `mt7981_data` sets `rx.desc_size = sizeof(struct mtk_rx_dma)`, four words (`:5344`); `mt7988_data` sets `_v2`, eight (`:5404`) | "`rxd6` is absent silicon" | **Settled 2026-09-15, and it went against me** - see below. `rxd6` is how the driver *talks to* TOPS, not why MT7981 lacks it. I had the causality backwards |
| `compatible = "mediatek,pce"` appears in `mt7988.dtsi` and not in `mt7981.dtsi` (zero word-boundary matches for `tops`, `npu`, `pce`) | "the PCE is not present on MT7981" | A memory map. **Undeclared in device tree is not absent from the die** - a DT node can be added for a block that exists at an address. This is precisely the "make it available" question, and a DTS absence cannot answer it |
| `feed/kernel/` holds `crypto-eip`, `fips-debugfs`, `pce` and nothing else | "TOPS cannot be had" | Where MediaTek actually ships the TOPS module. Its absence from *this SDK snapshot* is a sourcing fact, not a hardware one |

**The falsification test, run - and it clears the conclusion while killing my
reason for it.** The test was: if MT7987 is NETSYS v2 *and* carries TOPS, the
descriptor argument collapses. MT7987 is **NETSYS v3**, confirmed in two
independent copies of `750-net-ethernet-mtk_eth_soc-add-mt7987-support.patch`,
the 6.12 one this tree builds and the 6.18 one in OpenWrt. So there is no v2 SoC
with TOPS, and the conclusion survives.

But completing the table is what matters, because MT7987 turns out to be the
interesting case rather than the control:

| SoC | `.version` | `ppe_num` | RX descriptor | `tops`/`npu`/`pce` DT node |
|---|---|---|---|---|
| MT7981 | 2 | 2 | `mtk_rx_dma`, 4 words | no |
| MT7986 | 2 | 2 | `mtk_rx_dma`, 4 words | no |
| **MT7987** | **3** | 2 | **`mtk_rx_dma_v2`, 8 words** | **no** |
| MT7988 | 3 | 3 | `mtk_rx_dma_v2`, 8 words | **yes** - the only SoC declaring `mediatek,pce` |

**MT7987 is NETSYS v3, has `mtk_rx_dma_v2`, therefore has `rxd6` - and still has
no TOPS.** Zero word-boundary matches for `tops`, `npu` or `pce` across all
fifteen `mt7987*.dtsi` files in the vendor SDK. So:

* being NETSYS v3 is **not sufficient** for TOPS;
* having v3 descriptors is **not sufficient** for TOPS;
* **TOPS tracks the specific part, not the generation and not the descriptor
  format.** It appears on exactly one of four Filogic SoCs.

That makes "MediaTek built it for NETSYS v3" - my phrasing - wrong. But so was
my replacement for it. I then wrote **"MediaTek built it for MT7988"** and called
TOPS "an MT7988-only hardware block", which is the same error a third time: what
MT7987 establishes is that MediaTek **did not wire it**, not that the silicon
lacks it. If a v3 part with `rxd6` can ship without a TOPS node, wiring is a
choice, and that reading cuts against my conclusion rather than for it.

#### What the PCE actually is, which I should have looked at first

The MT7988 node is:

    pce: pce@15100000 {
            compatible = "mediatek,pce";
            fe_mem = <&eth>;
    };

**No `reg`, no clocks, no interrupts, no power domain.** It is not a separate IP
block. It borrows the frame engine's register window, and the driver reaches
everything through `writel(val, netsys.base + reg)` where `netsys.base` is that
window (`feed/kernel/pce/src/netsys.c`). The offsets it uses, from
`inc/pce/netsys.h`:

| symbol | offset |
|---|---|
| `PPE0_BASE` / `PPE1_BASE` / `PPE2_BASE` | `0x2000` / `0x2400` / `0x2C00` |
| `PPE_TPORT_TBL_0` / `_1` | `0x0258` / `0x025C` |
| `GLO_MEM_CFG` / `GLO_MEM_CTRL` / `GLO_MEM_DATA_IDX(x)` | `0x0600` / `0x0604` / `0x0608 + 4x` |

That `CFG` / `CTRL` / `DATA_IDX` triple is an **indirect table-access window** -
the tables being CLS, CDRT, DIPFILTER and TS_CONFIG, whose index limits
`netsys.c` carries in `fe_mem_limit[]`.

And the geometry lines up exactly with this board:

* Both `mt7981.dtsi` and `mt7988.dtsi` declare `eth: ethernet@15100000` with
  `reg = <0 0x15100000 0 0x80000>` - **same base, same 512 KB window**.
* MT7981 uses `mt7986_reg_map`, whose `ppe_base` is `0x2000`; MT7988 uses
  `mt7988_reg_map`, whose `ppe_base` is also `0x2000`. **The PCE driver's
  `PPE0_BASE` matches MT7981's PPE0 offset exactly.**
* Upstream `mtk_eth_soc` describes **nothing** at `0x0258` or `0x0600` for *any*
  SoC, and has no notion of CLS, CDRT, DIPFILTER or `GLO_MEM` at all. So upstream
  silence is not evidence either way.

**So I cannot establish from source that MT7981 lacks these tables.** The
register geometry the PCE driver assumes is the geometry MT7981 has. The only
difference I can actually point to is a device-tree node MediaTek did not write.
**E2** for all of the above; the conclusion I previously drew from it is
withdrawn.

#### The question is now testable on the box, which it never was before

This is the useful part. `GLO_MEM_CFG` is a plain register read at physical
`0x15100600`. Whether MT7981's frame engine responds there is not a datasheet
question any more - it is a `devmem` read, with the PPE0 registers upstream
already drives as a positive control and unused offsets in the same window as a
negative control. `x3000/docs/fe-probe.sh` does exactly that and nothing else.

> **Superseded in part, see 24.13.** This build has no `/dev/mem` at all
> (`CONFIG_DEVMEM` is unset in OpenWrt's shared config), so the read was not
> available when this was written. Three config symbols fix that; the
> placement of one of them is not where it looks like it should go.

**Read-only, and it must stay that way.** Writing an undocumented frame-engine
register on a live router is how the WAN goes away. Reading is not free either -
on some designs an unimplemented address inside a peripheral window raises an
imprecise abort rather than returning zero - so it is a run-it-when-a-reboot-is-
cheap probe, not a routine one.

Neither outcome would be proof. A region that reads back identical to the
negative controls is consistent with not being implemented; a region that reads
back structured says it responds. Either is one more piece of evidence than a
device-tree absence, which is all this question has had so far. **E1 once run;
nothing above it has been run.**

Weak corroboration, graded **E4** and offered as no more than that: MediaTek's
own RDK-B `meta-filogic` layer's only TOPS reference is an MT7988 commit. It
carries no per-SoC capability matrix, so it confirms nothing on its own.

**One claim from the sweep that I am retracting outright.** The sweep reported
"the vendor's own build matrix has `mt7987-npu` and `mt7988-npu`". It does not.
The only `npu` build variant anywhere in the feed is **`mt7996_npu`**, and every
occurrence is inside **mt76 Wi-Fi driver patches** - that is the Wi-Fi 7 chip's
own NPU, unrelated to NETSYS TOPS. I did not carry the claim into this document,
but it was in the report this section was written from, and the same search will
surface it again.

**What is genuinely established:** the v3 path as MediaTek wrote it will not run
on this board unmodified, because it reads a descriptor word this driver does
not configure and maps a node this device tree does not declare. **What is not
established:** that the silicon lacks the blocks. Those are different sentences
and only the first is E2.

**Two patches in the series looked worth carrying and are not** - see 24.12.
I planned to take them as scaffolding for W0040 and validation killed that:
neither compiles here as written, one patches a file this image does not build,
and the infrastructure they appeared to add is already upstream. W0044 is
withdrawn. What came out of looking properly is a much stronger W0040, now
shipped as 997.

One method note, because this section nearly recorded the opposite. My first
sweep of the vendor SDK for `mt7981` near `npu` returned the MT7981 device trees
as hits, which reads as evidence that the silicon has an NPU. It is the regex
trap this document has hit before: **`input` contains `npu`.** With word
boundaries the count is zero.

A methodological note that cost real time: the `mtkfeed` checkout is **sparse**.
`git sparse-checkout disable` materialises 4,683 files; anyone grepping it
without that gets false negatives.

One curiosity found along the way and confirmed dead: the legacy 5.4 vendor HNAT
declares `ppe_hook_rx_modem` and `ppe_hook_tx_modem` function pointers
(`21.02/.../foe_hook/hook_ext.c:29-32`) with a `channel_id` argument. Zero callers
anywhere in 4,683 files, `struct sk_buff *` so software not hardware, and gone
entirely from the current 6.12 HNAT. There is no `FOE_MAGIC_MODEM` in the legacy
magic list either.

### 24.9 The PPE claim was right in its conclusion and wrong in its mechanism - and downlink installs a phantom entry

This tree has recorded, and built on, the assertion that *"a PPE entry needs both
ends and every internet flow on this box crosses the modem, which can never be a
PPE ingress."* The bottom line survives. The mechanism does not, and the wrong
mechanism has been producing a false sub-conclusion.

**"A PPE entry needs both ends" is false. E2.** A `struct mtk_foe_entry` contains
**no ingress-derived field whatsoever**. Every `mtk_foe_entry_set_*` helper
writes egress state: the L2 header the PPE will synthesise, the destination PSE
port, the queue, the VLAN/PPPoE/DSA/WDMA encapsulation to apply on transmit. The
ingress netdev is consulted in exactly one place in the whole driver -
`mtk_ppe_offload.c:291-299` - and only to choose which of the two PPE units to
install into. `mtk_flow_is_valid_idev()` returning false **is not an error
path**: there is no `else` and no `return`, and control falls straight through.

The two real barriers are:

1. **The egress must be an mtk netdev.** `mtk_ppe_offload.c:224-231` -
   `eth->netdev[0..2]` or `-EOPNOTSUPP`. A genuine, cited software check.
2. **The ingress must physically enter through a GMAC or WDMA.** PPE ingress
   routing is configured per-GDM-port only (`mtk_eth_soc.c:3460-3479`), and PPE
   learning happens only inside the FE RX DMA loop from the FE RX descriptor
   (`:2169-2204`). A packet arriving over PCIe/MHI has no FE RX descriptor. This
   is a hardware property and is **never expressed as a software check anywhere
   in the driver** - which is exactly why conflating it with (1) was easy.

**The operational finding, and it is the one to act on. E2.** The two directions
are two independent FOE entries with two independent cookies
(`nf_flow_table_offload.c:866-896`), both always offered
(`nft_flow_offload.c:378` sets `NF_FLOW_HW_BIDIRECTIONAL` unconditionally), and
one succeeding is sufficient (`nf_flow_table_offload.c:955-969`).

* **Uplink (LAN -> modem) is rejected twice**: `-EINVAL` at
  `mtk_ppe_offload.c:398-400` because the synthesised source MAC is all-zero
  (wwan0 has `addr_len == 0`), and `-EOPNOTSUPP` at `:231` because wwan0 is not
  an mtk netdev. Clean, visible failure.
* **Downlink (modem -> LAN) is accepted and installed.** The ingress check falls
  through, both MACs are valid because they come from the LAN side, `eth1`
  resolves to `PSE_GDM2_PORT`, and `mtk_foe_entry_commit()` runs at `:500`. **A
  real entry in `MTK_FOE_STATE_BIND` appears in
  `/sys/kernel/debug/mtk_ppe/entries` and forwards exactly zero packets**,
  because modem-originated packets never traverse the frame engine.

So any reading of PPE debugfs that treats a bound entry as evidence that WAN
offload works is wrong. That is a live instrument hazard on this box, of the same
class as the three this document has already had to withdraw. It is harmless to
correctness - `NF_FLOW_HW` only gates GC and stats - but it is misleading, and
nothing in this tree warned about it before now.

A second reason the entry is unreachable even in principle: GMAC1 is bound to
`ppe_idx = 1` (`mtk_eth_soc.c:3471-3473`) while the downlink entry lands on
`ppe[0]`, because `ppe_index` kept the literal `0` from
`mtk_ppe_offload.c:609` when the ingress check fell through.

**And MediaTek ships a counterexample to the "both ends" formulation today.**
`999-ppe-39-mtk_ppe-add-464xlat-clat-support.patch` matches a CLAT virtual
interface as the **ingress**, by name prefix `"464-"`, and never consults
`mtk_flow_is_valid_idev()`. **E2.** That is notable here beyond the general
point, because section 23.11 established that this link *is* 464XLAT.

### 24.10 Two findings from the sweep that I am rejecting

Recorded because both are correct about pristine 6.12.103 and wrong about this
tree, and the next sweep will surface them again.

* **"RX headroom is too small, so generic XDP reallocates every packet."** True
  of pristine `mhi_wwan_mbim.c:319`, where `netdev_alloc_skb()` yields only
  `NET_SKB_PAD` and `netif_receive_generic_xdp()` therefore takes the
  `netif_skb_check_for_xdp()` branch on every packet
  (`net/core/dev.c:5202-5206`). **992 already fixes this**: it reserves
  `XDP_PACKET_HEADROOM` whenever a program is attached, so headroom is
  `NET_SKB_PAD + XDP_PACKET_HEADROOM` and the slow branch is never taken. The
  patch header has always said so.
* **"Threaded NAPI on the gro_cells NAPIs, zero code, move GRO to the second
  core."** This is W0002, and section 23.21 established it is unsafe by
  construction; 996 now makes the toggle inert precisely so it cannot be taken.
  It is an appealing suggestion from the outside and it took the WAN down twice.

### 24.11 What this changes

* **My headroom claim is withdrawn.** Zero headroom does not block native XDP.
  The design constraint is 40 bytes for `XDP_TX`/`XDP_REDIRECT` and a correct
  per-datagram `frame_sz`; the memset in `bpf_xdp_adjust_tail()` is the actual
  hazard.
* **W0026 gains a mechanism and loses an excuse.** `mhi_queue_dma()` already
  accepts pre-mapped buffers, octeontx2 shows native XDP over a shared page-pool
  fragment, and mlx5 striding RQ shows how to charge truesize proportionally. The
  remaining obstacle is geometry - 32 KB against a 4 KB page - not accounting and
  not headroom.
* **W0026's payoff grading is unchanged.** Nothing here revisits the measurement
  that undercut "the modem path is CPU-bound by the copy": both cores at 20-26%
  at ~250 Mbps.
* **The upstream calculus is worse than it was.** Three maintainers stated a
  month ago that XDP is Ethernet-only and that the answer for non-Ethernet
  devices is tc-BPF. A native-XDP-on-cellular series is now first-of-kind against
  a stated position, not merely unprecedented.
* **WED moves from E3 to E2 and stays closed.** So does the modem-as-PPE-ingress
  question, with a corrected mechanism and a new instrument hazard attached.
* **One new open item**: whether the modem ever exceeds the 32 KB MRU today and
  triggers the O(n^2) `frag_list` chaining path. That is a counter on the box,
  not a source read.
* **One upstream door is open**: MediaTek's t9xx WWAN driver has its control
  plane in review at v7 and its **data plane not yet posted**. If page-pool or
  XDP is ever to exist in a cellular driver, an unfixed design is the place to
  argue for it.

### 24.12 W0040 was the answer, and the evidence for it is upstream - 2026-09-15

I set out to carry two of MediaTek's TOPS patches as scaffolding for W0040.
Validating them first killed the plan and produced a better one. Recording the
whole path, because the dead ends are the useful part.

#### What validation found, in order

| check | result |
|---|---|
| Is `union nf_inet_addr` reachable from `netdevice.h`? | **No.** No `netfilter.h` include, zero references; it is at `include/uapi/linux/netfilter.h:72`. `999-net-02`'s `tunnel.sip`/`.dip` do not compile here |
| Is `struct dst_entry` declared for `netdevice.h`? | **No.** Not there, not in `skbuff.h`. The only `include/linux/` header carrying the forward declaration is `security.h`, which is not included. `struct dst_entry *dst;` would declare a fresh incomplete type |
| Does another vendor patch supply those? | **No.** Of the eight `999-*` patches touching `netdevice.h`, the only one adding an include is `999-ppe-01`, and it adds `br_private.h` to a different file |
| Is `net/l2tp/l2tp_ppp.c` built in this image? | **No.** `# CONFIG_L2TP is not set` and `# CONFIG_PPPOL2TP is not set`, OpenWrt `generic/config-6.12:3124` and `:4882` |
| Does a new path type break existing consumers? | **No.** `nft_dev_path_info()` ends its switch with `default: info->indev = NULL; break;` and the caller bails on `!info->indev`. Clean |

So lifting was never a lift; it was a port with a config change attached.

#### The finding that changed the plan

**The infrastructure those patches appeared to add is already upstream.**
`struct ppp_channel_ops` has a `fill_forward_path` member at
`include/linux/ppp_channel.h:33` in pristine `v6.12.103`. MediaTek's
`999-tnl-07` does not add a hook - it *implements an existing one* for L2TP
channels. There was nothing to backport.

And once I looked at who implements these callbacks at all, W0040 stopped being
a board-specific Wi-Fi complaint. **Exactly three functions sit behind
`ndo_fill_forward_path` in the entire tree**, and two return `-EOPNOTSUPP` to
mean "not this instance":

| implementer | returns `-EOPNOTSUPP` | when |
|---|---|---|
| `ppp_fill_forward_path()` `ppp_generic.c:1591` | `:1599` | the PPP device is a multilink bundle |
| the same | `:1610` | the channel's ops lack `fill_forward_path` - and `pppoe.c:1008` is the **only** setter upstream, so every non-PPPoE channel type lands here, L2TP included |
| `ieee80211_netdev_fill_forward_path()` | `iface.c:939` (pristine) / `:1001` (backports 7.2, which is what ships) | the driver has no `net_fill_forward_path` op |

`dev_fill_forward_path()` (`dev.c:729`) turns every one of those into
`return -1`, discarding the walk - while a device with **no callback at all**
falls through to `DEV_PATH_ETHERNET` and works.

**So MediaTek's L2TP patch is a downstream workaround for W0040, not
infrastructure to carry.** They hit `ppp_generic.c:1610` and implemented the
hook for the one channel type they cared about rather than fixing the walk.
That makes it evidence *for* the bug report - a citation, not a merge.

#### A route that looked promising and closes cleanly

If a non-Ethernet device can implement `ndo_fill_forward_path`, could
`mhi_wwan_mbim` implement one and reach `FLOW_OFFLOAD_XMIT_DIRECT`? **No, and
the reason is structural. E2.**

`nft_dev_path_info()` sets `info->indev = path->dev` for
`DEV_PATH_ETHERNET/DSA/VLAN/PPPOE`, and the xmit type is decided at the end by
`nft_is_valid_ether_device(info->indev)` - which requires `ARPHRD_ETHER`,
`addr_len == ETH_ALEN` and a valid address. A non-Ethernet device reaches
XMIT_DIRECT only by **resolving down to a real Ethernet device beneath it**:
PPPoE resolves to its underlying NIC, a Wi-Fi client to its bridge port.

`wwan0` has nothing beneath it. It is the bottom of the stack - MHI over PCIe,
no netdev below. Whatever it declared, `info->indev` would still be `wwan0` and
`nft_is_valid_ether_device()` would still be false. Implementing the callback
there buys nothing.

#### What shipped

**997**, the three-line W0040 fix: treat `-EOPNOTSUPP` from
`ndo_fill_forward_path` as "no special path" rather than as failure. Three
details in it are load-bearing rather than stylistic, and each was found by
checking rather than by reading the diff:

* `dev_fwd_path()` does `int k = stack->num_paths++` **before** the callback
  runs, so the slot has to be given back.
* `ret` must be cleared. `nft_flow_offload.c:206` gates on `>= 0` and
  `mtk_ppe_offload.c:105-108` does `if (err) return err`, so leaving `ret` at
  `-EOPNOTSUPP` would reproduce the same bug one layer up. My first draft did
  exactly that.
* `break`, not `continue`. The callbacks return without touching `ctx`, so
  continuing trips `WARN_ON_ONCE(last_dev == ctx.dev)` immediately below.

**W0044 is withdrawn**, having existed for about an hour. The two patches it
covered are cited in 997's message instead.

### 24.13 The PCE question became answerable, and getting there cost two wrong answers - 2026-09-15

24.8 ended by saying the MT7981 PCE question "is not a datasheet question any
more - it is a `devmem` read." That was right about the shape of the answer and
wrong about whether the answer could be had: **there is no `devmem` on this
build, and there never was.** Closing that gap took one retraction of a claim I
had written into the probe's own help text, and one config change I placed in
the wrong file and shipped.

Everything below is **E2** where it is a source read, **E1** where it was run.
The register values themselves are still unread - that is the next section's
job, once an image carrying the corrected config is flashed.

#### What actually blocked the read

Not `CONFIG_IO_STRICT_DEVMEM`, which is what I guessed and, worse, wrote into
`fe-probe.sh` as the likely cause. The blocker is one line in OpenWrt's shared
kernel config:

`target/linux/generic/config-6.12:1405` carries `# CONFIG_DEVMEM is not set`.
With it off, `drivers/char/mem.c:764` skips the minor-1 entry, so devtmpfs never
creates the node; a node made by hand opens `-ENXIO` at `:723`. The char major
is still registered (`:756`), which is why `/proc/devices` is not the place to
look. No userspace tool can reach a physical address on such a kernel - not
`devmem`, not `dd`, not anything - so the backend question the probe spent two
rounds on was never the real one.

**The `IO_STRICT_DEVMEM` claim is withdrawn.** It is real in general and was
inert here: it `depends on STRICT_DEVMEM` (`lib/Kconfig.debug:1886`),
`STRICT_DEVMEM` was off (`generic/config-6.12:6546`), and with it off
`page_is_allowed()` is the no-op stub at `drivers/char/mem.c:79-82`, so nothing
filtered anything. The `CONFIG_IO_STRICT_DEVMEM=y` at `generic/config-6.12:2850`
was a dead line. Verified against three independent v6.12.x trees.

One correction to the question as I posed it: `read_mem()` calls
`page_is_allowed()` (`mem.c:141`), not `range_is_allowed()`, which is
mmap-only (`:362`). The conclusion is the same, both stub out to 1.

#### The placement trap, which is the part worth remembering

The fix is three symbols. Getting them to take effect is not obvious, and I got
it wrong and shipped an image without noticing:

| symbol | where it must live | why |
|---|---|---|
| `CONFIG_KERNEL_DEVMEM=y` | `x3000/config.common` | OpenWrt declares it, so a value written in the target fragment is overridden |
| `CONFIG_STRICT_DEVMEM=y` | `filogic/config-6.12` | no `KERNEL_` equivalent exists, so the fragment is its only home |
| `# CONFIG_IO_STRICT_DEVMEM is not set` | `filogic/config-6.12` | same |

The mechanism, read from `include/`:

1. `config/Config-kernel.in:1385` declares `KERNEL_DEVMEM` as a bare `bool`
   with **no `default` line**, so a defconfig pass writes
   `# CONFIG_KERNEL_DEVMEM is not set` into the top-level `.config`.
2. `include/kernel-defaults.mk:116` runs
   `awk '/^(#[[:space:]]+)?CONFIG_KERNEL/{sub("CONFIG_KERNEL_","CONFIG_");print}'`
   over that `.config` and **appends** the result to `.config.target` - which is
   the file the generic and subtarget fragments were already merged into. Note
   the regex matches the negated form too.
3. `scripts/kconfig.pl`'s `load_config()` is called without `mod_plus` for that
   file, so a later line overwrites an earlier one.

Net effect: `CONFIG_DEVMEM=y` in the subtarget fragment is silently replaced by
`# CONFIG_DEVMEM is not set` from the appended `KERNEL_` line. The build
succeeds, the image boots, and `/dev/mem` is simply absent. `STRICT_DEVMEM` then
falls with it, since it `depends on MMU && DEVMEM`.

**This is what the 2026-09-15 build produced**, and the only reason it was
caught is that the build script echoed the real kernel `.config` at the end
rather than trusting the merged fragment. A gate that reads the artifact instead
of the input is worth the two lines it costs.

The general rule, which was not written down anywhere before: a kernel symbol
OpenWrt declares as `KERNEL_<X>` must be set from `config.common`, because the
declared value always lands last; a kernel symbol it does not declare can only
be set from the target fragment. Checking which case applies is one grep of
`config/Config-kernel.in`.

#### What the three symbols buy, and what they cost

`STRICT_DEVMEM=y` is not belt-and-braces, it is what makes the whole thing
proportionate. `devmem_is_allowed()` (`lib/devmem_is_allowed.c`, selected by
arm64 at `arch/arm64/Kconfig:153`) returns 1 for a page that is not RAM and 0
for one that is, so the window narrows to memory-mapped I/O and kernel and
process memory stay unreachable. Without it, `/dev/mem` is an unfiltered
read-write handle on all of physical memory in exchange for one register read.

`IO_STRICT_DEVMEM` must then be explicitly off, because enabling `STRICT_DEVMEM`
is exactly what would make the shared config's dead `=y` line live -
`resource_is_exclusive()` (`kernel/resource.c:1819`) would call every
driver-claimed range exclusive, and `mtk_eth_soc` claims this entire window
through `devm_platform_ioremap_resource()`. The probe would read nothing.

#### 998, written and dropped

Before the config route was understood I wrote a temporary patch, 998, that read
the same fourteen offsets from inside `mtk_eth_soc` through the ioremap
`mtk_probe()` already holds, exposed at `/sys/kernel/debug/mtk_fe_probe`. It
worked on paper - applied at `--fuzz=0` against the fully patched tree, compiled
clean standalone - and it was the wrong answer, because enabling `/dev/mem`
takes three config lines and no carried patch, and `/dev/mem` is worth having
for the next register question as well. It was removed before it ever built.
Recorded here so the idea is not re-derived: a driver-side debugfs read is the
fallback if `/dev/mem` is ever unavailable again, not the first move.

#### The patch series, verified rather than assumed

Reconstructed the real tree - pristine `v6.12.103` plus every patch in this tree
that touches any file 990-997 touch, in OpenWrt's documented order
(backport, pending, hack, then target). The enumeration is complete:
`net/core/dev.c` is touched by exactly one earlier patch,
`hack-6.12/721-net-add-packet-mangeling`; `net/core/gro_cells.c` by none;
`include/linux/netdevice.h` by three; `mhi_wwan_mbim.c` by none before mine.

| patch | result |
|---|---|
| 990, 991, 992, 993 | clean |
| 995 | applies, 6 hunks at offset +47 |
| 996 | applies, 3 hunks at offset +5 |
| 997 | clean, zero offset, applied after 996 |

All at `--fuzz=0`. The offsets are stale recorded line numbers, not conflicts:
995 is +47 because 991 and 992 grow `mhi_wwan_mbim.c` above its hunks, and 996
is +5 because `hack/721` adds five lines to `dev.c` above its first edit. Left
alone; `make target/linux/refresh` is what zeroes them if that is ever wanted.

**One real defect found, in 997's own commit message.** It claimed to share no
file with 996. It does - both edit `net/core/dev.c`. They do not conflict, since
996 works on `dev_set_threaded()` and `netif_napi_add_weight()` near line 6726
and 997 on `dev_fill_forward_path()` near 749, roughly 6000 lines apart, which
is why 997 lands at zero offset even after 996. The sentence is corrected in
place and now says how it was checked.

Post-patch source consistency, checked in the extracted tree and confirmed again
on the box's own build: `NAPI_STATE_NO_THREAD` is appended last in the enum at
bit 10 with no existing bit renumbered, `NAPIF_STATE_NO_THREAD` is defined
alongside, and the four use sites resolve - `netdevice.h` 2, `dev.c` 4,
`gro_cells.c` 1, plus 997's unique `stack->num_paths--` 1, 992's `mhi_mbim_xdp`
5 and 991's `gro_cells` 7. Those six counts came back exactly on the 2026-09-15
build. **E1.**

#### Method notes from the probe itself

Two bugs in `fe-probe.sh` that are worth not repeating:

* **Tab indentation is not paste-safe.** A leading TAB pasted into an
  interactive shell is a readline completion request. It dumped the box's entire
  command list into the middle of the heredoc, twice, at exactly the two
  tab-indented lines inside `rd()`, so the file written was not the file sent.
  The script is spaces-only now and says why in its own header.
* **`devmem` is a busybox applet, not a coreutils one.** Installing coreutils
  never provides it. The rewrite takes `devmem`, `busybox devmem`, or `dd` plus
  `od` or `hexdump`, and reports which backend it chose.

On access width, since it matters for MMIO: a `dd bs=4 count=1` read lands in
`copy_from_kernel_nofault()`, which picks its width from the alignment of the
source and destination pointers alone (`mm/maccess.c:26-41`). On a 4-aligned
address the u64 loop cannot run and the u32 loop does exactly one 32-bit load,
which is the right width. Changing the block size breaks that, which is now a
note in the script.
