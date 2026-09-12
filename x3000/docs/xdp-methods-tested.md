# XDP / eBPF / tc-BPF on the X3000: every method, tested

Kernel sources read: **v6.12** (the target's own tree, `/scratchpad/lx`, matching
6.12.103 + your 990/991/992).
Compile tests: **x86_64 defconfig + `MHI_BUS=y WWAN=m MHI_WWAN_MBIM=m GRO_CELLS=y
BPF_SYSCALL=y XDP_SOCKETS=y TCP_CONG_BBR=m`**, driver and `net/core/filter.c` built
with `W=1`.
Runtime tests: this container's live kernel, on **real netdevs** — an `IFF_TUN`
device (`ARPHRD_NONE`, `hard_header_len 0`, no L2 header: the closest possible
analogue of `wwan0`), an `IFF_TAP` device, a veth pair, a bridge and an ifb.
clang 18 / libbpf 1.3 / iproute2 6.1.

---

## 0. Two corrections to what I told you earlier

**I was wrong about the blocker for XDP_REDIRECT on `wwan0`.**
I said it needed a one-line `EXPORT_SYMBOL_GPL(xdp_do_generic_redirect)` kernel
patch. It does not. `do_xdp_generic()` — which *contains* the redirect dispatch,
the `XDP_TX` path and its own `bpf_net_context` — **is already exported**:

```
net/core/dev.c:5170:  EXPORT_SYMBOL_GPL(do_xdp_generic);
```

and `drivers/net/tun.c` calls it from a driver in exactly the shape we'd need
(tun.c:1929 and tun.c:2523). I was looking one level too deep in the call chain
and stopped at the first unexported symbol.

**992 changed the default XDP attach mode on `wwan0`, and that is why
`xdp-loader load wwan0` broke.**

```
net/core/dev.c:9335:  return dev->netdev_ops->ndo_bpf ? XDP_MODE_DRV : XDP_MODE_SKB;
```

Pristine `mhi_wwan_mbim.c` has **0** `ndo_bpf` references; 991 has **0**; 992
adds **6**. So before 992, an attach with no mode flag went to `XDP_MODE_SKB`
(full generic XDP, redirect and AF_XDP included). After 992 it goes to
`XDP_MODE_DRV` — our hand-rolled hook, which advertises `NETDEV_XDP_ACT_BASIC`
and refuses `XDP_REDIRECT`. Verified at runtime (test C5 below).

That is the whole story of the crash you hit: `xdp-loader load wwan0` installed
libxdp's `xsk_def_prog`, 992's `ndo_bpf` captured it into native mode, the
program called `bpf_redirect_map()` from the MHI tasklet, and there was no
`bpf_net_context`. The `bpf_net_context` fix stopped the oops; the redirect
itself is still refused.

---

## 1. Method C — plain `xdpgeneric`, zero patches (WORKS TODAY)

| test | device | result |
|---|---|---|
| C1 | bridge (no `ndo_bpf`) | generic XDP **attached** |
| C2 | bridge, `xdpdrv` | refused: *"Underlying driver does not support XDP in native mode"* (`dev.c:9588`) |
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
U do_xdp_generic          <- EXPORT_SYMBOL_GPL, dev.c:5170
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
   and that arithmetic would walk off the front of the buffer. 992 currently
   resets it only *after* the XDP hook.
2. `skb->protocol` set before the call — `generic_xdp_tx()` and
   `dev_map_generic_redirect()` both end in `dev_queue_xmit()` and neither
   re-derives it. 992 also sets this only after the hook.
3. `do_xdp_generic()` takes `struct sk_buff **`, not `*` —
   `netif_skb_check_for_xdp()` may reallocate. (It won't here: the RX loop
   already reserves `XDP_PACKET_HEADROOM` when a program is attached. Honour the
   contract anyway.)

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
- `xdp_do_flush()` must be called before clearing the context. We're not inside
  `net_rx_action()`, so nothing else will drain the devmap/cpumap/xsk bulk queues
  this redirect just appended to.

Verdict: carries a kernel patch, duplicates code the core already exports, and
buys nothing over A. **Not recommended.**

---

## 4. Method D — tc-BPF on a raw-IP device (WORKS, with one gotcha)

Source, v6.12:

```
net/core/dev.c:4080   sch_ret = tcx_run(entry, skb, true);    /* ingress: pushes skb->mac_len */
net/core/dev.c:4139   sch_ret = tcx_run(entry, skb, false);   /* egress:  no push */
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
EtherType. Every packet looks like "not IPv4" and sails through unfiltered. Your
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
| wired LAN/WAN (`mtk_eth_soc`) | **yes** — `BASIC\|REDIRECT\|NDO_XMIT\|NDO_XMIT_SG` (`mtk_eth_soc.c:4706`), gated on NETSYS v2+; MT7981 is v2 | yes | yes | no |
| DSA user ports | no — `net/dsa/user.c`: 0 `ndo_bpf` | yes | yes | no |
| `br-lan` | no — `net/bridge/br_device.c`: 0 `ndo_bpf` | yes | yes | no |
| wireless LAN (mac80211/mt76) | no — `net/mac80211/iface.c`: 0 `ndo_bpf` | yes | yes | no |
| wireless WAN (`wwan0`) | 992's hook, `BASIC` only | yes (full set) | yes (raw-IP-aware) | no |

**Hardware BPF/XDP offload does not exist on this box.** Whole-tree grep:
`NETDEV_XDP_ACT_HW_OFFLOAD` is set in exactly two files — `netdevsim/netdev.c:629`
and `nfp/nfp_net_common.c:2768` — and `bpf_offload_dev_create()` has exactly those
two callers. Nothing MediaTek, nothing mt76, nothing MHI.

**MediaTek PPE hardware NAT can never carry LAN↔wwan0.**
`mtk_ppe_offload.c` resolves the egress PSE port from `eth->netdev[0..2]` and
returns `-EOPNOTSUPP` otherwise (line 227). `wwan0` is not one of those.

---

## 6. The one kernel hook that *does* tie nft-offload to XDP

You asked whether there's a specific hook inside `kmod-nft-offload` or the kernel
that makes hardware/software offload reachable from BPF. There is exactly one:

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
`nf_flow_offload_xdp_setup()` (`nf_flow_table_offload.c:1195`), precisely when the
flowtable is **not** hardware-offloaded.

Build gating, `net/netfilter/Makefile`:

```
145  nf_flow_table-y                            += ... nf_flow_table_xdp.o
148  nf_flow_table-$(CONFIG_DEBUG_INFO_BTF_MODULES) += nf_flow_table_bpf.o
150  nf_flow_table-$(CONFIG_DEBUG_INFO_BTF)         += nf_flow_table_bpf.o
```

The device→flowtable registration (`nf_flow_table_xdp.o`) is unconditional. Only
the **kfunc** needs BTF.

**Your build already has it.** `x3000/config.common` sets
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
| wireless (mt76/mac80211) | no `ndo_bpf` in `net/mac80211/iface.c` | yes | yes | `napi_gro_receive` (mt76 `mac80211.c:1550` -> `ieee80211_rx_napi` -> `rx.c:5533`) | no |
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
flows the hardware will take."** Choosing it never costs you the software path.

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
LAN-to-`wwan0` at all (10.1), so you would be giving up the only kernel hook that
lets an XDP program consult the flowtable in exchange for nothing. **Leave the
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

Both units are in use, so check both. `mtk_eth_soc.c:3466-3475` assigns
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
we have showed both CPUs at 0-6 percent during the stall, so **this box has not
yet been shown to be CPU-bound at all** - which makes RPS a lever to test at
250+ Mbps, not a known win. Measure `cpu0_busy`/`cpu0_si` in `dlwatch` with it
off and on before keeping it.


### 14.3 Measured, 2026-09-10: this box is not CPU-bound

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
  unlike an XDP redirect - it does the NAT for you, because it *is* netfilter.

### 15.4 The measurement that is missing

Everything above is optimising a bottleneck nobody has demonstrated. Every
capture we have shows both CPUs at 0-6 percent, including during the 43-second
deadlock at full downlink rate. The box has never been shown to be CPU-bound.

So the order is: measure first. #98 (RPS) is a one-line sysfs write that shows
whether moving work off CPU0 changes anything at all. If it does not, the whole
XDP fast-path line of work is solving a problem this hardware does not have, and
#101 and #102 should stay parked. If it does, that same measurement tells us how
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

    2105   xdp_init_buff(&xdp, PAGE_SIZE, &ring->xdp_q);
    2106   xdp_prepare_buff(&xdp, data, MTK_PP_HEADROOM, pktlen, false);
    2110   ret = mtk_xdp_run(eth, ring, &xdp, netdev);
    2114   if (ret != XDP_PASS) goto skip_rx;
    2117   skb = build_skb(data, PAGE_SIZE);
    ...
    2189   skb->protocol = eth_type_trans(skb, netdev);

The program runs at 2110 on a buffer that is still nothing but DMA'd page-pool
memory. `build_skb()` sits at 2117 and is reached only on `XDP_PASS`;
`eth_type_trans()` is seventy lines further on. Anything the program drops,
transmits or redirects never gets an `sk_buff` at all. So on `eth0` and `eth1`
the hook is genuinely ahead of allocation.

Two facts make it cheap to try. `mtk_page_pool_enabled()` is just
`mtk_is_netsys_v2_or_greater()`, and `mt7981_data.version = 2`, so this SoC
always takes the page-pool path whether or not a program is attached - attaching
one adds a `bpf_prog_run_xdp()` call and switches the pool's DMA direction to
bidirectional (line 1731), nothing structural. It does bounce the link once:
`mtk_xdp_setup()` calls `mtk_stop()`/`mtk_open()` when the program count crosses
zero.

### 16.2 But on the wired ports every ifindex-based helper reads a dummy netdev

MT7981 runs two netdevs on one DMA ring and one NAPI, so the driver has no real
device to register the RX queue against and uses a placeholder:

    1737   err = __xdp_rxq_info_reg(xdp_q, eth->dummy_dev, id,
                                   eth->rx_napi.napi_id, PAGE_SIZE);

    5129   eth->dummy_dev = alloc_netdev_dummy(0);

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

`mt76` uses a page pool for RX buffers, which makes it look like an XDP driver
from a distance. It is not one. There is no `xdp_rxq_info`, no `xdp_buff`, no
`bpf_prog_run_xdp` and no `ndo_bpf` anywhere in `mt76_dma.c` or `mt76.h` -
`grep -c xdp` returns 0 for both. Neither `mac80211` nor `br_device.c`
implements `ndo_bpf` either, so `br-lan` and every AP netdev are
generic-XDP-only.

Where the skb actually gets built on the wireless path:

    mt76_dma.c:1045       skb = napi_build_skb(data, q->buf_size);
      -> ieee80211_rx_napi()                        mac80211 rx.c:5510
        -> ieee80211_rx_list()   decrypt, defrag, A-MSDU split, 802.11->802.3
          -> ieee80211_deliver_skb()                mac80211 rx.c:2662
            -> napi_gro_receive()                   mac80211 rx.c:5533
              -> __netif_receive_skb_core()  <- generic XDP hook is here

The allocation happens in the driver's NAPI poll, before mac80211 has even
looked at the frame. A generic XDP program on an AP netdev sits at the very end
of that chain - later than the equivalent point on `wwan0`, and about as far
from "before allocation" as it is possible to get.

And it is not free to attach. `generic_xdp_install()` does
`rcu_assign_pointer(dev->xdp_prog, new)` and `dev_disable_lro(dev)`
(`dev.c:5944-5960`), and `netif_elide_gro()` is:

    netdevice.h:2423   if (!(dev->features & NETIF_F_GRO) || dev->xdp_prog)
                               return true;

which `dev_gro_receive()` tests on every packet (`gro.c:488`, `goto normal`).
So attaching any generic XDP program to `phy0-ap0` or `phy1-ap0` **turns GRO off
for that interface**. This is the same trap 992 was written to avoid on the
modem - it is exactly why 992 keeps the program on `link->xdp_prog` instead of
`dev->xdp_prog` - and on a wifi netdev there is no equivalent dodge available,
because there is no driver hook to own the pointer.

Net: on wireless you pay a certain, measurable loss (GRO and LRO) to buy a hook
that runs after every expensive thing has already happened. There is no version
of this that pays.

### 17.2 Every generic-XDP redirect bypasses the qdisc, and tc ingress

This is the finding that matters most, and it applies to `wwan0` and to the
wired ports equally.

Both redirect paths converge:

    filter.c:4655            generic_xdp_tx(skb, xdp_prog);   /* bpf_redirect() */
    devmap.c                 generic_xdp_tx(skb, xdp_prog);   /* bpf_redirect_map() */

and `generic_xdp_tx()` is (`dev.c:5237-5257`):

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

## 18. #114 run on hardware, 2026-09-11: what it measured, and why the CPU numbers do not stand

Section 16.6 asked for a bracket: the cost of the XDP hook itself, and the cost
of everything a pre-`sk_buff` drop skips. The test ran on the box across eight
attempts. It produced one solid throughput result, one instrument that has to be
abandoned, and two structural findings about the receive path that matter more
than the number it was after.

Read 18.3 and 18.6 before repeating any of this. Most of the attempts were
invalidated by the rig rather than by the box.

Everything in this section is labelled by how it is known: **measured** on the
router, **read** from `6.12.103` in the build tree at
`build_dir/target-aarch64_cortex-a53_musl/linux-mediatek_filogic/linux-6.12.103`,
or **reasoned**. The re-verification pass behind the `read` labels is 18.7.

### 18.1 The rig, and why it ended up using `xdp-filter`

Hand-compiled BPF objects were the original plan and they did not survive
transfer - base64 pasted into `ttyd` decoded to **zero bytes**, which `libxdp`
reports as the misleading `BPF object format invalid`. The same objects opened
cleanly under libbpf 1.3 off-box, so the objects were fine and the paste was not.

`xdp-tools` on this image ships `xdp-filter` alongside `xdp-loader` and
`xdpdump`, which removes the problem entirely - a prebuilt native XDP program is
already on the router:

    xdp-filter load -m native -f udp eth1      # parses to UDP, passes everything
    xdp-filter port -m dst -p udp 9999         # now udp/9999 dies pre-skb

The same program, `xdpfilt_alw_udp`, runs in both conditions and differs only by
one entry in its port map, so the difference isolates the drop rather than
comparing two different programs. It keeps its own per-action and per-port
counters, which turned out to be the only trustworthy numbers in the exercise.

The test flow is 64-byte UDP to the router's own LAN address, paced from a PC on
a wired LAN port. An `nft` rule at `type filter hook input priority 10` sinks it,
so the kernel never generates ICMP port-unreachable replies - without that, the
pass conditions carry a rate-limited ICMP path that the drop conditions do not.

### 18.2 What was actually measured

**Measured.** At roughly 100,000 pkt/s offered, over repeated 40 and 45 second
windows:

| path | result |
|---|---|
| full receive path to the input chain | zero loss |
| native `XDP_DROP` on udp/9999 | zero loss |

So capacity on both paths **exceeds 100k pkt/s on this port**, and no upper bound
was established. That is the entire measured result, and it is less than 16.6
asked for.

Two corrections to assumptions from earlier sections, both confirmed on hardware:

**The driver does export XDP counters to ethtool.** `rx_xdp_pass` and
`rx_xdp_drop` are present at `mtk_eth_soc.c:247-248` and they move. I had
predicted they were absent because those names come from the Marvell and Intel
drivers.

**`/proc/net/dev` `rx_packets` counts frames that XDP dropped.** Measured: in one
window `xdp-filter` counted 12,032,615 drops - `XDP_DROP` moved 500,849 to
12,533,464 and the port hit counter moved by the identical amount - while
`rx_packets` on `eth1` moved 12,000,459, agreeing to 0.3%. Read: that follows
from `mtk_get_stats64()` pulling from `mac->hw_stats` via
`mtk_stats_update_mac()`, where the non-MT7628 branch does

    hw_stats->rx_packets += mtk_r32(mac->hw, reg_map->gdm1_cnt + 0x8 + offs);

with `offs = hw_stats->reg_offset` selecting GDM1 or GDM2 per MAC. That is a
**hardware GDM frame counter**, incremented at the MAC before the CPU sees the
frame, so no software verdict can subtract from it. The practical consequence:
`/proc/net/dev` is the one packet source that works in every condition, attached
or not.

### 18.3 `/proc/stat` cannot measure per-packet cost on this box

This is the finding that cost the session. **Do not use `/proc/stat` for this.**

**Measured.** Eight consecutive 40-second windows, two CPUs, so an 80-second
budget each. Summing every state - user, nice, system, idle, iowait, irq,
softirq:

    72.04  73.71  70.02  92.54  81.51  73.81  66.71  96.25

67 to 96 against 80. All of the variation sits in the `system` column, which
ranged from 0.82 to 23.50 seconds across windows that were otherwise identical.
The windows really were 40 seconds: every one received within 0.5% of the same
packet count, so the sampler's clock and arithmetic were both sound. On an idle
box the same sampler closed correctly, 89.8 against a 90-second budget.

**Read.** The kernel's accounting configuration explains why this is expected
rather than anomalous:

    CONFIG_TICK_CPU_ACCOUNTING=y
    CONFIG_IRQ_TIME_ACCOUNTING=y
    CONFIG_NO_HZ_IDLE=y
    CONFIG_HZ=100

User, system and idle are assigned by **sampling at 100 Hz - one sample per 10 ms
per CPU** - with precisely-measured irq and softirq time subtracted from each
tick's allotment, and batches of skipped ticks attributed in a lump when NO_HZ
restarts the tick.

The decisive part needs no more than those two symbols. At 100k pkt/s the NAPI
poll runs on the order of 1,500 times a second in bursts of tens of
microseconds. A sampler with 10 ms resolution that attributes whole ticks cannot
resolve work at that timescale; over a 40-second window on two CPUs it has 8,000
samples to characterise 12 million packets. The resulting variance is structural,
not noise that averages out. Which specific mis-attribution produced the 96.25
totals is not identified here, and does not need to be.

Four successive attempts at a per-packet figure produced **1,583, then 4,132,
then 1,870 ns/pkt**. None of them stand. There is no per-packet CPU cost for this
box in this file. Getting one needs an instrument that does not read
`/proc/stat`: a fixed-work yardstick timed by wall clock, or a capacity
measurement built only from exact counters.

Two rig confounders found along the way, neither of them the root cause but both
capable of ruining a run on their own:

- **`ttyd` spins.** Streaming the results file with `tail -f` through `ttyd` put
  `ttyd` itself at 30.24 seconds and 100.8% of a core in one 30-second window,
  and left 15-16 seconds of *user* time in three others. Start the run detached
  with `setsid` over ssh and read the file afterwards. Never tail it live.
- **`irqbalance` rewrites IRQ affinity mid-window.** Stop it for the duration.
  Put it back afterwards - it had arranged a sensible split, RX on CPU0 and TX
  on CPU1.

### 18.4 The wired receive path is one kernel thread, on a device with no sysfs entry

Per-task CPU sampling - reading `utime` and `stime` from `/proc/<pid>/stat`,
because busybox `top` and `ps` do not list kernel threads at all - named the
holder of the receive work as a thread called `napi/mtk_eth-6`. That comes from
an OpenWrt patch, not upstream:

`target/linux/generic/pending-6.12/702-net-ethernet-mtk_eth_soc-enable-threaded-NAPI.patch`,
Felix Fietkau, 2022, *"This can improve performance under load by ensuring that
NAPI processing is not pinned on CPU 0."*

    + eth->dummy_dev->threaded = 1;
    + strcpy(eth->dummy_dev->name, "mtk_eth");
      netif_napi_add(eth->dummy_dev, &eth->tx_napi, mtk_napi_tx);
      netif_napi_add(eth->dummy_dev, &eth->rx_napi, mtk_napi_rx);

The thread name follows from `dev.c:1508`,
`kthread_run(napi_threaded_poll, n, "napi/%s-%d", n->dev->name, n->napi_id)` -
hence `napi/mtk_eth-<napi_id>`. Which of the two ids is RX is inferred from the
registration order above, not read.

Four consequences, and they compound:

**`cat /sys/class/net/eth1/threaded` returns `0` and is not wrong.** It is
answering about eth1's own NAPI list, which is empty. Both NAPI instances belong
to `eth->dummy_dev` (`mtk_eth_soc.c:5732-5733`), and a dummy netdev has no sysfs
directory for the attribute to appear in. There is no runtime switch for
threading on this path.

**The thread's time lands in two places at once.** `napi_threaded_poll_loop()`
runs the poll under bh-disabled - `local_bh_disable()` at `dev.c:7014`,
`__napi_poll()` at `7021`, `local_bh_enable()` at `7033` - so the same
microseconds appear as `softirq` in `/proc/stat` and as `stime` for the thread.
They are not additive. Measured, one clean window: per-task sampling attributed
7.69 s to `napi/mtk_eth-6` over 30 s while `/proc/stat` softirq for the
overlapping window was 7.28 s. That pair identifies the thread as the holder,
which is all it is good for; it does not quantify the cost, per 18.3.

**RPS backlog work for the local CPU happens inside that same thread.**
`dev.c:4919` skips raising `NET_RX_SOFTIRQ` when `sd->in_napi_threaded_poll` is
set, and `dev.c:7027-7030` dispatches pending RPS IPIs inside the bh-disabled
region before it ends. So RPS does not cleanly separate into its own accounting
bucket either.

**Receive is single-threaded.** Exactly two `netif_napi_add` calls in the whole
driver, one per direction, and no `netif_set_real_num_rx_queues` or
`num_rx_queues` anywhere in it - so no RSS and no second receive NAPI. RPS is the
only mechanism that gets CPU1 into this path at all, which makes the
packet-steering default a load-bearing choice rather than a tuning nicety.

**Pinning the interrupt does not pin the work.** `echo 1 >
/proc/irq/76/smp_affinity` fixes where the hard IRQ lands; the poll runs in a
schedulable thread the scheduler is free to migrate, and patch 702 exists
precisely so that it can. Stabilising where receive work happens means `taskset`
on the `napi/mtk_eth` thread, not on the IRQ.

So `eth->dummy_dev` is responsible for three separate constraints on this board:
no ifindex, so every ifindex-based BPF helper fails (16.2, re-verified in 18.7);
no sysfs, so NAPI threading cannot be controlled at runtime; and it owns the NAPI
instance the entire wired receive path runs inside.

### 18.5 What this changes, and what it does not

**#101 and #102 are unaffected.** They were decided by 16.2, 16.3 and 17.2, all
read from kernel source and none dependent on today's numbers. Every link in
those chains was re-read against 6.12.103 before this section was written - see
18.7, including one refinement that makes 16.2 stronger than it was.

**#114 closes as bounded by instrumentation**, not as answered.

**What is now better founded is narrower and more defensible than #102 was:
native XDP on `eth0` for flood absorption.** A static filter needs neither
`bpf_xdp_flow_lookup()` nor `ctx->ingress_ifindex`, which is exactly why
`xdp-filter` worked where a flow-aware program structurally cannot. Whether it is
worth shipping depends on a capacity number this session could not produce.

Sizing it needs a generator that can exceed the box's capacity, and the obvious
one cannot. **Measured: WSL2 is not a usable packet source for this.** Four
unpaced worker processes never cleared 150k pkt/s. Paced at 100k it delivered
99.9k, which says the cap sits between those two figures and nothing more.
Reasoned, not established: WSL2 traffic crosses a Hyper-V virtual switch with
NAT, where small-packet rates are known to be poor. Distinguishing the VM
boundary from Python's own per-packet cost takes one test - run the same unpaced
flood natively on Windows and see whether it clears 150k.

For whoever picks this up: 64-byte UDP occupies 130 bytes on the wire - a
106-byte frame, 4 bytes of FCS, and 20 bytes of preamble, SFD and inter-frame gap
- so gigabit line rate is **961,538 pkt/s** and the 2.5G WAN port is
**2,403,846 pkt/s**. A sizing run must offer more than the path under test can
absorb, or it measures the generator.

### 18.6 Operational notes for repeating this

- `xdp-filter` is on the image; no compiler and no object transfer needed.
  `xdp-filter status` gives exact per-action and per-port counters.
- **Attaching or detaching a program bounces the link.** `mtk_xdp_setup()` sets
  `need_update = !!eth->prog != !!prog` and then calls `mtk_stop(dev)` and
  `mtk_open(dev)` around the swap, so the bounce happens on the zero-to-one and
  one-to-zero transitions but not on a program replacement. `ip -d link show
  eth1` caught it as `NO-CARRIER ... state DOWN` immediately after a load. Allow
  several seconds of settle before opening a window.
- Use `/proc/net/dev` `rx_packets` for the packet count. ethtool's `rx_xdp_*`
  counters are cumulative and survive an unload, so a stale non-zero reading
  looks live while never advancing - which silently produced a window reporting
  zero packets.
- Sink the test flow at `type filter hook input priority 10`, or ICMP
  port-unreachable generation sits in the pass conditions and not the drop ones.
- Have the runner wait for traffic rather than relying on starting two sides in
  the right order. One run measured an idle link for four straight windows.
- Run detached over ssh, stop `irqbalance`, and read the output file only after
  the run finishes.

### 18.7 Re-verified against 6.12.103 before closing #101 and #102

Both tasks are being closed on source reading rather than measurement, so every
link was re-read in the build tree rather than trusted from an earlier session.

| Claim | Where | Status |
|---|---|---|
| The XDP rxq's dev is the dummy netdev, for both wired ports | `mtk_eth_soc.c:2115` `__xdp_rxq_info_reg(xdp_q, eth->dummy_dev, id, eth->rx_napi.napi_id, PAGE_SIZE)` | confirmed |
| A dummy netdev has ifindex 0 | `init_dummy_netdev_core()` at `dev.c:10699` sets only `reg_state = NETREG_DUMMY` and never assigns an ifindex; the sole assigners are `register_netdevice()` at `dev.c:10571-10574` and the netns-move path at `11683-11741`, and a dummy goes through neither | confirmed (was reasoned) |
| `ctx->ingress_ifindex` reads that dev | `filter.c:10246-10255` - `xdp_buff->rxq` then `xdp_rxq_info->dev` then `net_device->ifindex` | confirmed |
| The flowtable kfunc is keyed on the rxq's dev | `bpf_xdp_flow_lookup()` ends in `bpf_xdp_flow_tuple_lookup(xdp->rxq->dev, &tuple, proto)`; `nf_flowtable_by_dev()` at `nf_flow_table_xdp.c:27-33` keys on `unsigned long key = (unsigned long)dev` and matches `iter->net_device_addr` | confirmed, and stronger than 16.2 said |
| One program covers both wired ports | `mtk_xdp_setup()` does `rcu_replace_pointer(eth->prog, …)` - the pointer is on `struct mtk_eth`, not per-netdev | confirmed |
| Attach and detach bounce the link | `mtk_xdp_setup()` `mtk_stop(dev)` / `mtk_open(dev)` guarded by `need_update` | confirmed |
| Generic `XDP_REDIRECT` bypasses the qdisc | `xdp_do_generic_redirect()` at `filter.c:4628`, ifindex path: `skb->dev = fwd; generic_xdp_tx(skb, xdp_prog);` at `4653-4655`. `generic_xdp_tx()` at `dev.c:5242-5263` goes `netdev_core_pick_tx` then `HARD_TX_LOCK` then `netdev_start_xmit` with no qdisc | confirmed for `bpf_redirect()` |
| ditto for `bpf_redirect_map()` | the devmap case goes to `dev_map_generic_redirect()` at `filter.c:4600`, which lives in `kernel/bpf/devmap.c` | **not re-checked in this tree** |
| `do_xdp_generic` is exported | `dev.c:5301` `EXPORT_SYMBOL_GPL(do_xdp_generic)` | confirmed |

Two refinements worth carrying forward.

**16.2 is stronger than stated.** The flowtable is selected by the `net_device *`
**pointer**, not by ifindex. The tuple's own `.iifidx` comes from the
caller-supplied `fib_tuple->ifindex`, so a program *can* put a correct ifindex in
the tuple - and it still fails, because the flowtable it would be looked up in is
chosen from `xdp->rxq->dev`, which is `eth->dummy_dev` and is never inserted into
any flowtable. There is no way for an XDP program on the wired ports to reach the
flowtable, not even by hardcoding the right interface.

**17.2 is half re-verified.** The plain `bpf_redirect()` path provably bypasses
the qdisc in this tree. The `bpf_redirect_map()` path was read in an earlier
session and not re-read here; its call site is `filter.c:4600`. The conclusion
17.2 draws - that a wwan0 generic-XDP fastpath cannot be always-on alongside SQM
- stands on the verified half alone, since a fastpath would use one path or the
other and one is proven.
