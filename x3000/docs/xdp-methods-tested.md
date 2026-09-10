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
flow is software-offloaded and nothing else is possible.** Setting the dropdown
to Hardware is not harmful - it just has nothing to accelerate until a wired WAN
or LAN-to-LAN flow appears.

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

Before turning it on, note what it would buy. `mtk_wed_setup_tc_block()` binds
only `FLOW_BLOCK_BINDER_TYPE_CLSACT_INGRESS`, and `mtk_wed_flow_add()` /
`mtk_wed_flow_remove()` are driven by PPE flow entries - WED accelerates flows
that PPE has already offloaded. Per section 10.1, PPE cannot carry `wwan0`. So on
this router WED would only accelerate wireless traffic to and from the wired
ports, which is not the path anyone here uses. Enabling it is one line -
`options mt7915e wed_enable=1` in `/etc/modules.conf` - but it should be measured,
not assumed, and it changes the wireless RX ring setup.
