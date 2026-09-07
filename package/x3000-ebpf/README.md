# x3000/ebpf — eBPF/XDP across the four paths, honestly

Two programs + loaders covering every attach point this box has, at the
layer each one can actually reach. **Lever-off:** nothing loads or
attaches at boot; the scripts are the levers. Both objects are
**compiled with `-Werror` and accepted by the in-kernel BPF verifier**
before shipping (see "Verification").

## Offloading vocabulary, mapped to reality on this box

"XDP offload" means three different things; only some exist here:

- **Hardware offload** (`xdpoffload`, program on the NIC silicon):
  mainline Linux supports this in **one** driver family (Netronome NFP).
  `mtk_eth_soc`, `mt76`, and `mhi_wwan_mbim` have **no** `XDP_SETUP_PROG_HW`
  path (verified in v6.12 source). Not buildable here by anyone.
- **Native / driver mode** (`xdpdrv`, program in the driver's RX poll):
  this is our "native." eth0/eth1 have it stock; wwan0 gets it via the
  `992` patch. This is software, running at the earliest driver point.
- **Generic / SKB mode** (`xdpgeneric`, after skb alloc): the fallback,
  little benefit. The only mode wireless LAN can use.

"Fast forwarding" also splits:

- **XDP_REDIRECT** (NIC→NIC stack bypass): **bypasses the qdisc, so it
  bypasses cake, and does no NAT.** Wrong for a NAT gateway whose whole
  point is shaping. Not built for the WAN — `992` implements PASS/DROP/TX
  but deliberately **not** REDIRECT.
- **The correct NAT fast path** is the nftables **software flowtable**
  (`kmod-nft-offload`, already baked): it shortcuts conntrack for
  established flows yet re-transmits through `dev_queue_xmit`, so cake
  still shapes. That's the offload your forwarded traffic actually uses.

## The matrix, as built

| Path | Interface | XDP native? | What runs here |
|---|---|---|---|
| Ethernet WAN | `eth0` | yes (stock mtk_eth) | `xdp_filter` (idle port; ingress guard for a future wired WAN) |
| Ethernet LAN | `eth1` | yes (stock mtk_eth) | `xdp_filter` (faces your own clients — rarely a useful drop point) |
| Wireless WAN | `wwan0` | **yes, via `992`** | `xdp_filter` (L2/L3/L4 ingress filter) + `tc_cake_mark` (egress DSCP → cake tins) |
| Wireless LAN | `phy0-ap0` … | no (mac80211) | `xdp_filter` generic-mode only; wifi latency lever is AQL, not XDP |

Native XDP on mac80211 would mean rewriting its RX pipeline (A-MPDU
reassembly, decrypt offload, vif demux) — upstream-scale, out of scope.

## Programs

**`xdp_filter.c`** (XDP ingress, L2/L3/L4) — one object for every attach
point; per-interface framing from `mode_map` by ifindex (eth vs raw-IP).
Per-CPU pass/drop counters, drop-by-source (`block4`/`block6`), and
drop-by-dest-port (`portblock`). On `wwan0` each MBIM datagram is copied
out of the shared NTB before the program runs, so the win is the
earliest drop/filter point, not zero-copy line rate.

**`tc_cake_mark.c`** (tc clsact egress, L3/L4) — the cake-cooperative
classifier. Runs before the root qdisc, so it only sets DSCP; cake still
shapes. Marks by dest port (`port_dscp`) or proto default into cake's
diffserv tins. **Marking correctness (checksum fixups) is a runtime
concern the verifier cannot check — bench before trusting.**

## Build (in-tree — all-inclusive)

This is an OpenWrt package (`package/x3000-ebpf`). It compiles both
programs during the normal image build and bakes them in — no host
Makefile, no scp. Just select it (already `=y` in `x3000/config.common`)
and build the image. To build only this package while iterating:

```sh
make package/x3000-ebpf/{clean,compile} V=s
```

Objects land at `/lib/bpf/{xdp_filter,tc_cake_mark}.o`; loaders at
`/usr/sbin/x3000-xdp` and `/usr/sbin/x3000-tc-cake`.

## Use (router)

```sh
# XDP ingress filter
x3000-xdp load
x3000-xdp attach wwan0 rawip        # native, needs 992 in the kernel
x3000-xdp attach eth0 eth           # native
x3000-xdp attach phy0-ap0 eth generic
x3000-xdp block4 203.0.113.7
x3000-xdp block-port 23
x3000-xdp stats
x3000-xdp unload

# tc egress DSCP classifier (pairs with cake on the WAN)
x3000-tc-cake load
x3000-tc-cake attach wwan0 rawip
x3000-tc-cake mark 3074 46          # e.g. game port -> EF
x3000-tc-cake unload
```

Confirm native attach: `bpftool net show` — `driver` = native,
`generic` = SKB fallback; `ip -d link show dev <if>` shows the prog id.

## Verification (what was actually checked, and what wasn't)

Done in-cloud before shipping, on a 6.18 kernel (a superset of your
6.12): both `.c` compile with `-Werror -target bpf`, and both objects
load through libbpf's `bpf_object__load()` — i.e. the **real in-kernel
verifier accepts them** (memory-safety, bounded loops, valid map
access). The kernel-side `991`/`992` APIs were confirmed present in
v6.12 source with matching signatures.

NOT checked here (needs your hardware — bench-first, like everything in
this tree): that the programs do the right thing on live traffic, that
`tc_cake_mark`'s DSCP/checksum rewrites are correct on the wire, that
`992` attaches in `driver` mode on the real modem, and the CPU/latency
A/B that decides whether any of it stays on.
