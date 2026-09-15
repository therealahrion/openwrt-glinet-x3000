# Branch `lean` — vjt's stock modem stack + the optimization layer

This branch is **vjt/openwrt-25.12 at `a94508368f` (2026-07-16, "bake
kmod-tun") plus one commit** that adds only the optimization work and
leaves everything modem-related exactly as vjt ships it: ModemManager +
mainline MHI/MBIM on `wwan0`, his quectel-5g-tools (unpatched, so its
5g-watchdog is the link-recovery agent), his feeds, his patches.

Kernel is 6.12.103 (same tarball hash as the `openwrt-25.12` fork
branch) and vjt's patch stack differs from that branch only in
MTD/spinand/u-boot patches — none of the 16 kernel files BBRv3 touches —
so the zero-reject BBRv3 verification carries over intact.

## What the commit adds

| Bucket | What | Where |
|---|---|---|
| kernel / pacing | **BBRv3** (CachyOS `0002-bbr3` patch, md5 `c064ec8052acea6c9ada6280abd9f509`). vjt already ships `kmod-tcp-bbr=y` and bbr is already his boot default (the package's `12-tcp-bbr.conf`); the module simply becomes v3 | `target/linux/mediatek/patches-6.12/990-tcp-bbr3.patch` |
| kernel / CPU / threading | `CONFIG_PREEMPT_DYNAMIC=y` — boots `preempt=none` as before; adds the `preempt=voluntary|full` boot-arg lever (arm64 static-key path) | appended to `target/linux/mediatek/filogic/config-6.12` |
| kernel / verification | `CONFIG_IKCONFIG=y` + `CONFIG_IKCONFIG_PROC=y` — `zcat /proc/config.gz` on the live box | same fragment |
| eBPF / XDP / BTF platform | `KERNEL_CGROUP_BPF`, `BPF_EVENTS`, `KPROBES`, `PERF_EVENTS`, `XDP_SOCKETS`, `DEBUG_INFO` (+`_BTF`, `_BTF_MODULES`; `_REDUCED` off) | `x3000/config.common` (lean block at the end) |
| qdisc / classifier kmods | `kmod-sched-core`, `kmod-sched`, `kmod-sched-cake`, `kmod-sched-bpf`, `kmod-ifb`, `kmod-xdp-sockets-diag` — vermagic-locked, bake now or never | `x3000/config.common` |
| software flow offload (2026-09-07) | `kmod-nft-offload` — nft flowtable fast path. **Image default is on** — `files-common/etc/uci-defaults/96-flow-offload` sets firewall `flow_offloading '1'` on a fresh config, and only when the option is unset, so a deliberate `'0'` sticks (corrected 2026-09-12; this row said off, which was wrong and is exactly the error the note below describes); the running state is whatever LuCI last set, because `/etc/config/firewall` survives sysupgrade — read it, do not assume it (see "Levers that drift" below). Interface-agnostic, so it shortcuts LAN↔wwan0 flows yet still hits the egress qdisc (cake keeps shaping). Two things still unproven: the cake interaction, and any CPU saving at all — `time_squeeze` has read 0 in every window ever measured here. It is also **mutually exclusive with any per-packet netfilter rule** on the same traffic, which is what rules out NFQUEUE-style inspection while it is on | `x3000/config.common` |
| WAN GRO via gro_cells (2026-09-07) | `991` kernel patch: MBIM RX delivered through per-CPU NAPI + `napi_gro_receive` instead of per-datagram `netif_rx` — batches the ~21-datagram 32KB NTB bursts (the RM520N controller sets `mru_default=32768`), and gives `wwan0` real NAPI instances. Those NAPIs also made the per-device `threaded` control do something, which was a hazard rather than a feature: gro_cells queues are per-CPU and lockless, threaded NAPI drains them from unbound kthreads, and the toggle took the WAN down twice on 2026-09-14 (`xdp-methods-tested.md` 23.21). **996 closes that in core net** - gro_cells now declines to be threaded, so the control is inert on `wwan0` again and W0042 is no longer what it takes to make it safe. Kill-switch: `ethtool -K wwan0 gro off`. **BENCH-FIRST**: iperf3 downlink CPU + latency-under-load A/B before trusting | `target/linux/mediatek/patches-6.12/991-net-wwan-mhi_wwan_mbim-gro-cells-rx.patch` |
| WAN XDP (2026-09-07, reworked 2026-09-09) | `992` kernel patch (applies after 991): `ndo_bpf` + per-datagram `do_xdp_generic()` on the MBIM RX path — the complete verdict set PASS / DROP / ABORTED / TX / REDIRECT. REDIRECT matters beyond redirection itself: every `xdp-loader load` of an AF_XDP program installs libxdp's `xsk_def_prog`, whose only verdict is `bpf_redirect_map()`, so refusing it refuses AF_XDP. The program sits on `link->xdp_prog`, never `dev->xdp_prog`, so `netif_elide_gro()` stays false and 991's GRO survives — attaching the same program with `xdpgeneric` instead measures 1.00x aggregation against 24.8x with it detached. Raw-IP link: programs see the IP header at offset 0, not an Ethernet header, and a redirect to an Ethernet device must prepend one with `bpf_xdp_adjust_head(ctx, -14)`. Inert with no program attached (one `rcu_dereference` per datagram). The private-pointer design was re-examined 2026-09-12 and is not a workaround: a hook inside `gro_cells_receive()` would double-execute, and a driver opt-out from the elision would run the program on the coalesced skb only, so this is the only shape that keeps both GRO and per-datagram XDP. `drivers/net/tun.c` does the same thing. On the way back from `XDP_PASS` the hook re-anchors both headers and forces `PACKET_HOST`: `bpf_prog_run_generic_xdp()` reads bytes 0..5 and 12..13 as an Ethernet destination and ethertype (`dev.c:5095`, `:5128`), so on a raw-IP link a source rewrite, an IHL change or any `bpf_xdp_adjust_head()` makes it run `eth_type_trans()` over the IP header - after which IPv4 comes out `PACKET_MULTICAST`, IPv6 `PACKET_OTHERHOST`, and `ip_forward()` drops every forwarded datagram at `ip_forward.c:93` (23.28). See `xdp-methods-tested.md` section 22. **BENCH-FIRST** | `target/linux/mediatek/patches-6.12/992-net-wwan-mhi_wwan_mbim-native-xdp.patch` |
| MHI doorbell workaround (2026-09-10) | `993` kernel patch: adds the `mhi` module parameter `force_db_brst_disable`, which downgrades `MHI_DB_BRST_ENABLE` channels to `MHI_DB_BRST_DISABLE` in `parse_ch_cfg()` so the doorbell is written on every queued buffer. The patch defaults it off; the image turns it **on** at every boot from `files-common/etc/modules.d/mhi-doorbell` — not `/etc/modules.conf`, which is a ubox conffile that sysupgrade would then preserve against a later image. Without it the downlink deadlocks under sustained load, in practice past roughly 200 Mbps. Cost is two MMIO writes per queued buffer. The controlled reverse test — turn it off at matched throughput and see the stall return — has never been run, and the upstream draft names that as its weakness. Analysis in `downlink-stall.md`, operator steps in `wan-stall-runbook.md`, upstream draft in `993-upstream-report.md` | `target/linux/mediatek/patches-6.12/993-bus-mhi-host-optional-doorbell-write.patch`, `x3000/files-common/etc/modules.d/mhi-doorbell` |
| MBIM RX input validation (2026-09-12) | `995` kernel patch: three modem-supplied values in `mhi_mbim_rx()` that 6.12.103 uses unchecked — `wNextNdpIndex` with no requirement that the NDP chain advances (an NDP pointing at itself spins the loop forever in the MHI DL tasklet, so a hard lockup of that CPU), `wDatagramIndex`/`wDatagramLength` with no check that they fall inside `skb->len`, and a discarded `skb_copy_bits()` return after `skb_put()` has already sized the skb, which delivers whatever `netdev_alloc_skb()` handed back. Applies after 992 because it edits the loop 991 and 992 rewrite. **A local carry with an expiry date, not mine to submit**: fixes for two of the three were posted upstream 2026-09-11 by Guanglei Zhu, tagged against `aa730a9905b7` and copied to stable, and were not merged as of 2026-09-12. Drop this when they reach 6.12.y; the helper is deliberately named `mhi_mbim_rx_error()` rather than upstream's `mhi_mbim_rx_drop()` so the collision is loud | `target/linux/mediatek/patches-6.12/995-net-wwan-mhi_wwan_mbim-validate-ndp-chain-and-datagram-bounds.patch` |
| gro_cells threading opt-out (2026-09-15) | `996` kernel patch: a new `NAPI_STATE_NO_THREAD`, set by `gro_cells_init()` and honoured by `dev_set_threaded()` (both loops) and `netif_napi_add_weight()`, so a gro_cells NAPI is never handed an unbound kthread and never gets `NAPI_STATE_THREADED`. Those three are the only sites that can create the thread - `napi_enable()`'s arm needs `n->thread` non-NULL, so it closes on its own, and the two `state &= NAPIF_STATE_THREADED` sites (`dev.c:6266`, `:11818`) are reached only under `napi->poll == process_backlog`. Writing 1 to `/sys/class/net/wwan0/threaded` is inert again rather than fatal, and a mixed device still threads its driver-owned NAPIs. Core net only, no driver, no file shared with 991/992/993/995, so apply order between them does not matter. Upstream-shaped: splits into flag-then-user for submission. Numbered 996 because 994 is retired (22.7). See `xdp-methods-tested.md` 23.21 and 23.28 | `target/linux/mediatek/patches-6.12/996-net-gro_cells-opt-out-of-threaded-napi.patch` |
| forward-path walk, decline vs fail (2026-09-15) | `997` kernel patch: `dev_fill_forward_path()` (`dev.c:729`) turns any negative return from `ndo_fill_forward_path` into `return -1` and discards the walk, while a device with **no** callback falls through to `DEV_PATH_ETHERNET` and works. Those are the same statement. 997 makes `-EOPNOTSUPP` mean the second. **Only three functions implement the callback tree-wide and two return `-EOPNOTSUPP` legitimately** — `ppp_generic.c:1599` (multilink), `:1610` (any non-PPPoE channel type, L2TP included), and mac80211 when the driver has no `net_fill_forward_path` op. Three load-bearing details: `dev_fwd_path()` takes the stack slot *before* the callback runs so it must be given back; `ret` must be cleared because `nft_flow_offload.c:206` gates on `>= 0` and `mtk_ppe_offload.c:105-108` does `if (err) return err`; and it must `break` rather than `continue`, or it trips `WARN_ON_ONCE(last_dev == ctx.dev)`. Buys Wi-Fi coverage for W0038 — a bridged client can reach `XMIT_DIRECT`. Does **not** make `wwan0` a target: it has no Ethernet device beneath it to resolve down to. Core net only, no file shared with 991/992/993/995/996 | `target/linux/mediatek/patches-6.12/997-net-forward-path-decline-without-failing.patch` |
| /dev/mem for register reads (2026-09-15) | `CONFIG_DEVMEM=y` + `CONFIG_STRICT_DEVMEM=y` + `# CONFIG_IO_STRICT_DEVMEM is not set`, appended to the subtarget fragment. Stock OpenWrt carries `# CONFIG_DEVMEM is not set` (`generic/config-6.12:1405`), so nothing in userspace can reach a physical address at all: the char major is registered but the minor-1 node is never created (`drivers/char/mem.c:764`) and a hand-made node opens `-ENXIO` (`:723`). The subtarget layer overrides generic because `kconfig.pl` merges the two with `config_add(..., mod_plus=0)`, where the later file wins — verified by running this tree's own `scripts/kconfig.pl` over both fragments, which changes exactly these three symbols and nothing else. All three are load-bearing. `STRICT_DEVMEM=y` narrows the exposure to memory-mapped I/O, since `devmem_is_allowed()` returns 1 only when `!page_is_ram(pfn)` (`lib/devmem_is_allowed.c`), so kernel and process memory stay out of reach. Turning `IO_STRICT_DEVMEM` back off is what keeps a driver-claimed range readable, and `mtk_eth_soc` claims this entire window. Worth recording: the generic config's `CONFIG_IO_STRICT_DEVMEM=y` (`:2850`) was **inert** before this change, because it `depends on STRICT_DEVMEM` (`lib/Kconfig.debug:1886`) and that was off — enabling STRICT_DEVMEM is precisely what would have made it bite, which is why it is disabled in the same edit | appended to `target/linux/mediatek/filogic/config-6.12` |
| zram swap, ACTIVE (2026-09-11) | `kmod-zram` + `zram-swap`, enabled at boot by `92-zram-swap`. The real lever is `CONFIG_KERNEL_ZRAM_BACKEND_{LZO,LZ4,ZSTD}` — kernel 6.12 dropped zram's crypto-API path, and those symbols are what pull `kmod-lib-lzo`/`-lz4`/`-zstd` *and* let zram use them. LZO must be stated explicitly: enabling LZ4 or ZSTD cancels kmod-zram's `FORCE_LZO` auto-select. Compressor `lz4` and size 256 MiB, set by the same script. lz4 is faster than zstd at both ends, beats plain lzo, and is one of the three values LuCI's ZRam dropdown offers — `lzo-rle` is not, so it read as unset there. Size is a ceiling on the compressed store, not a reservation | `x3000/config.common`, `x3000/files-common/etc/uci-defaults/92-zram-swap` |
| ttyd defaults (2026-09-11) | `command` set to `/bin/login -f root` and `ipv6` on, in the anonymous `@ttyd[0]` section. ttyd binds `@lan` only, so anyone who can reach it is already inside the firewall and the extra login prompt only slows down pasting diagnostics. Marker-guarded, since `command` ships with a real value | `x3000/files-common/etc/uci-defaults/88-ttyd` |
| irqbalance (2026-09-11) | `irqbalance` + `luci-app-irqbalance`. No kernel symbols — it only writes `/proc/irq/*/smp_affinity`. Inert as packaged: `/etc/config/irqbalance` ships `enabled '0'` and the init returns early, so `93-irqbalance` flips it. Can pull against packet steering, which moves NAPI threads and `rps_cpus` on the same two cores | `x3000/config.common`, `x3000/files-common/etc/uci-defaults/93-irqbalance` |
| packet steering (2026-09-11) | `network.globals.packet_steering='2'` (LuCI "Enabled (all CPUs)") + `steering_flows='128'` ("Suggested: 128"). Set only when unset, so a LuCI choice survives. Not a measured win — see `xdp-methods-tested.md` 14.3/14.4 | `x3000/files-common/etc/uci-defaults/94-packet-steering` |
| Fantastic Packages feed (2026-09-11) | `fantastic-keyring` + `fantastic-packages-feeds` — key into `/etc/apk/keys/`, repo lines into `/etc/apk/repositories.d/customfeeds.list`, written at image build time. Makes the catalogue installable with `apk add`; nothing from it is built in. No "allow untrusted" needed, because the keyring is present | `x3000/config.common`, `x3000/custom-feeds.txt` |
| LuCI theme + compat layer (2026-09-13) | `luci-theme-argon` from `jerrykuku/luci-theme-argon` pinned to `v2.4.7` — the 25.12 luci feed carries only bootstrap, footstrap, material, openwrt and openwrt-2020, checked against `themes/` on that branch rather than assumed. **Nothing here sets the theme**: the package ships `/etc/uci-defaults/30_luci-theme-argon`, which writes `luci.main.mediaurlbase` once, guarded on `luci.themes.Argon` being absent, and sorts ahead of `30_luci-theme-bootstrap`, whose own write fires only when that option is unset — so Argon wins a fresh config, and afterwards neither script touches it, which is why a theme picked in LuCI survives the next sysupgrade. Same persistence the markers in `defaults.sh` give the rows above, but earned by the package's own guard, so adding a script here would be a duplicate. `luci-theme-bootstrap` stays in as the fallback, since `luci-base` ships `/etc/config/luci` pointing at it and a theme that fails to render leaves no way back through the UI. `luci-compat` is the pre-JS CBI/Lua form layer: nothing in the image needs it — on this feed only `luci-app-openvpn` depends on it — but most of the Fantastic catalogue above is still on the old API, and apk cannot add a missing LuCI runtime after flashing. Cost computed from the dependency closure, not guessed: `+luci-lua-runtime` names `luci-base`, `lua`, `luci-lib-base`, `-nixio`, `-ip`, `-jsonc`, `libubus-lua`, `liblucihttp-lua` and `ucode-mod-lua`, of which three were already here — `luci-base` and `lua` directly, and `libubus-lua` via `prometheus-node-exporter-lua`, whose DEPENDS carries it — so the layer adds eight packages. The theme is ucode-based with no `luasrc/`, so `luci.mk` attaches none of that to it, and it costs only itself: `USE_APK` is default y and `uclient-fetch` carries `PROVIDES:=@wget-any`, while `jsonfilter` is pulled unconditionally by `base-files`, so it is in every OpenWrt image | `x3000/config.common`, `x3000/custom-feeds.txt` |
| eBPF userland | `tc-bpf` (tc-tiny unset), `libbpf`, `bpftool-full`, `xdp-loader`, `xdpdump` | `x3000/config.common` |
| cake-autorate prereqs | `bash`, `fping` (the script itself is dropped in post-flash) | `x3000/config.common` |
| WireGuard | `kmod-wireguard`, `wireguard-tools`, `luci-proto-wireguard` — inert until a wg interface exists | `x3000/config.common` |
| TCP / qdisc baseline | `net.core.default_qdisc=fq_codel`; `tcp_sack=1`, `tcp_dsack=1`; a commented opt-OUT to cubic (bbr stays default) | `x3000/files-common/etc/sysctl.d/` — four fragments, of which `40-kptr-restrict.conf` belongs to the diagnostics bundle the repo-root README documents rather than to this row |
| harness fix | `prepare.sh` now composes `.config` + runs `defconfig` **after** `feeds install` (pure move of the block). At vjt's HEAD it ran before, so the first run on a fresh clone silently dropped every feed-provided package — his own quectel-5g-tools and wifi-dethrash-collector included | `x3000/prepare.sh` |

## What stays out, on purpose

* **Anything QModem** — no feed, no packages, no vendor `pcie_mhi`, no
  rmnet MTU hotplug (vendor-driver-specific; dead code on MBIM `wwan0`).
* **qosify, sqm-scripts, luci-app-sqm** — Phase-1 cake is hand-driven; see
  `x3000/docs/cake-wan.init` (reference script, NOT installed; lever off).
* **ply** (needs the ftrace stack; deferred as before).
* **Custom in-tree BPF programs** (`xdp_filter`, `tc_cake_mark`) — dropped
  2026-09-07 (recoverable from git history). The 991/992 kernel hooks and
  the full BPF/XDP/BTF platform stay; upstream `xdp-filter` (now enabled,
  `CONFIG_PACKAGE_xdp-filter=y`) covers ingress filtering, and cake shapes fine
  without bespoke DSCP marking. Shipping bespoke `.o` plus a build-time LLVM
  toolchain wasn’t worth it for two lever-off utilities.
* `CONFIG_SCHED_DEBUG` — would expose the runtime
  `/sys/kernel/debug/sched/preempt` toggle; deps are already satisfied and
  it is introspection-only, but it was never baked/validated. Opt in with
  one line appended to the filogic fragment. There is now a concrete reason
  to: `/proc/stat` does not conserve time on this box under load, and this
  build carries `PREEMPT_DYNAMIC` where stock OpenWrt is `PREEMPTION=n`, so
  the toggle is what would tell me whether the two are related. See
  `x3000/docs/xdp-methods-tested.md` section 18.3.
* Every HELD research item: mt76 bump, fullcone NAT, safexcel. (MHI-GRO
  graduated 2026-09-07: its mainline equivalent is the 991 gro_cells
  patch above — still bench-first.)
* **Hardware flow offload for the cellular WAN — closed, not merely off.**
  This entry used to read "moot anyway (wwan0 is not an mtk_eth port)",
  which is one of the two barriers stated as if it were the whole story;
  corrected 2026-09-15. A `struct mtk_foe_entry` carries **no
  ingress-derived field at all**, and `mtk_flow_is_valid_idev()` failing
  is not an error path — no `else`, no `return`. What actually blocks it:
  the egress must be an mtk netdev (`mtk_ppe_offload.c:224-231`), *and*
  the ingress must physically enter through a GMAC or WDMA, which is a
  hardware property never written as a software check anywhere in the
  driver. **The practical consequence is a trap**: the downlink direction
  is accepted and committed as a real bound FOE entry that forwards zero
  packets — see the verification table above and instrument M14.
* **WED cannot see the modem, and TOPS is an MT7988-only block.** WED does
  not accept packets; it drives the client's WPDMA ring registers
  (`mtk_wed.c:1222-1252`) and pre-writes an 802.11 TXWI into every buffer
  (`mt7915/mac.c:816-837`). On this board its single unit is AXI-bound to
  the on-SoC radio while the modem is on PCIe. MediaTek's generic 5-tuple
  engine (TOPS/NPU + PCE) is real and is not a NETSYS-v3 feature as I
  first wrote: MT7987 is v3, has `mtk_rx_dma_v2` and therefore `rxd6`, and
  still declares no `tops`/`npu`/`pce` node. It appears on one Filogic
  part in four. Tracked by the part, not the generation.
  `xdp-methods-tested.md` sections 24.7 to 24.9.

Guard lines (`# CONFIG_PACKAGE_qosify is not set`, sqm, ply,
tc-tiny) sit at the very end of `config.common`; the composed `.config`
is common + `config.<variant>` + optional `.local`, and `config.public`
is empty, so nothing can re-select them behind the guards.

## Known gaps in the shipped build

Not deliberate omissions - outstanding defects, listed so they are not
rediscovered. Found 2026-09-12 by checking upstream against the function 991
and 992 rewrite.

* **Three holes in `mhi_mbim_rx()` — closed by 995, flashed and verified on
  hardware 2026-09-12.** See the table above. They are in 6.12.103 and therefore
  in any image built from it without that patch. The source of all three is the
  modem rather than the network, so the probability is low and the impact is not:
  one of them is an endless loop in softirq context.

  Verified in the running kernel rather than inferred from the build: the
  installed `mhi_wwan_mbim.ko` contains all three message strings the patch adds,
  and `dmesg` shows none of the three paths firing, which is the correct result on
  a healthy modem. Re-check after any flash with
  `for s in 'NDP chain does not advance' 'outside the' 'datagram copy failed'; do
  grep -ac "$s" /lib/modules/$(uname -r)/mhi_wwan_mbim.ko; done` — expect three
  non-zero counts.

  Two points that outlive the fix. The upstream versions restructure the same
  loop, so **they will conflict with 991, 992 and 995 on the next kernel bump** —
  expect to rebase all three, and drop 995 once its content arrives through
  stable. And the lesson that found them: the holes had been sitting in the
  exact function this project spent days rewriting, and nothing turned them up
  until upstream's own recent activity on that file was checked. Read what
  upstream is doing to the code being patched.

* **991 still bundles an unrelated use-after-free fix** - the un-hash when
  `register_netdevice()` fails. Functionally fine here; it matters only for
  upstream, where it has to be its own `[PATCH net]`. See
  `992-upstream-submission.md` section 3.

## Levers that drift

`/etc/config/*` survives sysupgrade, so for anything set by a `uci-defaults`
script the image default stops describing the board the moment someone changes it
in LuCI. Nothing in these docs used to say which of the two was being described,
and that went wrong once already: flow offload was documented as dormant while the
flowtable was installed on `br-lan`, `eth0` and `wwan0` with a third of live
forwarded flows in `OFFLOAD` state. Read the board, do not trust the row.

**`x3000/docs/boxstate.sh` reads every lever in this table in one pass**, plus
the flowtable device list, TCP congestion control and ECN/SACK, RPS and XPS
masks per interface, the 464XLAT topology and zram. It is the command to run
first; the per-lever commands below are the fallback when only one answer is
wanted.

```sh
sh /tmp/boxstate.sh            # the whole report
sh /tmp/boxstate.sh mix 30     # family split over a 30-second window
```

| lever | image default | read the running state with |
|---|---|---|
| software flow offload | on | `uci -q get firewall.@defaults[0].flow_offloading`, then `nft list ruleset \| grep -c 'flow add'` |
| flowtable device list | `br-lan`, `eth0`, `wwan0` — fw4 builds it from each zone's networks, and a bridge *port* is not a network, so `eth1`, `phy0-ap0` and `phy1-ap0` are absent | `sh x3000/docs/flowtable-ports.sh` — adding them takes a wired client from 0 to 100% `XMIT_DIRECT`, which is what W0038 needs; `add` is in-memory only and `fw4 restart` undoes it. Making it persist is W0039. See `xdp-methods-tested.md` 23.17 |
| packet steering / RPS | `2` and `128` | `uci -q get network.globals.packet_steering; uci -q get network.globals.steering_flows` |
| irqbalance | enabled | `/etc/init.d/irqbalance enabled && echo on` |
| zram | `lz4`, 256 MiB | `uci -q get zram.@zram[0].zram_comp_algo; free -m \| grep -i swap` |
| ttyd command | `/bin/login -f root` | `uci -q get ttyd.@ttyd[0].command` |
| MHI doorbell (993) | on, via `modules.d` | `cat /sys/module/mhi/parameters/force_db_brst_disable` |
| GRO on `wwan0` (991) | actually aggregating, not merely flagged | `ethtool -k wwan0` reports `on` on **any** netdev — `register_netdevice()` sets `NETIF_F_GRO` for every device at `dev.c:10575`, so the bit says nothing about whether GRO runs. Use `BOXSTATE_LIB=1 . /tmp/boxstate.sh; bs_gro_effective wwan0`, which also tests for a generic-mode XDP program eliding it (`xdp-methods-tested.md` 23.24) |
| PPE hardware offload of WAN traffic | **never** — and the debugfs will say otherwise | `/sys/kernel/debug/mtk_ppe/entries` shows a **bound** entry for the downlink direction of every modem flow, forwarding zero packets. The two directions are two independent FOE entries and one succeeding is enough; the downlink passes every software check and commits, but modem-originated packets never traverse the frame engine, so the entry can never be hit. Read the per-entry packet counters, never the bind state — `xdp-methods-tested.md` 24.9, instrument M14 |
| `netdev_max_backlog` | 1000 | `cat /proc/sys/net/core/netdev_max_backlog` |
| WAN shaper | none — `cake-wan.init` is a reference script, not installed | `tc qdisc show dev wwan0` — measured absent 2026-09-14, and the latency that costs is entry #5 of the field log in `qos-latency-research.md` |
| TCP congestion control | `bbr`, set by the `kmod-tcp-bbr` package's own `12-tcp-bbr.conf`, not by this tree; 990 makes that module v3, and this tree's `30-tcp-bbr.conf` is a commented-out opt-out to cubic | `sysctl net.ipv4.tcp_congestion_control` |
| `default_qdisc` | `fq_codel` | `sysctl net.core.default_qdisc` |
| LuCI theme | Argon | `uci -q get luci.main.mediaurlbase` — `/luci-static/argon` unless changed |

## On-box scripts

Four scripts in `x3000/docs/`. None is copied into the image — they are pulled
or pasted onto a running box — and since 2026-09-14 the other three source
`boxstate.sh` as a shell library rather than carrying their own copies of the
same readers.

| script | what it does |
|---|---|
| `boxstate.sh` | report **and** library. `BOXSTATE_LIB=1 . boxstate.sh` exports `bs_*` readers, `bs_require_*` gates and `bs_set_*` setters with an undo log |
| `xdp-ft-wwan.sh` | the W0038 flowtable XDP harness — `check \| probe \| dryrun \| status \| off`. Verifies the BPF object against a committed sha256 before loading it |
| `verify-992a.sh` | the 992 XDP hook verifier, eleven steps, PASS/FAIL tally |
| `gro-backlog-ab.sh` | GRO and `netdev_max_backlog` A/B, with `--baseline` for one window that changes nothing |
| `flowtable-ports.sh` | puts the bridge ports into the flowtable so a forwarded flow can reach `XMIT_DIRECT`, and attributes offloaded flows to the port their client is on. In-memory only; `fw4 restart` undoes it |
| `wifi-encap.sh` | toggles 802.3 encap offload on the Wi-Fi vifs via a monitor interface, which is what decides whether a Wi-Fi client can reach `XMIT_DIRECT`, and A/Bs what that costs. Diagnostic lever; the real fix is W0040 |
| `wifiload.py` | runs on a *wired* PC, not the router. Serves an endless stream plus a page that discards it, so a Wi-Fi client can be saturated without the WAN as the bottleneck and without writing to its storage |

Three rules the library exists to enforce, each of which was a bug before it was
a rule:

- **Readers exit 0, always.** A reader returning non-zero aborts its caller under
  `set -e` before any output, which reads as the script producing nothing rather
  than as a failed read. Questions (`bs_have`, `bs_ft_has`, `bs_zram_active`)
  keep their status; readers do not.
- **A gate that cannot verify says so.** The hardware-offload gate used to report
  `ok` when `uci` was unreadable — a gate passing because it was never tested. It
  now reports UNVERIFIED.
- **Every setter logs its undo.** `bs_set_sysctl`, `bs_set_sysfs` and `bs_set_gro`
  append the previous value to `$BS_UNDO`, and `bs_restore` replays it, so a
  script that dies mid-window still leaves the box as it found it.

## Work queue, easiest to hardest

The task list prefixes every open item with a tier so it reads in difficulty
order. The point is that T1 to T3 can be picked up at any time while T4 needs a
scheduled session, so they should not be interleaved when planning.

* **T1** — desk work. No router, no build. Docs, patch authoring, script edits.
* **T2** — one command on a running box.
* **T3** — needs a build and a flash.
* **T4** — needs the LAN load rig: traffic driven from a PC so the router is only
  routing, which is both the realistic path and the only way to measure without
  the generator competing for CPU. Tabled 2026-09-12.
* **T5** — long or externally gated: waiting on a stall to happen, on a net-next
  rebase, or on an upstream decision.

## Build

Build the **public** variant — vjt's `private` variant is his fleet image
(telegraf-full pushing to his metrics host, internal-CA expectations).

```sh
# fresh WSL clone of THIS branch — keep the qmodem build tree separate
git clone -b lean <fork url> ~/x3000-lean && cd ~/x3000-lean
./x3000/prepare.sh public
# gate before spending hours in make — expect 17, then 0, then 4:
grep -c '^CONFIG_PACKAGE_\(kmod-sched-cake\|tc-bpf\|xdp-loader\|fping\|kmod-wireguard\|luci-proto-wireguard\|quectel-5g-tools\|modemmanager\|kmod-nft-offload\|kmod-zram\|zram-swap\|irqbalance\|luci-app-irqbalance\|fantastic-keyring\|fantastic-packages-feeds\|luci-compat\|luci-theme-argon\)=y' .config
grep -c '^CONFIG_PACKAGE_\(qosify\|sqm-scripts\|luci-app-sqm\|tc-tiny\)=y' .config
grep -c '^CONFIG_KERNEL_ZRAM_\(BACKEND_LZO\|BACKEND_LZ4\|BACKEND_ZSTD\|DEF_COMP_LZORLE\)=y' .config
make -j$(nproc)            # or ./x3000/build.sh public → bin-x3000-public/
```

Known-benign: `feeds install -a` prints `WARNING: Not overriding core
package 'adb'` — vjt's android-tools feed carries an `adb` that shadows
OpenWrt 25.12's base `package/utils/adb`; scripts/feeds skips the feed copy
by design and the base one builds. vjt has built with this all along.

## Post-flash proof

```sh
zcat /proc/config.gz | grep -E 'PREEMPT_DYNAMIC|IKCONFIG=|DEBUG_INFO_BTF=|BPF_SYSCALL'
sysctl net.core.default_qdisc net.ipv4.tcp_congestion_control net.ipv4.tcp_sack
ls /lib/modules/$(uname -r)/ | grep -E 'sch_cake|cls_bpf|ifb|wireguard|tcp_bbr'
bpftool version && xdp-loader --help >/dev/null && echo xdp-ok
```

BBRv3 proof, build-side (OpenWrt sets `CONFIG_MODULE_STRIPPED=y`, so the
installed module carries no `version=`):
`strings build_dir/target-*/linux-mediatek_filogic/linux-6.12.103/net/ipv4/tcp_bbr.ko | grep version=`
→ `version=3`, and `net/ipv4/tcp_bbr.c` in that build tree is 2407 lines with
`fast_ack_mode`.

There is also an on-box proof, which is better because it reads the running
kernel — the BTF platform makes the struct layout visible:

```sh
bpftool btf dump file /sys/kernel/btf/tcp_bbr format raw | grep -E 'bw_hi|bw_probe_up_cnt|ecn_alpha|plb'
```

v3 fields (`bw_hi[2]`, `bw_lo`, `inflight_hi`/`_lo`, `bw_probe_up_cnt`,
`ecn_alpha`, `struct tcp_plb_state plb`) are present and v1's are gone
(`struct minmax bw`, `rtt_cnt`, `lt_*`, `packet_conservation`). Recorded in
`xdp-methods-tested.md` section 20.2.

Run on 2026-09-13, on the flash carrying the quilt-regenerated patch set, and both
halves held. `net.ipv4.tcp_congestion_control` read `bbr`, `lsmod` showed `tcp_bbr`
loaded with 20 references, and the BTF dump listed `undo_bw_lo`,
`undo_inflight_lo`/`_hi`, `bw_lo`, `bw_hi`, `inflight_lo`/`_hi`, `bw_probe_up_cnt`,
`ecn_alpha` as a 9-bit bitfield, and `plb`.

The second grep is the half that actually proves it, and the easy one to skip:
searching the same dump for `lt_bw`, `lt_rtt_cnt`, `packet_conservation` and
`rtt_cnt` printed nothing. Present-v3-fields alone would not rule out a hybrid; the
empty result does. Run both, and treat a non-empty second grep as a failure even if
the first looks right.
