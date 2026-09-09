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
| software flow offload (2026-09-07) | `kmod-nft-offload` — nft flowtable fast path; lever-OFF (firewall `flow_offloading '0'`). Interface-agnostic, so it shortcuts LAN↔wwan0 flows yet still hits the egress qdisc (cake keeps shaping). Verify cake interaction empirically before trusting | `x3000/config.common` |
| WAN GRO via gro_cells (2026-09-07) | `991` kernel patch: MBIM RX delivered through per-CPU NAPI + `napi_gro_receive` instead of per-datagram `netif_rx` — batches the ~21-datagram 32KB NTB bursts (the RM520N controller sets `mru_default=32768`), and makes `wwan0` threaded-NAPI real. Kill-switch: `ethtool -K wwan0 gro off`. **BENCH-FIRST**: iperf3 downlink CPU + latency-under-load A/B before trusting | `target/linux/mediatek/patches-6.12/991-net-wwan-mhi_wwan_mbim-gro-cells-rx.patch` |
| WAN XDP (2026-09-07, reworked 2026-09-09) | `992` kernel patch (applies after 991): `ndo_bpf` + per-datagram `do_xdp_generic()` on the MBIM RX path — the complete verdict set PASS / DROP / ABORTED / TX / REDIRECT. REDIRECT matters beyond redirection itself: every `xdp-loader load` of an AF_XDP program installs libxdp's `xsk_def_prog`, whose only verdict is `bpf_redirect_map()`, so refusing it refuses AF_XDP. The program sits on `link->xdp_prog`, never `dev->xdp_prog`, so `netif_elide_gro()` stays false and 991's GRO survives — attaching the same program with `xdpgeneric` instead measures 1.00x aggregation against 24.8x with it detached. Raw-IP link: programs see the IP header at offset 0, not an Ethernet header, and a redirect to an Ethernet device must prepend one with `bpf_xdp_adjust_head(ctx, -14)`. Inert with no program attached (one `rcu_dereference` per datagram). **BENCH-FIRST** | `target/linux/mediatek/patches-6.12/992-net-wwan-mhi_wwan_mbim-native-xdp.patch` |
| zram, kmod-only (2026-09-07) | `kmod-zram` — the module + its compression kmods; capability only, **no** `zram-swap`, **no** uci-default, so no swap is enabled at boot | `x3000/config.common` |
| eBPF userland | `tc-bpf` (tc-tiny unset), `libbpf`, `bpftool-full`, `xdp-loader`, `xdpdump` | `x3000/config.common` |
| cake-autorate prereqs | `bash`, `fping` (the script itself is dropped in post-flash) | `x3000/config.common` |
| WireGuard | `kmod-wireguard`, `wireguard-tools`, `luci-proto-wireguard` — inert until a wg interface exists | `x3000/config.common` |
| TCP / qdisc baseline | `net.core.default_qdisc=fq_codel`; `tcp_sack=1`, `tcp_dsack=1`; a commented opt-OUT to cubic (bbr stays default) | `x3000/files-common/etc/sysctl.d/{11,20,30}-*.conf` |
| harness fix | `prepare.sh` now composes `.config` + runs `defconfig` **after** `feeds install` (pure move of the block). At vjt's HEAD it ran before, so the first run on a fresh clone silently dropped every feed-provided package — his own quectel-5g-tools and wifi-dethrash-collector included | `x3000/prepare.sh` |

## What stays out, on purpose

* **Anything QModem** — no feed, no packages, no vendor `pcie_mhi`, no
  rmnet MTU hotplug (vendor-driver-specific; dead code on MBIM `wwan0`).
* **qosify, sqm-scripts, luci-app-sqm** — Phase-1 cake is hand-driven; see
  `x3000/docs/cake-wan.init` (reference script, NOT installed; lever off).
* **zram-swap** (the auto-mkswap/swapon package) and its uci-default — the
  `kmod-zram` module IS baked now (see table above), but nothing enables
  swap on boot; that stays a manual choice.
* **ply** (needs the ftrace stack; deferred as before).
* **Custom in-tree BPF programs** (`xdp_filter`, `tc_cake_mark`) — dropped
  2026-09-07 (recoverable from git history). The 991/992 kernel hooks and
  the full BPF/XDP/BTF platform stay; upstream `xdp-filter` (packages feed,
  not currently enabled) covers ingress filtering, and cake shapes fine
  without bespoke DSCP marking. Shipping bespoke `.o` plus a build-time LLVM
  toolchain wasn’t worth it for two lever-off utilities.
* `CONFIG_SCHED_DEBUG` — would expose the runtime
  `/sys/kernel/debug/sched/preempt` toggle; deps are already satisfied and
  it is introspection-only, but it was never baked/validated. Opt in with
  one line appended to the filogic fragment.
* Every HELD research item: mt76 bump, fullcone NAT, safexcel. (MHI-GRO
  graduated 2026-09-07: its mainline equivalent is the 991 gro_cells
  patch above — still bench-first.) Hardware flow offload (PPE/WED) stays off and is
  moot for the cellular WAN anyway (wwan0 is not an mtk_eth port).

Guard lines (`# CONFIG_PACKAGE_qosify is not set`, sqm, zram-swap, ply,
tc-tiny) sit at the very end of `config.common`; the composed `.config`
is common + `config.<variant>` + optional `.local`, and `config.public`
is empty, so nothing can re-select them behind the guards.

## Build

Build the **public** variant — vjt's `private` variant is his fleet image
(telegraf-full pushing to his metrics host, internal-CA expectations).

```sh
# fresh WSL clone of THIS branch — keep the qmodem build tree separate
git clone -b lean <your fork> ~/x3000-lean && cd ~/x3000-lean
./x3000/prepare.sh public
# gate before spending hours in make — expect 10 then 0:
grep -c '^CONFIG_PACKAGE_\(kmod-sched-cake\|tc-bpf\|xdp-loader\|fping\|kmod-wireguard\|luci-proto-wireguard\|quectel-5g-tools\|modemmanager\|kmod-nft-offload\|kmod-zram\)=y' .config
grep -c '^CONFIG_PACKAGE_\(qosify\|sqm-scripts\|luci-app-sqm\|zram-swap\|tc-tiny\)=y' .config
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

BBRv3 proof is build-side (OpenWrt strips `version=` from installed
modules): `strings build_dir/target-*/linux-mediatek_filogic/linux-6.12.103/net/ipv4/tcp_bbr.ko | grep version=` → `version=3`,
and `net/ipv4/tcp_bbr.c` in that build tree is 2407 lines with
`fast_ack_mode`.
