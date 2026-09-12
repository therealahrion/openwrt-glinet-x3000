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
| WAN GRO via gro_cells (2026-09-07) | `991` kernel patch: MBIM RX delivered through per-CPU NAPI + `napi_gro_receive` instead of per-datagram `netif_rx` — batches the ~21-datagram 32KB NTB bursts (the RM520N controller sets `mru_default=32768`), and gives `wwan0` real NAPI instances, which is what makes the per-device `threaded` control meaningful at all (it does not enable threading: `/sys/class/net/wwan0/threaded` reads 0 as shipped). Kill-switch: `ethtool -K wwan0 gro off`. **BENCH-FIRST**: iperf3 downlink CPU + latency-under-load A/B before trusting | `target/linux/mediatek/patches-6.12/991-net-wwan-mhi_wwan_mbim-gro-cells-rx.patch` |
| WAN XDP (2026-09-07, reworked 2026-09-09) | `992` kernel patch (applies after 991): `ndo_bpf` + per-datagram `do_xdp_generic()` on the MBIM RX path — the complete verdict set PASS / DROP / ABORTED / TX / REDIRECT. REDIRECT matters beyond redirection itself: every `xdp-loader load` of an AF_XDP program installs libxdp's `xsk_def_prog`, whose only verdict is `bpf_redirect_map()`, so refusing it refuses AF_XDP. The program sits on `link->xdp_prog`, never `dev->xdp_prog`, so `netif_elide_gro()` stays false and 991's GRO survives — attaching the same program with `xdpgeneric` instead measures 1.00x aggregation against 24.8x with it detached. Raw-IP link: programs see the IP header at offset 0, not an Ethernet header, and a redirect to an Ethernet device must prepend one with `bpf_xdp_adjust_head(ctx, -14)`. Inert with no program attached (one `rcu_dereference` per datagram). The private-pointer design was re-examined 2026-09-12 and is not a workaround: a hook inside `gro_cells_receive()` would double-execute, and a driver opt-out from the elision would run the program on the coalesced skb only, so this is the only shape that keeps both GRO and per-datagram XDP. `drivers/net/tun.c` does the same thing. See `xdp-methods-tested.md` section 22. **BENCH-FIRST** | `target/linux/mediatek/patches-6.12/992-net-wwan-mhi_wwan_mbim-native-xdp.patch` |
| MHI doorbell workaround (2026-09-10) | `993` kernel patch: adds the `mhi` module parameter `force_db_brst_disable`, which downgrades `MHI_DB_BRST_ENABLE` channels to `MHI_DB_BRST_DISABLE` in `parse_ch_cfg()` so the doorbell is written on every queued buffer. The patch defaults it off; the image turns it **on** at every boot from `files-common/etc/modules.d/mhi-doorbell` — not `/etc/modules.conf`, which is a ubox conffile that sysupgrade would then preserve against a later image. Without it the downlink deadlocks under sustained load, in practice past roughly 200 Mbps. Cost is two MMIO writes per queued buffer. The controlled reverse test — turn it off at matched throughput and see the stall return — has never been run, and the upstream draft names that as its weakness. Analysis in `downlink-stall.md`, operator steps in `wan-stall-runbook.md`, upstream draft in `993-upstream-report.md` | `target/linux/mediatek/patches-6.12/993-bus-mhi-host-optional-doorbell-write.patch`, `x3000/files-common/etc/modules.d/mhi-doorbell` |
| zram swap, ACTIVE (2026-09-11) | `kmod-zram` + `zram-swap`, enabled at boot by `92-zram-swap`. The real lever is `CONFIG_KERNEL_ZRAM_BACKEND_{LZO,LZ4,ZSTD}` — kernel 6.12 dropped zram's crypto-API path, and those symbols are what pull `kmod-lib-lzo`/`-lz4`/`-zstd` *and* let zram use them. LZO must be stated explicitly: enabling LZ4 or ZSTD cancels kmod-zram's `FORCE_LZO` auto-select. Compressor `lz4` and size 256 MiB, set by the same script. lz4 is faster than zstd at both ends, beats plain lzo, and is one of the three values LuCI's ZRam dropdown offers — `lzo-rle` is not, so it read as unset there. Size is a ceiling on the compressed store, not a reservation | `x3000/config.common`, `x3000/files-common/etc/uci-defaults/92-zram-swap` |
| ttyd defaults (2026-09-11) | `command` set to `/bin/login -f root` and `ipv6` on, in the anonymous `@ttyd[0]` section. ttyd binds `@lan` only, so anyone who can reach it is already inside the firewall and the extra login prompt only slows down pasting diagnostics. Marker-guarded, since `command` ships with a real value | `x3000/files-common/etc/uci-defaults/88-ttyd` |
| irqbalance (2026-09-11) | `irqbalance` + `luci-app-irqbalance`. No kernel symbols — it only writes `/proc/irq/*/smp_affinity`. Inert as packaged: `/etc/config/irqbalance` ships `enabled '0'` and the init returns early, so `93-irqbalance` flips it. Can pull against packet steering, which moves NAPI threads and `rps_cpus` on the same two cores | `x3000/config.common`, `x3000/files-common/etc/uci-defaults/93-irqbalance` |
| packet steering (2026-09-11) | `network.globals.packet_steering='2'` (LuCI "Enabled (all CPUs)") + `steering_flows='128'` ("Suggested: 128"). Set only when unset, so a LuCI choice survives. Not a measured win — see `xdp-methods-tested.md` 14.3/14.4 | `x3000/files-common/etc/uci-defaults/94-packet-steering` |
| Fantastic Packages feed (2026-09-11) | `fantastic-keyring` + `fantastic-packages-feeds` — key into `/etc/apk/keys/`, repo lines into `/etc/apk/repositories.d/customfeeds.list`, written at image build time. Makes the catalogue installable with `apk add`; nothing from it is built in. No "allow untrusted" needed, because the keyring is present | `x3000/config.common`, `x3000/custom-feeds.txt` |
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
  the toggle is what would tell us whether the two are related. See
  `x3000/docs/xdp-methods-tested.md` section 18.3.
* Every HELD research item: mt76 bump, fullcone NAT, safexcel. (MHI-GRO
  graduated 2026-09-07: its mainline equivalent is the 991 gro_cells
  patch above — still bench-first.) Hardware flow offload (PPE/WED) stays off and is
  moot for the cellular WAN anyway (wwan0 is not an mtk_eth port).

Guard lines (`# CONFIG_PACKAGE_qosify is not set`, sqm, ply,
tc-tiny) sit at the very end of `config.common`; the composed `.config`
is common + `config.<variant>` + optional `.local`, and `config.public`
is empty, so nothing can re-select them behind the guards.

## Known gaps in the shipped build

Not deliberate omissions - outstanding defects, listed so they are not
rediscovered. Found 2026-09-12 by checking upstream against the function 991
and 992 rewrite.

* **Three unfixed holes in `mhi_mbim_rx()`**, all present in 6.12.103 and so in
  every image built from it. Verified against the pristine release:
  * no bounds check, so an NDP entry with `dgram_offset + dgram_len > skb->len`
    is accepted;
  * `mhi_wwan_mbim.c:324` ignores the return of `skb_copy_bits()` after
    `skb_put()` has already sized the skb, so a failed copy delivers
    uninitialized kernel memory to the stack;
  * `mhi_wwan_mbim.c:354` takes `wNextNdpIndex` with no check that it advances,
    so an NDP pointing at itself or backwards loops forever in BH context.

  The source is the modem, not the network, so the probability is low and the
  impact is real. Upstream fixes were posted 2026-09-11 (Guanglei Zhu, v2 1/3
  and 2/3, `Fixes: aa730a9905b7`, `Cc: stable`) and were not merged as of
  2026-09-12. They restructure the same loop, so they will also conflict with
  991 and 992 on the next kernel bump. Do not fold them into 991 or 992.

* **991 still bundles an unrelated use-after-free fix** - the un-hash when
  `register_netdevice()` fails. Functionally fine here; it matters only for
  upstream, where it has to be its own `[PATCH net]`. See
  `992-upstream-submission.md` section 3.

## Build

Build the **public** variant — vjt's `private` variant is his fleet image
(telegraf-full pushing to his metrics host, internal-CA expectations).

```sh
# fresh WSL clone of THIS branch — keep the qmodem build tree separate
git clone -b lean <your fork> ~/x3000-lean && cd ~/x3000-lean
./x3000/prepare.sh public
# gate before spending hours in make — expect 15, then 0, then 4:
grep -c '^CONFIG_PACKAGE_\(kmod-sched-cake\|tc-bpf\|xdp-loader\|fping\|kmod-wireguard\|luci-proto-wireguard\|quectel-5g-tools\|modemmanager\|kmod-nft-offload\|kmod-zram\|zram-swap\|irqbalance\|luci-app-irqbalance\|fantastic-keyring\|fantastic-packages-feeds\)=y' .config
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
