![OpenWrt logo](include/logo.png)

# This is a fork of OpenWrt

This branch (`openwrt-25.12`) carries the patches and build configuration
needed to produce a working image for the **GL.iNet GL-X3000 (Spitz AX)**
with its **Quectel RM520N-GL 5G modem** running on the mainline
`mhi_pci_generic` + `mhi_wwan_mbim` stack, with ModemManager owning the
data plane.

This is [therealahrion's fork](https://github.com/therealahrion/openwrt-glinet-x3000)
of [vjt/openwrt-glinet-x3000](https://github.com/vjt/openwrt-glinet-x3000).
It keeps vjt's tree and modem stack as they are and adds a lean
optimization layer on top: six patches, a set of kernel build options, and
the packages and first-boot defaults that go with them — all of it listed
under **[Patches and Enhancements](#patches-and-enhancements)** below, and
nothing else. What, why and how to verify:
[`x3000/docs/lean-overlay.md`](x3000/docs/lean-overlay.md). Images build
from the [Build X3000 image workflow](../../actions/workflows/x3000-image.yml)
(pushing an `x3000-rN` tag drafts a prerelease with the sysupgrade image).

**vjt's pre-built images** are on his
[**releases page**](https://github.com/vjt/openwrt-glinet-x3000/releases)
— the `jeeves-rN` builds are his stock tree without this overlay. Flash
`...-squashfs-sysupgrade.bin` (factory image is rejected by stock
GL.iNet U-Boot; sysupgrade is the only path in).

If you'd rather build the image yourself — including a private variant
with your own internal CA, custom apk feed, or extra packages baked
in — **read [`x3000/README.md`](x3000/README.md)**. It documents what's
different from a stock OpenWrt build, the modem fixes vjt's fork already
carries, the build prerequisites, the public/private variant split, and
the post-flash modem configuration. The whole build comes down to:

```
git clone https://github.com/therealahrion/openwrt-glinet-x3000.git
cd openwrt-glinet-x3000
./x3000/build.sh public          # or `private` with your own overlay
```

## Patches and Enhancements

Everything this fork adds that neither vjt's tree nor upstream OpenWrt has.
**My Patches** is what I wrote, **Additional Patches** is what I carried in
from somewhere else, and **Enhancements** is the rest: kernel build options,
packages and first-boot defaults, grouped by what they give the box rather
than listed symbol by symbol. The modem-enablement patches and package
choices vjt's fork already has are a separate set, described in
[`x3000/README.md`](x3000/README.md). Where each of these sits in the build
and how to read its state on a running router:
[`x3000/docs/lean-overlay.md`](x3000/docs/lean-overlay.md).

### My Patches

* **991 — modem receive through gro_cells**
  `target/linux/mediatek/patches-6.12/991-net-wwan-mhi_wwan_mbim-gro-cells-rx.patch`

  <pre>
  Description:    The modem hands the host one bundle carrying many packets
                  at a time, and the stock driver pushes each one up the
                  stack separately. This routes them through gro_cells, the
                  mechanism tunnel drivers use, so the kernel merges them
                  and works on batches.
  Benefit(s):     Far less per-packet work on a two-core router, which is
                  what limits 5G downlink speed on this box.
  Impact(s):      Gives wwan0 real NAPI contexts, so "ethtool -K wwan0 gro
                  off" and the per-device threaded switch start working.
                  Nothing outside the MBIM receive path changes.
  Limitation(s):  Downlink only; the upload side is untouched. Packets have
                  to arrive close together for there to be anything to
                  merge, so it does little at low rates.
  Attribution(s): Mine, written for this fork. Background:
                      - <a href="x3000/docs/xdp-methods-tested.md">x3000/docs/xdp-methods-tested.md</a>
  </pre>

* **992 — XDP on the modem interface**
  `target/linux/mediatek/patches-6.12/992-net-wwan-mhi_wwan_mbim-native-xdp.patch`

  <pre>
  Description:    Gives the modem's receive path its own XDP hook, so eBPF
                  programs attach to wwan0 the way they would to a normal
                  network card and see each packet before the rest of the
                  stack does.
  Benefit(s):     Filtering, sampling and redirect on the WAN side, AF_XDP
                  included, without giving up the batching 991 adds. The
                  kernel's fallback way of attaching XDP here switched that
                  batching off, so it used to be one or the other.
  Impact(s):      Owning ndo_bpf makes driver mode the default attach mode
                  for wwan0, so "ip link set dev wwan0 xdp ..." lands here.
                  Detaching a generic attach needs "xdpgeneric off"; plain
                  "xdp off" is a silent no-op.
  Limitation(s):  Needs 991. wwan0 is a raw-IP link, so a program written
                  against an Ethernet header misreads the first bytes of
                  the source address as an EtherType.
  Attribution(s): Mine, written for this fork. The same-shaped hook in the
                  in-tree tun driver is the precedent. Background:
                      - <a href="x3000/docs/xdp-methods-tested.md">x3000/docs/xdp-methods-tested.md</a>
  </pre>

* **993 — MHI doorbell writes**
  `target/linux/mediatek/patches-6.12/993-bus-mhi-host-optional-doorbell-write.patch`

  <pre>
  Description:    Adds a switch to the MHI bus driver that makes the host
                  tell the modem about every receive buffer it queues,
                  rather than only when the modem asks to be told.
  Benefit(s):     Works around a downlink that can stop dead under
                  sustained load and stay stopped until the modem is
                  re-probed.
  Impact(s):      On at boot, from
                  x3000/files-common/etc/modules.d/mhi-doorbell. Costs one
                  register write per queued buffer.
  Limitation(s):  A workaround, not a fix for the cause. The value is read
                  while the channels are configured, so changing it needs
                  an unbind/bind of the modem rather than just a write, and
                  a reboot returns to the image default.
  Attribution(s): Mine, written for this fork. Capture, analysis and the
                  draft report for the MHI maintainers:
                      - <a href="x3000/docs/downlink-stall.md">x3000/docs/downlink-stall.md</a>
                      - <a href="x3000/docs/993-upstream-report.md">x3000/docs/993-upstream-report.md</a>
  </pre>

* **firewall4 — flow offload on a modem WAN**
  `package/network/config/firewall4/patches/001-flowtable-fall-back-to-l3-device.patch`

  <pre>
  Description:    A one-line fix to OpenWrt's firewall so an interface that
                  only ever gets an IP-level device, which is what
                  ModemManager produces, can still be put into the flow
                  table.
  Benefit(s):     wwan0 joins the flow table, so software flow offload
                  actually covers WAN traffic instead of the LAN side only.
                  Without it the table looks healthy while offloading
                  nothing that matters.
  Impact(s):      Only ever adds devices that previously resolved to
                  nothing. Where a lower-level device exists it still wins,
                  so PPPoE and VLAN setups resolve exactly as before.
  Limitation(s):  Flow offload is a separate switch and has to be on for
                  this to do anything. Offloaded flows skip the rest of
                  netfilter, so it cannot be combined with a per-packet
                  rule on the same traffic.
  Attribution(s): Mine, written for this fork. Background, section 10.3:
                      - <a href="x3000/docs/xdp-methods-tested.md">x3000/docs/xdp-methods-tested.md</a>
  </pre>

### Additional Patches

* **990 — BBRv3**
  `target/linux/mediatek/patches-6.12/990-tcp-bbr3.patch`

  <pre>
  Description:    Replaces the kernel's BBR v1 congestion control with
                  BBRv3.
  Benefit(s):     BBR is already this image's default sender, so every
                  connection the router opens picks up v3's revised loss
                  and ECN handling. Nothing to turn on.
  Impact(s):      Replaces the in-tree tcp_bbr rather than adding a second
                  module, so kmod-tcp-bbr simply becomes v3.
  Limitation(s):  A router cannot choose congestion control for traffic it
                  forwards, so this reaches only connections the router
                  itself opens, never a LAN client's. BBRv3 is still not in
                  the mainline kernel.
  Attribution(s): Peter Jung's BBRv3 patch as carried by CachyOS, which in
                  turn tracks Google's BBRv3 branch:
                      - <a href="https://github.com/CachyOS/kernel-patches/blob/master/6.12/0002-bbr3.patch">CachyOS kernel-patches: 6.12/0002-bbr3.patch</a>
                      - <a href="https://github.com/google/bbr">google/bbr, the BBRv3 development branch</a>
  </pre>

* **995 — modem input validation**
  `target/linux/mediatek/patches-6.12/995-net-wwan-mhi_wwan_mbim-validate-ndp-chain-and-datagram-bounds.patch`

  <pre>
  Description:    Checks values the stock driver takes from the modem
                  without question: where the next packet list starts, and
                  where each packet starts and ends inside the bundle. It
                  also checks that copying a packet out of the bundle
                  actually worked.
  Benefit(s):     One of those values can spin a kernel thread forever and
                  lock up a CPU core; another can hand the network stack
                  whatever was sitting in freshly allocated memory. Both
                  are closed, and a bad packet is dropped and counted.
  Impact(s):      Three error paths share one helper, which also replaces
                  the open-coded counting on the existing unknown-protocol
                  path.
  Limitation(s):  A local carry with an expiry date, and not the version to
                  send upstream: it applies after 992 because it edits the
                  same loop 991 and 992 rewrite. Two of its three checks
                  can go once the upstream fixes reach 6.12.y; the bounds
                  check has no upstream successor, because the patch that
                  added one was withdrawn.
  Attribution(s): Guanglei Zhu posted the upstream fixes for two of the
                  three checks, on the suggestion of the driver's
                  maintainer Loic Poulain; on-list but not merged as of
                  2026-09-12. The implementation here is mine, against the
                  post-992 tree. Who posted what, and what was withdrawn:
                      - <a href="https://lore.kernel.org/r/20260911021734.1396599-1-zhugl3@xiaopeng.com">netdev v2 1/3: guard against a cyclic NDP chain</a>
                      - <a href="https://lore.kernel.org/r/20260911021734.1396599-2-zhugl3@xiaopeng.com">netdev v2 2/3: check skb_copy_bits() return value</a>
                      - <a href="x3000/docs/992-upstream-submission.md">x3000/docs/992-upstream-submission.md</a>
  </pre>

### Enhancements

* **eBPF, XDP and BTF platform**
  `x3000/config.common`

  <pre>
  Description:    Kernel BTF plus the XDP and tc-BPF userspace, so eBPF
                  programs can be built, loaded and inspected on the router
                  itself. Adds DEBUG_INFO, DEBUG_INFO_BTF, BTF_MODULES,
                  XDP_SOCKETS, BPF_EVENTS, CGROUP_BPF, KPROBES and
                  PERF_EVENTS to the kernel, and bpftool-full, libbpf,
                  tc-bpf, xdp-loader, xdpdump, xdp-filter, kmod-sched-bpf
                  and kmod-xdp-sockets-diag to the image.
  Benefit(s):     Portable eBPF binaries run unmodified here instead of
                  being cross-compiled against a matching kernel
                  elsewhere, and 992's XDP hook has something to attach.
  Impact(s):      Debug info has to stay un-reduced for BTF to build, which
                  costs image size. Kernel modules are tied to this exact
                  build, so they are baked in rather than installable
                  afterwards.
  Limitation(s):  xdp-filter parses an Ethernet header, so it belongs on
                  the wired ports rather than the raw-IP wwan0.
  Attribution(s): Mine. Every method tried and what each one measured:
                      - <a href="x3000/docs/xdp-methods-tested.md">x3000/docs/xdp-methods-tested.md</a>
  </pre>

* **Queue management and TCP baselines**
  `x3000/config.common`, `x3000/files-common/etc/sysctl.d/`

  <pre>
  Description:    cake and the rest of the qdisc set (kmod-sched-core,
                  kmod-sched, kmod-sched-cake, kmod-ifb) with full tc from
                  tc-bpf, plus bash and fping so cake-autorate can be
                  dropped in after flashing. Three sysctl files pin
                  fq_codel as the default qdisc and turn on SACK and DSACK.
  Benefit(s):     Everything needed to shape the 5G WAN is already in the
                  image, which matters because these modules cannot be
                  added later.
  Impact(s):      sqm-scripts, luci-app-sqm, qosify and tc-tiny are kept
                  out on purpose, so there is one unambiguous tc binary and
                  nothing competing with a hand-driven setup.
  Limitation(s):  No shaper is installed or running. cake-wan.init is a
                  reference to copy and fill in, and the sysctl settings
                  reach only connections the router itself opens, never a
                  client's forwarded traffic.
  Attribution(s): Mine. The reference shaper and the research behind it:
                      - <a href="x3000/docs/cake-wan.init">x3000/docs/cake-wan.init</a>
                      - <a href="x3000/docs/qos-latency-research.md">x3000/docs/qos-latency-research.md</a>
  </pre>

* **Software flow offload**
  `x3000/files-common/etc/uci-defaults/96-flow-offload`

  <pre>
  Description:    kmod-nft-offload provides the software flowtable fast
                  path, and a first-boot script switches it on unless
                  something has already set it either way.
  Benefit(s):     Established LAN-to-internet flows skip the conntrack
                  re-lookup and the filter, nat and mangle chains. Both of
                  its transmit paths still end in the normal transmit call,
                  so a cake shaper keeps working.
  Impact(s):      On by default. The firewall config survives sysupgrade,
                  so the running state is whatever was last set - read it
                  rather than assume it. Hardware offload stays off on
                  purpose: turning it on would disable the flowtable lookup
                  helper that XDP programs use, and MediaTek's engine
                  cannot reach wwan0 anyway.
  Limitation(s):  An offloaded flow is invisible to per-packet firewall
                  rules, so the two cannot cover the same traffic. wwan0
                  only joins the flowtable at all because of the firewall4
                  patch above.
  Attribution(s): Mine. The interaction matrix, sections 10.1 to 10.3:
                      - <a href="x3000/docs/xdp-methods-tested.md">x3000/docs/xdp-methods-tested.md</a>
  </pre>

* **Preemption model and running-config introspection**
  `target/linux/mediatek/filogic/config-6.12`

  <pre>
  Description:    Three kernel symbols that are not menu-exposed, so they
                  are appended to the subtarget config rather than set in
                  config.common: PREEMPT_DYNAMIC, IKCONFIG and
                  IKCONFIG_PROC. PCI_DEBUG is turned back off.
  Benefit(s):     The preemption model becomes a boot-time choice instead
                  of a rebuild, and /proc/config.gz lets a running router
                  answer what it was built with - which is how every
                  config claim about this image gets checked on the box.
  Impact(s):      Boots the same way as before, so nothing changes until
                  the preempt option is passed. PCI_DEBUG only ever added
                  log noise.
  Limitation(s):  Whether a different preemption model helps here has not
                  been measured.
  Attribution(s): Mine. Inventory row and the on-box check:
                      - <a href="x3000/docs/lean-overlay.md">x3000/docs/lean-overlay.md</a>
  </pre>

* **WireGuard**
  `x3000/config.common`

  <pre>
  Description:    kmod-wireguard with the userland tools and the LuCI
                  protocol page.
  Benefit(s):     A tunnel can be set up from the command line or the web
                  interface with no rebuild, and the kernel module picks up
                  the aarch64 NEON crypto automatically.
  Impact(s):      Inert until a wg interface exists. Baked in because a
                  kernel module cannot be installed after the fact on this
                  build.
  Limitation(s):  Nothing is configured - no keys, peers or interfaces
                  ship in the image.
  Attribution(s): Mine. Inventory row and verification:
                      - <a href="x3000/docs/lean-overlay.md">x3000/docs/lean-overlay.md</a>
  </pre>

* **Memory and interrupt headroom**
  `x3000/config.common`, `x3000/files-common/etc/uci-defaults/`

  <pre>
  Description:    Compressed-RAM swap (kmod-zram with the LZO, LZ4 and
                  ZSTD backends, defaulting to lzo-rle at 256 MB),
                  irqbalance to spread hardware interrupts across both
                  cores, and packet steering enabled for all CPUs.
                  First-boot scripts switch each one on, because all three
                  ship disabled.
  Benefit(s):     512 MB of RAM goes further, and receive work is not
                  pinned to one of only two cores.
  Impact(s):      irqbalance moves hardware interrupt affinity while packet
                  steering moves the NAPI threads and the steering mask, so
                  the two can pull against each other - turn irqbalance off
                  first if steering measurements come out noisy.
  Limitation(s):  All three live in /etc/config, which survives sysupgrade,
                  so the running values can differ from what the image
                  sets. Whether steering helps on this box has not been
                  measured under load.
  Attribution(s): Mine. What each lever is and how to read its state:
                      - <a href="x3000/docs/lean-overlay.md">x3000/docs/lean-overlay.md</a>
  </pre>

* **On-box diagnostics and access**
  `x3000/files-common/usr/bin/`

  <pre>
  Description:    MHI bus debugfs in the kernel, unhashed kernel pointers
                  for root, and three recorders: wanlog and dlwatch follow
                  the modem's state over time, collect-logs bundles
                  everything for a report. boot-history marks clean
                  shutdowns so a crash is distinguishable from a deliberate
                  reboot. ttyd with the LuCI terminal and file manager
                  pages give a shell and a file browser in the browser.
  Benefit(s):     The downlink stall was only diagnosable because the
                  per-channel view exists; without it there is nothing to
                  read but interrupt counters.
  Impact(s):      debugfs costs a little kernel size and nothing at runtime
                  until something reads it. Unhashing pointers only affects
                  readers that already have root, on files that are
                  root-only anyway. ttyd pulls in full libwebsockets and
                  OpenSSL, a few hundred KB.
  Limitation(s):  The recorders write to /tmp, so their output is lost on
                  reboot - only the tools themselves are permanent. The
                  debugfs symbol should come back out once the stall is
                  settled.
  Attribution(s): Mine. Capture, analysis and what to do during a stall:
                      - <a href="x3000/docs/downlink-stall.md">x3000/docs/downlink-stall.md</a>
                      - <a href="x3000/docs/wan-stall-runbook.md">x3000/docs/wan-stall-runbook.md</a>
  </pre>

* **First-boot defaults**
  `x3000/files-common/etc/uci-defaults/`

  <pre>
  Description:    Scripts that run once on a fresh config and then remove
                  themselves: timezone, route metrics for the wired and
                  modem WANs, the wireless radios, the modem interface,
                  mwan3 installed but left disabled, and a guard that stops
                  telegraf logging on every boot when no config was
                  supplied. Two further packages wire the Fantastic
                  Packages binary repository into apk so its catalogue is
                  installable after flashing.
  Benefit(s):     A freshly flashed router comes up configured instead of
                  needing a checklist, and every script is safe to re-run.
  Impact(s):      All of these write to /etc/config, which sysupgrade
                  preserves, so after the first flash the image default and
                  the running value can diverge.
  Limitation(s):  mwan3's stock configuration is a trap on this board -
                  read the inert script before enabling it. Nothing from
                  the Fantastic catalogue is built into the image.
  Attribution(s): Mine. The levers that drift, and how to read each one:
                      - <a href="x3000/docs/lean-overlay.md">x3000/docs/lean-overlay.md</a>
  </pre>

* **Web interface theme and compatibility layer**
  `x3000/config.common`, `x3000/custom-feeds.txt`

  <pre>
  Description:    luci-theme-argon is the theme a fresh flash comes up on,
                  pinned to v2.4.7 from jerrykuku/luci-theme-argon because
                  the 25.12 luci feed carries only bootstrap, footstrap,
                  material, openwrt and openwrt-2020. luci-compat adds the
                  pre-JS CBI/Lua form layer so third-party LuCI apps that
                  still use the old API can be installed on the box after
                  flashing. luci-theme-bootstrap stays in as the fallback.
  Benefit(s):     The router arrives on the intended theme with no
                  post-flash click, and most of the Fantastic Packages
                  catalogue becomes genuinely installable instead of
                  failing on a LuCI runtime that apk cannot add later.
  Impact(s):      luci-compat pulls the whole LuCI Lua runtime - seven
                  packages on top of luci-base and lua, which were already
                  in. The theme costs only itself: it is ucode-based, and
                  both its dependencies are already here - uclient-fetch
                  provides wget-any, and busybox brings jsonfilter in with
                  its ntpd applet. Nothing in the image needs luci-compat
                  today; it is there for what gets installed later.
  Limitation(s):  The theme is pinned to a tag, so a newer Argon release
                  means bumping custom-feeds.txt. No uci-defaults script
                  of ours sets the theme: the package ships its own, which
                  fires once on a fresh config and afterwards leaves a
                  theme chosen in LuCI alone.
  Attribution(s): Integration mine. The theme is jerrykuku/luci-theme-argon
                  (Apache-2.0); luci-compat is from the OpenWrt luci feed.
  </pre>

---

OpenWrt Project is a Linux operating system targeting embedded devices. Instead
of trying to create a single, static firmware, OpenWrt provides a fully
writable filesystem with package management. This frees you from the
application selection and configuration provided by the vendor and allows you
to customize the device through the use of packages to suit any application.
For developers, OpenWrt is the framework to build an application without having
to build a complete firmware around it; for users this means the ability for
full customization, to use the device in ways never envisioned.

Sunshine!

## Download

Built firmware images are available for many architectures and come with a
package selection to be used as WiFi home router. To quickly find a factory
image usable to migrate from a vendor stock firmware to OpenWrt, try the
*Firmware Selector*.

* [OpenWrt Firmware Selector](https://firmware-selector.openwrt.org/)

If your device is supported, please follow the **Info** link to see install
instructions or consult the support resources listed below.

## 

An advanced user may require additional or specific package. (Toolchain, SDK, ...) For everything else than simple firmware download, try the wiki download page:

* [OpenWrt Wiki Download](https://openwrt.org/downloads)

## Development

To build your own firmware you need a GNU/Linux, BSD or macOS system (case
sensitive filesystem required). Cygwin is unsupported because of the lack of a
case sensitive file system.

### Requirements

You need the following tools to compile OpenWrt, the package names vary between
distributions. A complete list with distribution specific packages is found in
the [Build System Setup](https://openwrt.org/docs/guide-developer/build-system/install-buildsystem)
documentation.

```
binutils bzip2 diff find flex gawk gcc-6+ getopt grep install libc-dev libz-dev
make4.1+ perl python3.7+ rsync subversion unzip which
```

### Quickstart

1. Run `./scripts/feeds update -a` to obtain all the latest package definitions
   defined in feeds.conf / feeds.conf.default

2. Run `./scripts/feeds install -a` to install symlinks for all obtained
   packages into package/feeds/

3. Run `make menuconfig` to select your preferred configuration for the
   toolchain, target system & firmware packages.

4. Run `make` to build your firmware. This will download all sources, build the
   cross-compile toolchain and then cross-compile the GNU/Linux kernel & all chosen
   applications for your target system.

### Related Repositories

The main repository uses multiple sub-repositories to manage packages of
different categories. All packages are installed via the OpenWrt package
manager called `opkg`. If you're looking to develop the web interface or port
packages to OpenWrt, please find the fitting repository below.

* [LuCI Web Interface](https://github.com/openwrt/luci): Modern and modular
  interface to control the device via a web browser.

* [OpenWrt Packages](https://github.com/openwrt/packages): Community repository
  of ported packages.

* [OpenWrt Routing](https://github.com/openwrt/routing): Packages specifically
  focused on (mesh) routing.

* [OpenWrt Video](https://github.com/openwrt/video): Packages specifically
  focused on display servers and clients (Xorg and Wayland).

## Support Information

For a list of supported devices see the [OpenWrt Hardware Database](https://openwrt.org/supported_devices)

### Documentation

* [Quick Start Guide](https://openwrt.org/docs/guide-quick-start/start)
* [User Guide](https://openwrt.org/docs/guide-user/start)
* [Developer Documentation](https://openwrt.org/docs/guide-developer/start)
* [Technical Reference](https://openwrt.org/docs/techref/start)

### Support Community

* [Forum](https://forum.openwrt.org): For usage, projects, discussions and hardware advise.
* [Support Chat](https://webchat.oftc.net/#openwrt): Channel `#openwrt` on **oftc.net**.

### Developer Community

* [Bug Reports](https://bugs.openwrt.org): Report bugs in OpenWrt
* [Dev Mailing List](https://lists.openwrt.org/mailman/listinfo/openwrt-devel): Send patches
* [Dev Chat](https://webchat.oftc.net/#openwrt-devel): Channel `#openwrt-devel` on **oftc.net**.

## License

OpenWrt is licensed under GPL-2.0
