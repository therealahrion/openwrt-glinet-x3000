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
optimization layer on top: a handful of kernel, driver and firewall
patches (listed in **[Patches we add on top of vjt's tree](#patches-we-add-on-top-of-vjts-tree)**
below), an eBPF/XDP/BTF platform with the cake/bpf qdisc kmods and tools,
PREEMPT_DYNAMIC + IKCONFIG, TCP/qdisc sysctl baselines, WireGuard —
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

## Patches we add on top of vjt's tree

Six patches this fork carries that neither vjt's tree nor upstream
OpenWrt has. The modem-enablement patches vjt's fork already carries are
a separate set, described in [`x3000/README.md`](x3000/README.md). Full
detail on each of these, including how to confirm it is really in a
running image, is in
[`x3000/docs/lean-overlay.md`](x3000/docs/lean-overlay.md).

### 990 — BBRv3

**What it is.** Replaces the kernel's BBR v1 congestion control with
BBRv3, using the patch the CachyOS kernel carries.

**How it helps.** BBR is already this image's default sender, so every
upload picks up v3's revised loss and ECN handling. Nothing to turn on.

**Where.** `target/linux/mediatek/patches-6.12/990-tcp-bbr3.patch`

### 991 — modem receive through gro_cells

**What it is.** The modem hands the host one bundle carrying many packets
at a time, and the stock driver pushes each packet up the stack on its
own. This sends them through `gro_cells` instead — the mechanism tunnel
drivers use — so the kernel can merge them and work on batches.

**How it helps.** Much less per-packet work on a two-core router, which
is what limits 5G downlink speed on this box. It also gives the modem
interface real NAPI contexts, which is what makes `ethtool -K wwan0 gro
off` and the per-device `threaded` switch work at all.

**Where.**
`target/linux/mediatek/patches-6.12/991-net-wwan-mhi_wwan_mbim-gro-cells-rx.patch`

### 992 — XDP on the modem interface

**What it is.** Gives the modem's receive path its own XDP hook, so eBPF
programs attach to `wwan0` the way they would to a normal network card
and see each packet before the rest of the stack does.

**How it helps.** The kernel's fallback way of attaching XDP to an
interface like this one worked, but it switched off the batching 991 adds
— so you could have one or the other, not both. This gives a proper
driver-mode hook that runs per packet and leaves the batching in place,
with the full set of verdicts including redirect and AF_XDP. Builds on
991 and needs it.

**Where.**
`target/linux/mediatek/patches-6.12/992-net-wwan-mhi_wwan_mbim-native-xdp.patch`

### 993 — MHI doorbell writes

**What it is.** Adds a switch to the MHI bus driver that makes the host
tell the modem about every receive buffer it queues, rather than only
when the modem asks to be told.

**How it helps.** Works around a downlink that can stop dead under
sustained load and stay stopped until the modem is re-probed. The image
turns the switch on at boot from
`x3000/files-common/etc/modules.d/mhi-doorbell`, and it can be turned
back off on a running router without reflashing.

**Where.**
`target/linux/mediatek/patches-6.12/993-bus-mhi-host-optional-doorbell-write.patch`

### 995 — modem input validation

**What it is.** Checks values the stock driver takes from the modem
without question: where the next packet list starts, and where each
packet starts and ends inside the bundle. It also checks that copying a
packet out of the bundle actually worked.

**How it helps.** One of those values can spin a kernel thread forever
and lock up a CPU core; another can hand the network stack whatever
happened to be sitting in freshly allocated memory. Fixes for these are
already on their way into the mainline kernel, so this is a local carry
until they arrive in 6.12 — not something for us to send on.

**Where.**
`target/linux/mediatek/patches-6.12/995-net-wwan-mhi_wwan_mbim-validate-ndp-chain-and-datagram-bounds.patch`

### firewall4 — flow offload on a modem WAN

**What it is.** A one-line fix to OpenWrt's firewall so an interface that
only ever gets an IP-level device, which is what ModemManager produces,
can still be put into the flow table.

**How it helps.** Without it the flow table holds the LAN side only, so
nothing between LAN and the internet can be offloaded and nothing says
so — the table looks healthy. With it, `wwan0` joins the table and
software flow offload actually covers WAN traffic.

**Where.**
`package/network/config/firewall4/patches/001-flowtable-fall-back-to-l3-device.patch`

The rest of this README is upstream OpenWrt's, kept verbatim for
reference.

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
