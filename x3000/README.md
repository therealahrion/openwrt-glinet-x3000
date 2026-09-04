# GL.iNet GL-X3000 (Spitz AX) — vanilla OpenWrt build

A working OpenWrt 25.12 image for the GL.iNet GL-X3000 (Spitz AX),
including the kernel and userspace pieces needed to drive the
Quectel RM520N-GL 5G modem on the Quectel *vendor* `pcie_mhi` path —
the same out-of-tree MHI driver stack GL.iNet's stock firmware uses,
packaged by the [QModem](https://github.com/FUjr/QModem) feed. It
exposes the stock-style device nodes (`/dev/mhi_DUN` for AT,
`/dev/mhi_QMI0` for QMI, an `rmnet_mhi0` netdev for data);
`quectel-CM` dials under qmodem's control and `luci-app-qmodem` is
the UI. (Upstream vjt drives the same modem on the mainline
`mhi_pci_generic` + `mhi_wwan_mbim` + ModemManager path instead —
that's the main delta of this fork.)

## Why this fork exists

The GL.iNet stock firmware ships an old OpenWrt 21.02 + kernel 5.4
+ a vendor-patched `pcie_mhi` driver that's never been upstreamed.
Vanilla OpenWrt 25.12 (kernel 6.12) supports the rest of the device
out of the box, but the modem needs a driver stack plus a few fixes
before it actually comes up and stays up under load:

1. **The modem needs an MHI driver that claims its PCI ID.** This
   fork uses QModem's `kmod-pcie_mhi` — Quectel's vendor driver
   (v1.4, with kernel 6.12 support), which matches `17cb:0308`
   (SDX62) with *no* subsystem-ID restriction, so the GLAP variant
   in this device (subsystem `17cb:5201`) enumerates without any
   kernel patching. For the mainline alternative, we still carry
   vjt's 12-line patch under
   `target/linux/generic/pending-6.12/gl-x3000-quectel-pci-id.patch`
   that teaches `mhi_pci_generic` the `0x17cb/0x0308/0x17cb/0x5201`
   combination — it's inert while `kmod-mhi-pci-generic` isn't in
   the build, but keeps the door open for A/B testing the mainline
   stack.

2. **PCIe runtime PM races with MHI's startup ramp.** When the root
   port is allowed to take the modem into D3hot during early MHI
   bring-up, the doorbell write that follows arrives mid-link-retrain,
   the modem firmware sees a malformed TLP and resets, and the host
   gets stuck spinning on `[14] CmpltTO` AER interrupts. Only a host
   reboot recovers — runtime sysfs toggles like `power/control=on`
   reach the device too late. We pin `pcie_port_pm=off` in the
   chosen bootargs (`target/linux/mediatek/dts/mt7981a-glinet-gl-x3000-xe3000-common.dtsi`)
   so the kernel never tries to take the link down. (vjt observed
   this on the *mainline* driver; the vendor driver forces the link
   awake around doorbells like the stock firmware does, so this is
   belt-and-braces here — kept because it costs nothing on always-on
   router hardware.)

3. **Exactly one owner per AT port.** QModem's daemons
   (`ubus-at-daemon`, `tom_modem`) own the PCIe-side AT channel
   `/dev/mhi_DUN`; the `quectel-5g-tools` helpers (`5g-info`,
   `5g-monitor`, `5g-lock`, `5g-led-bars`) keep talking to the
   USB-side `/dev/ttyUSB2`. Two different physical paths into the
   same modem, so they don't contend on a port — but don't point
   both stacks at the same node, and expect confusion if both issue
   conflicting mode/band commands. (ModemManager is not in this
   image at all, so upstream vjt's patched MM tty-hotplug scheme —
   `0001-modemmanager-tty-honour-ignore-tty.patch` — is gone with
   it.)

4. **curl autodetects the brotli we keep around for android-tools.**
   `android-tools` pulls libbrotli into staging, OpenWrt's curl
   Makefile has no DEPENDS line for it, and curl's configure happily
   links libcurl against `libbrotlidec.so.1` if it sees the headers
   — which trips the install-time `.so` sanity check with
   _"Package libcurl is missing dependencies"_. Patched via
   `x3000/patches/0002-curl-disable-brotli-autodetect.patch` to pass
   `--without-brotli` explicitly.

## What's different from a stock OpenWrt 25.12 build

Commits on top of upstream `openwrt-25.12`:

  * `mhi_pci_generic: claim Quectel RM520N-GL with Qualcomm subvendor IDs`
    (inert while the mainline MHI kmods aren't built — see above)
  * `mediatek: glinet gl-x3000: disable PCIe runtime PM via pcie_port_pm=off`
  * `x3000: persistent build configuration` (the build-prep machinery
    + variant split under `x3000/`)
  * `swap modem stack from umbim+watchdog to ModemManager` (vjt,
    historical)
  * `patch curl to disable brotli autodetect`
  * the QModem swap (this fork): modem stack moved from
    ModemManager + mainline MHI to QModem + vendor `pcie_mhi`

Plus the build-prep machinery under `x3000/` (incl. patches to feed
files applied at the end of `prepare.sh`).

The build config drops a few things that upstream's GL-X3000 device
recipe pulls in:

  * **samba4-server + luci-app-samba4.** No SMB use case for this
    image.
  * **kmod-scsi-core + kmod-usb-storage.** No USB storage use case.

And adds:

  * **QModem** ([FUjr/QModem](https://github.com/FUjr/QModem), pinned
    by commit in `x3000/feeds.conf`): `qmodem` core + `modem_scan`
    discovery + `luci-app-qmodem` UI, dialing via `quectel-CM-5G-M`,
    AT plumbing via `ubus-at-daemon`/`tom_modem`/`sms-tool_q`, and —
    the point of the exercise — **`kmod-pcie_mhi`**, Quectel's vendor
    MHI driver producing stock-firmware-style `/dev/mhi_*` nodes.
    Replaces upstream vjt's ModemManager + mainline-MHI stack
    (ModemManager, luci-proto-modemmanager, dbus/glib2, libmbim,
    mbim-utils and all `kmod-mhi-*` mainline kmods are dropped from
    the config).
  * **adb + fastboot** (nmeum/android-tools 35.0.2 with a small patch
    fixing the libusb claim bug for non-contiguous USB interface
    numbers — the RM520N publishes interfaces 0,1,2,3,5 and the
    upstream client iterates by array index).
  * **qfirehose** ([nippynetworks/qfirehose](https://github.com/nippynetworks/qfirehose)
    1.4.17 packaged for OpenWrt; available on the device for one-off
    modem firmware flashes, not used at runtime).
  * **quectel-5g-tools** (Lua AT helpers `5g-info`, `5g-monitor`,
    `5g-lock`, `modem-debug` reading `/dev/ttyUSB2`; the `5g-led-bars`
    procd daemon driving the panel signal LEDs from PCC/SCC NR-RSRP;
    a Prometheus collector). Patched at prepare time
    (`x3000/patches/0003-quectel-5g-tools-drop-modemmanager.patch`) to
    drop its `+modemmanager` dependency and omit the `5g-watchdog`
    daemon — that piece drives recovery through `mmcli` +
    `proto=modemmanager` and is meaningless without MM; session
    recovery is quectel-CM's job under QModem. Still ships an inert
    `/etc/modemmanager/ignore-tty` file — harmless, MM isn't
    installed.
  * **pciutils + usbutils** (lspci / lsusb baked in for diagnosing
    modem PCIe / USB topology).
  * **speedtest-go**, **wifi-dethrash-collector**.
  * **telegraf-full** — *private variant only*. Useful if you've got
    a metrics endpoint to push to. Toggled in `x3000/config.private`;
    the public variant explicitly unsets both `telegraf` and
    `telegraf-full`.
  * **procps-ng-ps**: real `ps` replacing busybox's stub, swapped in
    via the OpenWrt alternatives system at `/bin/ps`.

## Hardware

| Field | Value |
|---|---|
| Device | GL.iNet GL-X3000 (Spitz AX) |
| SoC | MediaTek MT7981A |
| Wi-Fi | MT7976 (2.4 GHz + 5 GHz) |
| Modem | Quectel RM520N-GL (5G NR Sub-6) over PCIe MHI |
| Storage | 8 GB eMMC |
| RAM | 1 GB DDR4 |

## Prerequisites (build host)

  * Linux x86_64 (build also works on aarch64; see below)
  * ~25 GB free disk for the build tree, dl/, build_dir/ and staging_dir/
  * 8+ GB RAM (toolchain build needs ~6 GB peak, android-tools' BoringSSL
    + fmt are also memory-hungry)
  * The standard OpenWrt build dependencies — see
    https://openwrt.org/docs/guide-developer/toolchain/install-buildsystem
    On Debian/Ubuntu:
    ```
    sudo apt install build-essential clang flex bison g++ gawk \
        gcc-multilib g++-multilib gettext git libncurses-dev libssl-dev \
        python3-distutils rsync unzip zlib1g-dev file wget
    ```
  * `golang` (≥ 1.21) on **aarch64** hosts only — the in-tree
    `golang-bootstrap` doesn't compile on arm64. On x86_64 you can leave
    `CONFIG_GOLANG_BUILD_BOOTSTRAP=y` and skip this step.

## Build

The build kit produces two variants, selected by argument to
`prepare.sh` (or `build.sh`, the one-shot driver):

  * **`public`** — clean image suitable for anyone with the same
    hardware. Hardware enablement, the custom packages above, no
    private overlay, no telegraf.

  * **`private`** — same image plus your own per-builder rootfs
    overlay at `x3000/files-private/`, plus `telegraf-full`.
    `files-private/`'s contents are gitignored, so each builder's
    private bits stay local and out of the public repo. See
    "Adding your own private overlay" below.

```
git clone https://github.com/vjt/openwrt-glinet-x3000.git
cd openwrt-glinet-x3000

# One-shot: prepare + make + relocate output to bin-x3000-<variant>/
./x3000/build.sh public           # public image
./x3000/build.sh private          # your-own-overlay image
./x3000/build.sh public -- V=s    # forward extra args to make

# Or step-by-step (artifacts land in bin/ — overwritten on every build):
./x3000/prepare.sh public
make -j$(nproc)
```

`prepare.sh` is idempotent — re-run it any time `x3000/custom-feeds.txt`
changes (e.g. you bumped a custom package) or you switch variants and
it will refresh the clones, refresh the symlinks under `feeds-local/`,
recompose `.config` from `x3000/config.common + x3000/config.<variant>`,
and recompose `files/` from `x3000/files-common/ + x3000/files-<variant>/`.
The active variant is recorded in `.x3000-variant`.

After `build.sh` finishes the artifacts land under

```
bin-x3000-<variant>/
├── openwrt-mediatek-filogic-glinet_gl-x3000-squashfs-sysupgrade.bin
├── openwrt-mediatek-filogic-glinet_gl-x3000-squashfs-factory.bin
├── openwrt-mediatek-filogic-glinet_gl-x3000.manifest
└── …
```

(Plain `make` without `BIN_DIR=` writes to the default `bin/`, which
gets overwritten by the next build of the other variant — use
`build.sh` if you want both variants to coexist on disk.)

Use `sysupgrade.bin` for an in-place upgrade from a router that's
already running OpenWrt; use `factory.bin` only via stock recovery
mode. The GL.iNet stock U-Boot rejects factory headers via the web
UI — it expects a sysupgrade-style image even on the first flash —
so plan accordingly.

## Adding your own private overlay

The `private` variant has three per-builder slots, all gitignored,
so populating them doesn't pollute the upstream tree:

| Slot | Purpose |
|---|---|
| `x3000/files-private/` | rootfs files (CAs, configs, …) |
| `x3000/custom-feeds.private.local` | extra package repos |
| `x3000/config.private.local` | extra `CONFIG_PACKAGE_…` selections |

### Rootfs files: `x3000/files-private/`

Drop anything here that should ship inside the rootfs of your private
build. Layout mirrors the device's rootfs path; permissions are
preserved (uci-defaults scripts must be `chmod +x`). Only `.gitkeep`
is tracked.

Common contents:

  * **Internal CA(s)** at
    `usr/local/share/ca-certificates/<name>.crt`, with a uci-default
    at `etc/uci-defaults/99-<name>-ca` that appends the cert to
    `/etc/ssl/certs/ca-certificates.crt` on first boot. Sketch:

    ```sh
    #!/bin/sh
    CERT=/usr/local/share/ca-certificates/<name>.crt
    BUNDLE=/etc/ssl/certs/ca-certificates.crt
    MARKER='# <name> internal CA'
    [ -r "$CERT" ] || exit 0
    grep -qF "$MARKER" "$BUNDLE" && exit 0
    { echo; echo "$MARKER"; cat "$CERT"; } >> "$BUNDLE"
    ```
  * **Custom apk feed wiring**: the feed-signing public key at
    `etc/apk/keys/<basename>.pem` (basename must match `--sign-key`
    used by `apk mkndx` on your feed builder), and the feed URL in
    `etc/apk/repositories.d/customfeeds.list`.
  * **Telegraf config** at `etc/telegraf.conf` if you've enabled
    `telegraf-full` via the `private` variant.
  * Anything else infra-specific.

### Baking your own packages

The `public` build pulls extra packages from `x3000/custom-feeds.txt`
(the four vjt forks listed there). For private builds you can layer
your own on top via two gitignored files:

`x3000/custom-feeds.private.local` — same line format as
`custom-feeds.txt` (`<symlink-name> <git-url> <ref> <subdir>`), one
per repo. `prepare.sh private` clones each, refreshes to `<ref>`, and
symlinks the package subdir under `feeds-local/` alongside the public
ones, so they're visible to OpenWrt's feeds machinery as if they'd
always been there. Example:

```
# x3000/custom-feeds.private.local
my-private-pkg  git@github.com:you/my-private-pkg.git  main  openwrt/my-private-pkg
my-other-pkg    git@gitea.example/you/my-other.git    v1.2  openwrt
```

`x3000/config.private.local` — `CONFIG_PACKAGE_<name>=y` lines,
appended to the composed `.config` after `config.private`. Anything
you'd put in `config.private` if it weren't going into the public
repo:

```
# x3000/config.private.local
CONFIG_PACKAGE_my-private-pkg=y
CONFIG_PACKAGE_my-other-pkg=y
```

Both files are absent in a fresh clone — the build silently no-ops
the local-additions step if either doesn't exist.

## On aarch64 build hosts

`x3000/config.common` already disables `CONFIG_GOLANG_BUILD_BOOTSTRAP`
and sets `GOLANG_EXTERNAL_BOOTSTRAP_ROOT="/usr/local/go"`. Install Go
≥ 1.21 there before running `prepare.sh`:

```
wget https://go.dev/dl/go1.23.5.linux-arm64.tar.gz
sudo tar -C /usr/local -xzf go1.23.5.linux-arm64.tar.gz
```

If your Go install lives elsewhere, edit
`CONFIG_GOLANG_EXTERNAL_BOOTSTRAP_ROOT` in `x3000/config.common` before
the `prepare.sh` run that composes it into `.config`.

## Pinning custom packages

`x3000/custom-feeds.txt` defaults to `master` for every custom repo,
which tracks fixes — handy during development but not reproducible.
For production builds, replace each `master` with a commit SHA, e.g.

```
android-tools https://github.com/vjt/openwrt-android-tools.git f24c199 openwrt/android-tools
```

Then `./x3000/prepare.sh` will fetch the repos and check out exactly
those SHAs.

## Layout

```
x3000/
├── README.md           This file.
├── prepare.sh          Variant-aware tree setup: feeds-local/, feeds.conf,
                        composes .config and files/ from common + variant
                        sources, applies x3000/patches/ with `-F 0`.
├── build.sh            One-shot driver: prepare.sh + make with a
                        variant-specific BIN_DIR (bin-x3000-<variant>/).
├── feeds.conf          Verbatim copy installed at /feeds.conf
                        (with feeds-local/ rewritten to absolute path).
├── custom-feeds.txt    Tracked repo list driving prepare.sh.
├── custom-feeds.private.local   *(optional, gitignored)* extra repos for
                        your private build. Same line format as
                        custom-feeds.txt.
├── config.common       Shared build-config overlay (target + the bulk of
                        package selections).
├── config.private      Private-only delta (telegraf-full, etc.).
├── config.public       Public-only delta (explicit unsets for telegraf).
├── config.private.local *(optional, gitignored)* extra CONFIG_PACKAGE_…
                        lines for your private build. Appended to .config
                        after config.private.
├── files-common/       Rootfs overlay shipped in every variant.
├── files-private/      Rootfs overlay only in private. Per-builder slot:
                        only .gitkeep is tracked, all contents are
                        gitignored, so each builder keeps their internal
                        CA / feed-signing pubkey / customfeeds.list
                        local. Empty in a fresh clone — populate before
                        building private if you need any of those.
├── files-public/       Rootfs overlay only in public (currently empty).
└── patches/            Unified diffs applied to feeds/ files after
                        `feeds install -a`. patch is invoked with
                        --forward and -F 0 so the loop is idempotent
                        AND a context drift is a hard fail. Currently:
                          * 0001-modemmanager-tty-honour-ignore-tty.patch
                          * 0002-curl-disable-brotli-autodetect.patch
target/linux/generic/pending-6.12/
└── gl-x3000-quectel-pci-id.patch   Kernel patch (commit 8cc71da72a).
target/linux/mediatek/dts/
└── mt7981a-glinet-gl-x3000-xe3000-common.dtsi   pcie_port_pm=off
                                                 (commit 4087faad55).
```

`prepare.sh` writes its composed outputs to `/.config` and `/files/`
(both gitignored), and records the active variant in `/.x3000-variant`.

## Post-flash modem config

First boot sanity checks, in order:

```sh
lspci -nn                    # expect 17cb:0308 (subsystem 17cb:5201)
lsmod | grep pcie_mhi        # vendor driver loaded (init.d/pcie_mhi, START=70)
ls /dev/mhi_*                # expect mhi_DUN / mhi_QMI0 / mhi_DIAG / ...
ip link | grep rmnet         # rmnet_mhi0 data netdev
```

Then configure the modem in LuCI: **Modem → QModem** (from
`luci-app-qmodem`). `modem_scand` discovers the PCIe modem and binds
it to its slot; set APN / PDP type / auth there and dial. QModem
drives `quectel-CM` (the 5G-M fork) for the data session and manages
the interface it creates.

Quick AT smoke test without the UI (QModem's CLI AT tool, against
the PCIe AT channel):

```sh
tom_modem -d /dev/mhi_DUN -c "ATI"
```

If `lspci` shows nothing in the modem slot or `/dev/mhi_*` never
appears, check the modem hasn't been switched to USB data mode —
from the USB AT port:

```sh
tom_modem -d /dev/ttyUSB2 -c 'AT+QCFG="data_interface"'   # 0,0 = USB mode
tom_modem -d /dev/ttyUSB2 -c 'AT+QCFG="data_interface",1,0'  # set PCIe
```

then power-cycle the router (takes effect on modem reboot). Stock
GL.iNet units ship in PCIe mode already, so this only bites if the
modem was reconfigured or firmware-flashed along the way.

Two migration gotchas:

  * **Coming from a vjt/ModemManager image:** sysupgrade preserves
    `/etc/config/*`, so a leftover `network.wwan` section with
    `proto='modemmanager'` will reference a proto that no longer
    exists. Delete or repurpose it (`uci delete network.wwan;
    uci commit network`) and let QModem manage its own interface.
  * **Coming from stock GL.iNet firmware:** flash WITHOUT keeping
    settings — the stock config schema isn't compatible.

The USB-side serial ports (`/dev/ttyUSB0-3`) still enumerate via
`option`, so `quectel-5g-tools` (`5g-info`, `5g-monitor`,
`5g-led-bars`) keep working unchanged on `/dev/ttyUSB2` alongside
QModem on `/dev/mhi_DUN`.
