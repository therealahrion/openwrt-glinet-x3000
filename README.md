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

To build the image instead of flashing a release — including a private
variant with an internal CA, a custom apk feed, or extra packages baked
in — **read [`x3000/README.md`](x3000/README.md)**. It documents what's
different from a stock OpenWrt build, the modem fixes vjt's fork already
carries, the build prerequisites, the public/private variant split, and
the post-flash modem configuration. The whole build comes down to:

```
git clone https://github.com/therealahrion/openwrt-glinet-x3000.git
cd openwrt-glinet-x3000
./x3000/build.sh public          # or `private`, which takes a local overlay
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

#### 890 — modem receive through gro_cells

| | |
|:--|:--|
| **Path(s)** | [`target/linux/mediatek/patches-6.12/890-net-wwan-mhi_wwan_mbim-gro-cells-rx.patch`](target/linux/mediatek/patches-6.12/890-net-wwan-mhi_wwan_mbim-gro-cells-rx.patch) |
| **Description** | The modem hands the host one bundle carrying many packets at a time, and the stock driver pushes each one up the stack separately. This routes them through `gro_cells`, the mechanism tunnel drivers use, so the kernel merges them and works on batches. |
| **Benefit(s)** | Far less per-packet work on a two-core router, which is what limits 5G downlink speed on this box. |
| **Impact(s)** | Gives wwan0 real NAPI contexts, so "ethtool -K wwan0 gro off" becomes a live kill switch. Nothing outside the MBIM receive path changes. It also makes the per-device "threaded" switch do something on wwan0, which is why 871 exists. |
| **Limitation(s)** | Downlink only; the upload side is untouched. Packets have to arrive close together for there to be anything to merge, so it does little at low rates. Carrying it without 871 means never writing 1 to /sys/class/net/wwan0/threaded, which killed the WAN twice. |
| **Attribution(s)** | N/A, written for this fork. |
| **Reference(s)** | Background:<br>[x3000/docs/xdp-methods-tested.md](x3000/docs/xdp-methods-tested.md) |

#### 891 — XDP on the modem interface

| | |
|:--|:--|
| **Path(s)** | [`target/linux/mediatek/patches-6.12/891-net-wwan-mhi_wwan_mbim-native-xdp.patch`](target/linux/mediatek/patches-6.12/891-net-wwan-mhi_wwan_mbim-native-xdp.patch) |
| **Description** | Gives the modem's receive path its own XDP hook, so eBPF programs attach to wwan0 the way they would to a normal network card and see each packet before the rest of the stack does. |
| **Benefit(s)** | Filtering, sampling and redirect on the WAN side, `AF_XDP` included, without giving up the batching 890 adds. The kernel's fallback way of attaching XDP here switched that batching off, so it used to be one or the other. |
| **Impact(s)** | Owning `ndo_bpf` makes driver mode the default attach mode for wwan0, so "ip link set dev wwan0 xdp ..." lands here. Detaching a generic attach needs "xdpgeneric off"; plain "xdp off" is a silent no-op. A program that rewrites a packet is safe to forward behind: the hook repairs the receive metadata the kernel derives from an Ethernet header this link does not have. |
| **Limitation(s)** | Needs 890. wwan0 is a raw-IP link, so a program written against an Ethernet header misreads the first bytes of the source address as an EtherType. |
| **Attribution(s)** | N/A, written for this fork. The same-shaped hook in the in-tree tun driver is the precedent. |
| **Reference(s)** | Background:<br>[x3000/docs/xdp-methods-tested.md](x3000/docs/xdp-methods-tested.md) |

#### 880 — MHI doorbell writes

| | |
|:--|:--|
| **Path(s)** | [`target/linux/mediatek/patches-6.12/880-bus-mhi-host-optional-doorbell-write.patch`](target/linux/mediatek/patches-6.12/880-bus-mhi-host-optional-doorbell-write.patch) |
| **Description** | Adds a switch to the MHI bus driver that makes the host tell the modem about every receive buffer it queues, rather than only when the modem asks to be told. |
| **Benefit(s)** | Works around a downlink that can stop dead under sustained load and stay stopped until the modem is re-probed. |
| **Impact(s)** | On at boot, from x3000/files-common/etc/modules.d/mhi-doorbell. Costs one register write per queued buffer. |
| **Limitation(s)** | A workaround, not a fix for the cause. The value is read while the channels are configured, so changing it needs an unbind/bind of the modem rather than just a write, and a reboot returns to the image default. |
| **Attribution(s)** | N/A, written for this fork. |
| **Reference(s)** | Capture, analysis and the draft report for the MHI maintainers:<br>[x3000/docs/downlink-stall.md](x3000/docs/downlink-stall.md)<br>[x3000/docs/mhi-upstream-report.md](x3000/docs/mhi-upstream-report.md) |

#### 871 — gro_cells declines threaded NAPI

| | |
|:--|:--|
| **Path(s)** | [`target/linux/mediatek/patches-6.12/871-net-gro_cells-opt-out-of-threaded-napi.patch`](target/linux/mediatek/patches-6.12/871-net-gro_cells-opt-out-of-threaded-napi.patch) |
| **Description** | The kernel's per-device threaded switch moves packet processing out of software interrupts and into kernel threads. On an interface built on `gro_cells` - tunnels, MACsec, modem links, and wwan0 here - doing that corrupts the receive queues. This teaches those queues to refuse, so the switch passes over them and threads only what is safe to thread. |
| **Benefit(s)** | /sys/class/net/wwan0/threaded is harmless to write again. Before this, writing 1 to it took the WAN down silently and needed a reboot. |
| **Impact(s)** | Core networking only, no driver. One new NAPI flag and three places that honour it. A device whose every queue opts out still accepts the write and reads back 1, exactly as it does today on a device with no queues at all - it simply threads nothing. Drivers with receive queues of their own are untouched and still thread normally. |
| **Limitation(s)** | It removes the hazard rather than making threaded `gro_cells` work. Binding each thread to the CPU whose queue it serves would do that, and is the larger change. Nothing needs it without 890, which is what puts `gro_cells` on wwan0 in the first place. |
| **Attribution(s)** | N/A, written for this fork. |
| **Reference(s)** | Background, section 23.21:<br>[x3000/docs/xdp-methods-tested.md](x3000/docs/xdp-methods-tested.md) |

#### 872 — a device may decline the forward path walk

| | |
|:--|:--|
| **Path(s)** | [`target/linux/mediatek/patches-6.12/872-net-forward-path-decline-without-failing.patch`](target/linux/mediatek/patches-6.12/872-net-forward-path-decline-without-failing.patch) |
| **Description** | Before offloading a connection the kernel walks the stack of devices a packet will cross. A device that does not implement the walk at all is handled fine; a device that implements it and answers "nothing to add for this one" throws the whole walk away. This makes the second answer mean the same as the first. |
| **Benefit(s)** | Bridged Wi-Fi clients can take the flow table's direct transmit path, which is the only route to Wi-Fi coverage for the XDP flowtable work. Without it the offload simply never engages and nothing reports why. |
| **Impact(s)** | Core networking, three lines plus a comment. Only changes behaviour for a device that was already failing the walk, so nothing that works today can change. The declining device now gets the same plain-Ethernet entry a device with no callback would have got. |
| **Limitation(s)** | It does not make the modem a flow-offload target - wwan0 has no Ethernet device beneath it to resolve down to, so it stays on the neighbour path either way. Fixes the walk, not what the walk finds. |
| **Attribution(s)** | N/A, written for this fork. |
| **Reference(s)** | Background, sections 23.18 and 24.12:<br>[x3000/docs/xdp-methods-tested.md](x3000/docs/xdp-methods-tested.md) |

#### 873 — XDP frame rebuild stops assuming Ethernet

| | |
|:--|:--|
| **Path(s)** | [`target/linux/mediatek/patches-6.12/873-net-xdp-no-ethernet-assumption-rebuilding-skb.patch`](target/linux/mediatek/patches-6.12/873-net-xdp-no-ethernet-assumption-rebuilding-skb.patch) |
| **Description** | `__xdp_build_skb_from_frame()` ends with an unconditional `eth_type_trans()`, which is right only when the ingress device has an Ethernet header. An `xdp_frame` carries no link-layer information, so the device is the only thing that can answer, and it was never asked. 873 asks it, and on a non-Ethernet device does the same work minus the header it does not have. |
| **Benefit(s)** | `XDP_REDIRECT` into a cpumap survives on a raw-IP link. Without it `eth_type_trans()` reads the IP version nibble as a destination MAC, IPv4 lands as `PACKET_MULTICAST` and IPv6 as `PACKET_OTHERHOST`, and `ip_forward()` drops every forwarded datagram. |
| **Impact(s)** | A no-op for every Ethernet device and every existing caller's normal case. On by default; core net only. |
| **Limitation(s)** | Native XDP only. The generic path tags its skbs into the same ring and never rebuilds them, so nothing can reach this today on a device that has no native XDP. It is a precondition for 893 rather than a result of it: native XDP on wwan0 delivers nothing through cpumap until this lands too. |
| **Attribution(s)** | N/A, written for this fork. Alexander Lobakin described this same failure - cpumap Rx on a non-Ethernet device - on a netdev thread in August 2026, so the consequence was named before I found it. |
| **Reference(s)** | The chain, the callers, and why the generic path escapes it:<br>[x3000/docs/xdp-methods-tested.md](x3000/docs/xdp-methods-tested.md)<br>[Jiayuan Chen's patch, Lobakin's review naming cpumap Rx, and Kicinski's refusal - netdev, August 2026](https://ratatoskr.run/bpf/2026/08/17407290/t) |

#### 893 — native XDP on the modem's receive path

| | |
|:--|:--|
| **Path(s)** | [`target/linux/mediatek/patches-6.12/893-net-wwan-mhi_wwan_mbim-native-xdp-datagrams.patch`](target/linux/mediatek/patches-6.12/893-net-wwan-mhi_wwan_mbim-native-xdp-datagrams.patch) |
| **Description** | Replaces 891's generic XDP hook with a native one. Each de-aggregated datagram is copied into a bare page frag and the program runs on an `xdp_buff`; an skb is built only if the verdict is `XDP_PASS`. Possible because the driver has always copied every datagram out of the NTB into its own allocation, and 891 added the headroom. |
| **Benefit(s)** | `XDP_DROP` allocates no skb at all, where the generic path allocated one, ran the program on it and freed it. `XDP_REDIRECT` can reach a cpumap, which is how per-packet work moves off the single CPU the MHI DL tasklet runs on. Native is also more correct here: generic XDP's Ethernet misparse never happens rather than being repaired afterwards. |
| **Impact(s)** | On by default whenever a program is attached; with none attached the path is byte-for-byte upstream's. Confirmed running natively on hardware 2026-09-15. Changes how receive memory is accounted, since `build_skb()` on a frag reports a different truesize than `netdev_alloc_skb`, which lands upstream of 890's `gro_cells`. |
| **Limitation(s)** | `XDP_TX` is not zero-copy - no `ndo_xdp_xmit` here, so the frame re-enters the ordinary transmit path. No tail slack, so a program growing the packet gets -EINVAL. The cpumap payoff needs 873, and that is the part still unmeasured, along with `XDP_DROP`'s saved allocation and any performance figure. |
| **Attribution(s)** | N/A, written for this fork. |
| **Reference(s)** | Design, hazards and the verification plan:<br>[x3000/docs/native-xdp-wwan-design.md](x3000/docs/native-xdp-wwan-design.md) |

#### 900 — firewall4 flow offload on a modem WAN

| | |
|:--|:--|
| **Path(s)** | [`package/network/config/firewall4/patches/900-flowtable-fall-back-to-l3-device.patch`](package/network/config/firewall4/patches/900-flowtable-fall-back-to-l3-device.patch) |
| **Description** | A one-line fix to OpenWrt's firewall so an interface that only ever gets an IP-level device, which is what ModemManager produces, can still be put into the flow table. |
| **Benefit(s)** | wwan0 joins the flow table, so software flow offload actually covers WAN traffic instead of the LAN side only. Without it the table looks healthy while offloading nothing that matters. |
| **Impact(s)** | Only ever adds devices that previously resolved to nothing. Where a lower-level device exists it still wins, so PPPoE and VLAN setups resolve exactly as before. |
| **Limitation(s)** | Flow offload is a separate switch and has to be on for this to do anything. Offloaded flows skip the rest of netfilter, so it cannot be combined with a per-packet rule on the same traffic. |
| **Attribution(s)** | N/A, written for this fork. |
| **Reference(s)** | Background, section 10.3:<br>[x3000/docs/xdp-methods-tested.md](x3000/docs/xdp-methods-tested.md) |

### Additional Patches

#### 870 — BBRv3

| | |
|:--|:--|
| **Path(s)** | [`target/linux/mediatek/patches-6.12/870-tcp-bbr3.patch`](target/linux/mediatek/patches-6.12/870-tcp-bbr3.patch) |
| **Description** | Replaces the kernel's BBR v1 congestion control with BBRv3. |
| **Benefit(s)** | BBR is already this image's default sender, so every connection the router opens picks up v3's revised loss and ECN handling. Nothing to turn on. |
| **Impact(s)** | Replaces the in-tree `tcp_bbr` rather than adding a second module, so kmod-tcp-bbr simply becomes v3. |
| **Limitation(s)** | A router cannot choose congestion control for traffic it forwards, so this reaches only connections the router itself opens, never a LAN client's. BBRv3 is still not in the mainline kernel. |
| **Attribution(s)** | Peter Jung's BBRv3 patch as carried by CachyOS, which in turn tracks Google's BBRv3 branch |
| **Reference(s)** | [CachyOS kernel-patches: 6.12/0002-bbr3.patch](https://github.com/CachyOS/kernel-patches/blob/master/6.12/0002-bbr3.patch)<br>[google/bbr, the BBRv3 development branch](https://github.com/google/bbr) |

#### 892 — modem input validation

| | |
|:--|:--|
| **Path(s)** | [`target/linux/mediatek/patches-6.12/892-net-wwan-mhi_wwan_mbim-validate-ndp-chain-and-datagram-bounds.patch`](target/linux/mediatek/patches-6.12/892-net-wwan-mhi_wwan_mbim-validate-ndp-chain-and-datagram-bounds.patch) |
| **Description** | Checks values the stock driver takes from the modem without question: where the next packet list starts, and where each packet starts and ends inside the bundle. It also checks that copying a packet out of the bundle actually worked. |
| **Benefit(s)** | One of those values can spin a kernel thread forever and lock up a CPU core; another can hand the network stack whatever was sitting in freshly allocated memory. Both are closed, and a bad packet is dropped and counted. |
| **Impact(s)** | Three error paths share one helper, which also replaces the open-coded counting on the existing unknown-protocol path. |
| **Limitation(s)** | A local carry with an expiry date, and not the version to send upstream: it applies after 891 because it edits the same loop 890 and 891 rewrite. Two of its three checks can go once the upstream fixes reach 6.12.y; the bounds check has no upstream successor, because the patch that added one was withdrawn. |
| **Attribution(s)** | Guanglei Zhu posted the upstream fixes for two of the three checks, on the suggestion of the driver's maintainer Loic Poulain; on-list but not merged as of 2026-09-12. The implementation here is mine, against the post-891 tree. |
| **Reference(s)** | Who posted what, and what was withdrawn:<br>[netdev v2 1/3: guard against a cyclic NDP chain](https://lore.kernel.org/r/20260911021734.1396599-1-zhugl3@xiaopeng.com)<br>[netdev v2 2/3: check skb_copy_bits() return value](https://lore.kernel.org/r/20260911021734.1396599-2-zhugl3@xiaopeng.com)<br>[x3000/docs/mbim-upstream-plan.md](x3000/docs/mbim-upstream-plan.md) |

### Enhancements

#### eBPF, XDP and BTF platform

| | |
|:--|:--|
| **Path(s)** | [`x3000/config.common`](x3000/config.common) |
| **Description** | Kernel BTF plus the XDP and tc-BPF userspace, so eBPF programs can be built, loaded and inspected on the router itself. Adds `DEBUG_INFO`, `DEBUG_INFO_BTF`, `BTF_MODULES`, `XDP_SOCKETS`, `BPF_EVENTS`, `CGROUP_BPF`, KPROBES and `PERF_EVENTS` to the kernel, and bpftool-full, libbpf, tc-bpf, xdp-loader, xdpdump, xdp-filter, kmod-sched-bpf and kmod-xdp-sockets-diag to the image. |
| **Benefit(s)** | Portable eBPF binaries run unmodified here instead of being cross-compiled against a matching kernel elsewhere, and 893's XDP hook has something to attach. |
| **Impact(s)** | Debug info has to stay un-reduced for BTF to build, which costs image size. Kernel modules are tied to this exact build, so they are baked in rather than installable afterwards. |
| **Limitation(s)** | xdp-filter parses an Ethernet header, so it belongs on the wired ports rather than the raw-IP wwan0. |
| **Attribution(s)** | N/A |
| **Reference(s)** | Every method tried and what each one measured:<br>[x3000/docs/xdp-methods-tested.md](x3000/docs/xdp-methods-tested.md) |

#### Queue management and TCP baselines

| | |
|:--|:--|
| **Path(s)** | [`x3000/config.common`](x3000/config.common), [`x3000/files-common/etc/sysctl.d/`](x3000/files-common/etc/sysctl.d/) |
| **Description** | cake and the rest of the qdisc set (kmod-sched-core, kmod-sched, kmod-sched-cake, kmod-ifb) with full tc from tc-bpf, plus bash and fping so cake-autorate can be dropped in after flashing. Three sysctl files pin `fq_codel` as the default qdisc and turn on SACK and DSACK. |
| **Benefit(s)** | Everything needed to shape the 5G WAN is already in the image, which matters because these modules cannot be added later. |
| **Impact(s)** | sqm-scripts, luci-app-sqm, qosify and tc-tiny are kept out on purpose, so there is one unambiguous tc binary and nothing competing with a hand-driven setup. |
| **Limitation(s)** | No shaper is installed or running. cake-wan.init is a reference to copy and fill in, and the sysctl settings reach only connections the router itself opens, never a client's forwarded traffic. |
| **Attribution(s)** | N/A |
| **Reference(s)** | The reference shaper and the research behind it:<br>[x3000/docs/cake-wan.init](x3000/docs/cake-wan.init)<br>[x3000/docs/qos-latency-research.md](x3000/docs/qos-latency-research.md) |

#### Software flow offload

| | |
|:--|:--|
| **Path(s)** | [`x3000/files-common/etc/uci-defaults/96-flow-offload`](x3000/files-common/etc/uci-defaults/96-flow-offload) |
| **Description** | kmod-nft-offload provides the software flowtable fast path, and a first-boot script switches it on unless something has already set it either way. |
| **Benefit(s)** | Established LAN-to-internet flows skip the conntrack re-lookup and the filter, nat and mangle chains. Both of its transmit paths still end in the normal transmit call, so a cake shaper keeps working. |
| **Impact(s)** | On by default. The firewall config survives sysupgrade, so the running state is whatever was last set - read it rather than assume it. Hardware offload stays off on purpose: turning it on would disable the flowtable lookup helper that XDP programs use, and MediaTek's engine cannot reach wwan0 anyway. |
| **Limitation(s)** | An offloaded flow is invisible to per-packet firewall rules, so the two cannot cover the same traffic. wwan0 only joins the flowtable at all because of the firewall4 patch above. |
| **Attribution(s)** | N/A |
| **Reference(s)** | The interaction matrix, sections 10.1 to 10.3:<br>[x3000/docs/xdp-methods-tested.md](x3000/docs/xdp-methods-tested.md) |

#### Preemption model and running-config introspection

| | |
|:--|:--|
| **Path(s)** | [`target/linux/mediatek/filogic/config-6.12`](target/linux/mediatek/filogic/config-6.12) |
| **Description** | Three kernel symbols that are not menu-exposed, so they are appended to the subtarget config rather than set in config.common: `PREEMPT_DYNAMIC`, IKCONFIG and `IKCONFIG_PROC`. `PCI_DEBUG` is turned back off. |
| **Benefit(s)** | The preemption model becomes a boot-time choice instead of a rebuild, and /proc/config.gz lets a running router answer what it was built with - which is how every config claim about this image gets checked on the box. |
| **Impact(s)** | Boots the same way as before, so nothing changes until the preempt option is passed. `PCI_DEBUG` only ever added log noise. |
| **Limitation(s)** | Whether a different preemption model helps here has not been measured. |
| **Attribution(s)** | N/A |
| **Reference(s)** | Inventory row and the on-box check:<br>[x3000/docs/lean-overlay.md](x3000/docs/lean-overlay.md) |

#### WireGuard

| | |
|:--|:--|
| **Path(s)** | [`x3000/config.common`](x3000/config.common) |
| **Description** | kmod-wireguard with the userland tools and the LuCI protocol page. |
| **Benefit(s)** | A tunnel can be set up from the command line or the web interface with no rebuild, and the kernel module picks up the aarch64 NEON crypto automatically. |
| **Impact(s)** | Inert until a wg interface exists. Baked in because a kernel module cannot be installed after the fact on this build. |
| **Limitation(s)** | Nothing is configured - no keys, peers or interfaces ship in the image. |
| **Attribution(s)** | N/A |
| **Reference(s)** | Inventory row and verification:<br>[x3000/docs/lean-overlay.md](x3000/docs/lean-overlay.md) |

#### Memory and interrupt headroom

| | |
|:--|:--|
| **Path(s)** | [`x3000/config.common`](x3000/config.common), [`x3000/files-common/etc/uci-defaults/`](x3000/files-common/etc/uci-defaults/) |
| **Description** | Compressed-RAM swap (kmod-zram with the LZO, LZ4 and ZSTD backends, defaulting to lz4 at 256 MiB), irqbalance to spread hardware interrupts across both cores, and packet steering enabled for all CPUs. First-boot scripts switch each one on, because all three ship disabled. |
| **Benefit(s)** | 512 MB of RAM goes further, and receive work is not pinned to one of only two cores. |
| **Impact(s)** | irqbalance moves hardware interrupt affinity while packet steering moves the NAPI threads and the steering mask, so the two can pull against each other - turn irqbalance off first if steering measurements come out noisy. |
| **Limitation(s)** | All three live in /etc/config, which survives sysupgrade, so the running values can differ from what the image sets. Whether steering helps on this box has not been measured under load. |
| **Attribution(s)** | N/A |
| **Reference(s)** | What each lever is and how to read its state:<br>[x3000/docs/lean-overlay.md](x3000/docs/lean-overlay.md) |

#### On-box diagnostics and access

| | |
|:--|:--|
| **Path(s)** | [`x3000/files-common/usr/bin/`](x3000/files-common/usr/bin/) |
| **Description** | MHI bus debugfs in the kernel, unhashed kernel pointers for root, and three recorders: wanlog and dlwatch follow the modem's state over time, collect-logs bundles everything for a report. boot-history marks clean shutdowns so a crash is distinguishable from a deliberate reboot. ttyd with the LuCI terminal and file manager pages give a shell and a file browser in the browser. |
| **Benefit(s)** | The downlink stall was only diagnosable because the per-channel view exists; without it there is nothing to read but interrupt counters. |
| **Impact(s)** | debugfs costs a little kernel size and nothing at runtime until something reads it. Unhashing pointers only affects readers that already have root, on files that are root-only anyway. ttyd pulls in full libwebsockets and OpenSSL, a few hundred KB. |
| **Limitation(s)** | The recorders write to /tmp, so their output is lost on reboot - only the tools themselves are permanent. The debugfs symbol should come back out once the stall is settled. |
| **Attribution(s)** | N/A |
| **Reference(s)** | Capture, analysis and what to do during a stall:<br>[x3000/docs/downlink-stall.md](x3000/docs/downlink-stall.md)<br>[x3000/docs/wan-stall-runbook.md](x3000/docs/wan-stall-runbook.md) |

#### First-boot defaults

| | |
|:--|:--|
| **Path(s)** | [`x3000/files-common/etc/uci-defaults/`](x3000/files-common/etc/uci-defaults/) |
| **Description** | Scripts that run once on a fresh config and then remove themselves: timezone, route metrics for the wired and modem WANs, the wireless radios, the modem interface, mwan3 installed but left disabled, and a guard that stops telegraf logging on every boot when no config was supplied. Two further packages wire the Fantastic Packages binary repository into apk so its catalogue is installable after flashing. |
| **Benefit(s)** | A freshly flashed router comes up configured instead of needing a checklist, and every script is safe to re-run. |
| **Impact(s)** | All of these write to /etc/config, which sysupgrade preserves, so after the first flash the image default and the running value can diverge. |
| **Limitation(s)** | mwan3's stock configuration is a trap on this board - read the inert script before enabling it. Nothing from the Fantastic catalogue is built into the image. |
| **Attribution(s)** | N/A |
| **Reference(s)** | The levers that drift, and how to read each one:<br>[x3000/docs/lean-overlay.md](x3000/docs/lean-overlay.md) |

#### Web interface theme and compatibility layer

| | |
|:--|:--|
| **Path(s)** | [`x3000/config.common`](x3000/config.common), [`x3000/custom-feeds.txt`](x3000/custom-feeds.txt) |
| **Description** | luci-theme-argon is the theme a fresh flash comes up on, pinned to v2.4.7 from jerrykuku/luci-theme-argon because the 25.12 luci feed carries only bootstrap, footstrap, material, openwrt and openwrt-2020. luci-compat adds the pre-JS CBI/Lua form layer so third-party LuCI apps that still use the old API can be installed on the box after flashing. luci-theme-bootstrap stays in as the fallback. |
| **Benefit(s)** | The router arrives on the intended theme with no post-flash click, and most of the Fantastic Packages catalogue becomes genuinely installable instead of failing on a LuCI runtime that apk cannot add later. |
| **Impact(s)** | luci-compat pulls the whole LuCI Lua runtime, eight packages in all. luci-base and lua were already in, and so was libubus-lua, which prometheus-node-exporter-lua already depends on. The theme costs only itself: it is ucode-based, and both its dependencies are already here - uclient-fetch provides wget-any, and base-files pulls jsonfilter unconditionally. Nothing in the image needs luci-compat today; it is there for what comes later. |
| **Limitation(s)** | The theme is pinned to a tag, so a newer Argon release means bumping custom-feeds.txt. No uci-defaults script here sets the theme: the package ships its own, which fires once on a fresh config and afterwards leaves a theme chosen in LuCI alone. |
| **Attribution(s)** | N/A |
| **Reference(s)** | The inventory row, and how to read the theme on a running box:<br>[x3000/docs/lean-overlay.md](x3000/docs/lean-overlay.md) |

#### Physical register reads for frame-engine work

| | |
|:--|:--|
| **Path(s)** | [`x3000/config.common`](x3000/config.common), [`target/linux/mediatek/filogic/config-6.12`](target/linux/mediatek/filogic/config-6.12) |
| **Description** | Three kernel symbols that make /dev/mem exist and be useful for reading memory-mapped registers. DEVMEM creates the device node, `STRICT_DEVMEM` keeps system RAM unreachable through it, and `IO_STRICT_DEVMEM` is turned back off so a range a driver has already claimed can still be read. They sit in two different files because OpenWrt declares `KERNEL_DEVMEM` and appends it after the kernel config fragments, so DEVMEM only takes effect from config.common; the other two have no KERNEL_ equivalent and belong in the fragment. |
| **Benefit(s)** | Undocumented SoC registers can be read from a shell rather than from a debug patch and a rebuild. The frame engine window at 0x15100000 is the case that forced it: nothing published says whether MT7981 implements the tables MediaTek's PCE driver drives on MT7988, and the address either decodes or it does not. |
| **Impact(s)** | /dev/mem exists on the running router. `STRICT_DEVMEM` narrows it to memory-mapped I/O, since `devmem_is_allowed()` returns 1 only for a page that is not RAM, so kernel and process memory stay out of reach. Root can still write any MMIO register through it. On by default. |
| **Limitation(s)** | A read says whether an address decodes, not what the bits mean. Writing an undocumented frame engine register takes the WAN down, which is why the probe script reads and never writes. Leaving `IO_STRICT_DEVMEM` off is what makes a driver-claimed range readable; that is the whole point here, and it is also a wider door than the upstream default. Putting DEVMEM in the fragment builds and boots and silently has no device; the split above is not a style choice. |
| **Attribution(s)** | N/A |
| **Reference(s)** | The probe, the offsets it reads and how to read the result:<br>[x3000/docs/fe-probe.sh](x3000/docs/fe-probe.sh) |

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
