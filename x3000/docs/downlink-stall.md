# The wwan0 downlink stall

Status: root-caused and fixed. The modem's MHI data channels run in burst-mode
doorbell, and under sustained load nothing on this hardware ever rings the bell,
so the downlink deadlocks holding a full ring of buffers the modem was never
told about. Patch 993 forces unconditional doorbell writes; it is enabled on
this board through `/etc/modules.conf` and has held through sustained 250+ Mbps
runs that used to stall.

## Symptom

Downlink freezes completely for one to two minutes at a time while the uplink
keeps working. Client traffic dies; unplugging and replugging the LAN cable
appears to restore it. Recovery arrives as a burst of a few thousand packets
with a few hundred to a thousand drops, then the link is normal again. The
interface never leaves `up: true` and the modem never re-registers.

## Which interrupt is which

Everything below rests on knowing which `/proc/interrupts` line is the
downlink, so that comes from the driver rather than from correlation. Each MHI
event ring takes MSI vector `ring + 1`; vector 0 is the BHI control interrupt
and is registered under the name `bhi`, while rings 0-3 are all registered as
`mhi` and appear in vector order (`mhi_init_irq_setup`, and the
`MHI_EVENT_CONFIG_*` macros in `pci_generic.c`):

| line | event ring | carries |
|---|---|---|
| 88 | 0 | control, and the software channels (MBIM, DUN, NMEA) |
| 89 | 1 | DIAG |
| 90 | 2 | `IP_HW0_MBIM(100)`, uplink |
| 91 | 3 | `IP_HW0_MBIM(101)`, downlink |

The debugfs `events` dump agrees independently: rings 0 and 1 hold 128
elements, rings 2 and 3 hold 1024, matching `MHI_EVENT_CONFIG_CTRL`/`DATA`
against `MHI_EVENT_CONFIG_HW_DATA`. And the uplink attribution matches
measurement - vector 90's delta tracks `tx_packets`.

Note the modem's channel configuration comes from
`gl-x3000-quectel-pci-id.patch`, which binds this device (Qualcomm 0x0308,
subsystem 0x5201) to `mhi_quectel_rm5xx_info`: 128-descriptor data rings,
1024-element event rings, `MHI_DB_BRST_ENABLE`, `doorbell_mode_switch` true,
MRU 32768.

## The measurement

Captured 2026-09-09 16:29 on image `328ceaa639`, which enables
`CONFIG_MHI_BUS_DEBUG` for exactly this purpose.

| interval | rx_packets | tx_packets | irq90 (uplink) | irq91 (downlink) |
|---|---|---|---|---|
| 16:29:17 - 16:29:24 | +0 | +165 | +177 | **+0** |
| 16:29:24 - 16:29:31 | +0 | +157 | +160 | **+0** |

The downlink vector does not fire at all. The downlink event ring was drained
to empty, and the controller reported `M0 / Active / MISSION MODE` throughout,
so the device was awake and not suspended.

`IP_HW0_MBIM(101)` is the downlink channel: a 128-entry ring where the host
posts empty buffers (`wp`, host-written) and the modem consumes them (`rp`,
which only the modem writes after init). Converting to descriptor indices:

| | modem rp | host wp | last doorbell | posted, unconsumed |
|---|---|---|---|---|
| idle baseline | 15 | 15 | 85 | 0 |
| during the stall | 26 | 4 | 5 | **106** |

The ring was **not empty**, which rules out host-side buffer starvation.

Read that table carefully though: the baseline row was taken on an essentially
idle link six seconds after the recorder started, not under load. Under load
the host keeps the ring locally full, so a healthy loaded reading is probably
also high - meaning 106-versus-0 is not by itself the discriminator it looks
like. What carries weight is that the count is not zero. `wanlog.sh` now
records these columns on every sample, which supplies the missing
healthy-under-load control.

## Why it is not ours

The kernel-side difference between this tree and `jeeves-r8` is exactly:

- `990-tcp-bbr3.patch`, `991-...gro-cells-rx.patch`, `992-...native-xdp.patch`
  (none of the three exist in `jeeves-r8`)
- `PCI_DEBUG` off, `IKCONFIG`, `IKCONFIG_PROC`, `PREEMPT_DYNAMIC` on
- ramoops record-size and console-size in the board dts
- `CONFIG_KERNEL_MHI_BUS_DEBUG=y`

The two MHI-adjacent patches are not ours. `gl-x3000-quectel-pci-id.patch` is
Marcello Barnaba's, and `790-bus-mhi-core-add-SBL-state-callback.patch` is
Robert Marko's ath11k patch, which only touches a control-plane execution
environment transition.

That leaves 991 and 992, and they are ruled out structurally rather than by
argument:

- Every line either patch changes lives inside `mhi_mbim_rx()` and the new
  `ndo_bpf` hooks.
- `mhi_mbim_rx()` has exactly one caller, `mhi_mbim_dl_callback()`, which is
  **byte-identical to upstream** in this tree.
- `mhi_mbim_dl_callback()` runs only from the downlink event ring, driven by
  vector 91 - which fired zero times during the freeze. So none of this code
  executed while the link was stalled.
- The only indirect route would be starving the modem of buffers, and
  `mhi_net_rx_refill_work()` is **byte-identical to upstream** too. Neither
  patch touches `mhi_queue*`, `mbim->mru`, `rx_queue_sz` or
  `mhi_get_free_desc_count`.
- 992's one allocation change is `netdev_alloc_skb(ndev, headroom + dgram_len)`
  where `headroom` is `XDP_PACKET_HEADROOM` only while a program is attached.
  With none attached - normal operation - it is zero and the allocation is
  identical to upstream.

BBR3 is TX-side TCP congestion control and cannot stop a modem writing DMA;
the freeze also kills ICMP, which BBR does not touch. `PCI_DEBUG` only adds log
messages. `PREEMPT_DYNAMIC` changes when work runs, not whether the modem
writes.

### Correction: this covers the freeze, not entry into it

The argument above proves the patched code does not run *while* the link is
stalled. It does not prove the patched code cannot cause the stall to start,
and a later observation makes that distinction matter: the stall only appears
above roughly 200-300 Mbps.

`mhi_ev_task()` drains the downlink completion ring with no budget - the quota
it passes is `U32_MAX` - and calls `mhi_mbim_dl_callback()` inline for every
entry. So NTB de-aggregation, the per-datagram `netdev_alloc_skb`, the copy,
and everything 991 added (a per-datagram flow hash, then `gro_cells_receive`)
all execute inside that single unbounded loop, in a tasklet, on whichever CPU
took the interrupt. All four MHI vectors land on CPU0, so uplink and downlink
event processing share one A53 core.

That makes 991 a live suspect again for *entering* the stall, by slowing the
drain loop until the modem has nowhere left to report completions. 992 is not:
with no XDP program attached it costs one `rcu_dereference` per datagram.

`er3_bk` in `dlwatch.sh` measures this directly - unprocessed entries in the
downlink completion ring, out of 1024. If it climbs toward 1023 as throughput
rises, the drain loop is the bottleneck. If it stays at 1 right up to the
freeze, the loop is keeping up and the fault is still below the driver.

**So the stall should be present on `jeeves-r8` as well.** That is an inference
from the diff, not a measurement. Flashing `jeeves-r8` and reproducing would
settle it directly.

## What was ruled out earlier, and how

- **gro_cells backlog drops.** 60 s of sustained load, `rx_dropped` +0,
  `softnet` +0.
- **Firewall, DHCP, dnsmasq, DNSSEC, NAT64 prefix.** All above IP, and DNS
  answers keep resolving through the freeze.
- **`mbim-proxy` pinning the control port.** `kill -9` on it, ModemManager
  recovered in 16 s.
- **Bufferbloat or congestion.** Congestion degrades throughput; this stops
  reception dead and then resumes at full rate.
- **The Windows NCSI indicator.** Real but cosmetic: `dns.msftncsi.com`
  publishes a ULA AAAA that dnsmasq's rebind protection strips.

## Measured: the doorbell is only ever rung by a power transition

Capture of 2026-09-09 17:27 to 17:36, with `kptr_restrict=1` so the driver's
own ring pointers are readable. Nine minutes at 1 Hz. This settles the
mechanism.

**The host ring is healthy and never starved.** `dl_qd` traces a clean sawtooth
between about 65 and 127 posted buffers. That floor is not arbitrary:
`mhi_mbim_dl_callback()` schedules a refill only once free descriptors reach
half the queue (`free_desc_count >= mbim->rx_queue_sz / 2`, i.e. 63 of 127), so
the ring is meant to drain to ~64 before being topped up. The measurement
matches the driver exactly, which also validates the instrument.

**The completion ring is never backed up.** Downlink event-ring backlog is one
element essentially always, peaking at five, against a 1024-element ring, while
both CPUs sit at 0-5 percent. The unbounded drain loop keeps up easily, so 991's
per-datagram work in that loop is not a factor. (An earlier version of
`dlwatch.sh` reported a recurring backlog of 14352 here. That was a bug of mine:
`off()` masked every pointer to the 0x800 data-ring size, so event offsets
straddling a 0x800 boundary inverted the subtraction. Fixed; the value is
reproducible from the bug and was never real.)

**And the finding.** From 17:27:40 to 17:32:51 - five minutes of continuous
traffic - `dl_db` sat frozen at index 68 and the modem's `dev_rp` at 99, while
`dl_wp` cycled right around the ring many times. The host posted hundreds of
buffers and wrote the doorbell register **zero** times.

At 17:32:54 both began moving. The reason is in the `m0`/`m3` columns: the
controller's power-transition counters had been static at 253/252 for that whole
five minutes, and resumed incrementing at 17:32:56. From then on every single
`m0` increment is matched one-for-one by a step in `dl_db`:

| time | m0 | dl_db | dev_rp |
|---|---|---|---|
| 17:27:40 - 17:32:51 | 253 | 68 | 99 |
| 17:32:54 | 254 | 24 | 35 |
| 17:33:20 | 255 | 22 | 64 |
| 17:34:14 | 256 | 79 | 11 |
| 17:34:34 | 256 | 77 | 80 |
| 17:34:54 | 258 | 12 | 14 |
| 17:35:35 | 260 | 10 | 62 |
| 17:35:55 | 262 | 73 | 109 |

So on this hardware **the only thing that ever writes the downlink doorbell is
an M3 to M0 transition.** That follows from the code: both data channels are
`MHI_DB_BRST_ENABLE`, where `mhi_db_brstmode()` writes the register only while
`db_mode` is set and clears it after each write; `mhi_pm_m0_transition()` re-arms
`db_mode` because `doorbell_mode_switch` is true for these channels; and the
only other re-arm is a `MHI_EV_CC_DB_MODE` event from the modem, which evidently
is not arriving. It also explains why `dev_rp` looked frozen: the modem
republishes its read pointer around those same transitions and not otherwise.

The consequence is the important part. **Under sustained traffic the modem never
suspends, so the doorbell is never written** - exactly the condition in which a
stall does the most damage. If the modem stops and waits for a doorbell during
that window, nothing on the host will ring it until traffic drops long enough
for a suspend/resume cycle, or until something forces a wake. Replugging the LAN
cable forces one: the client re-DHCPs, that traffic drives a resume, and the
resume rings the bell.

## The radio is also genuinely marginal

In the same window: RSRP -101 to -103 dBm, RSRQ -10 dB, SINR 15-16 on a 90 MHz
n41 carrier, with the SCC n25 aggregated but reporting no RSRP or SINR at all.
Round trips to 1.1.1.1 range from 28 ms to 689 ms with occasional timeouts,
while `rx_dropped` does not move at all - so the loss is upstream of the router,
not inside it.

## Where that leaves it

One theory covers everything observed: **the radio supplies the pause, and the
missing doorbell makes it persist.** A marginal link stalls briefly; that should
be a blip, but with no doorbell coming it becomes a freeze lasting until a power
transition or a forced wake. That accounts for the random timing, the duration
being far longer than any plausible radio dip, the LAN-replug workaround, the
clean dmesg, the healthy host ring, and the idle CPU.

The test is to switch channels 100 and 101 to `MHI_DB_BRST_DISABLE`, making the
host write the doorbell on every posted buffer at the cost of one MMIO write
each. Prediction: the long freezes disappear, while the high round trips and
timeouts remain, since nothing there touches the radio.

## Upstream, and prior reports

Nothing between 6.12 and 6.17 fixes this. `mhi_process_data_event_ring()` did
gain a ring-desync sanity check ("Event element points to an unexpected TRE"),
which is detection rather than a fix, but its existence confirms ring desync is
a real failure mode on MHI. `mhi_prepare_channel()` gained an ENABLED state
check, and `mhi_wwan_mbim` got a session mux-id fix - neither related.

No matching report found elsewhere. The GL.iNet thread about the RM520N-GL
losing packet service every 30-33 minutes is a different fault: stock firmware
over QMI, the modem detaches and re-registers, and recovery takes 10-21 s via a
`CFUN` cycle. Here the interface never changes state and recovers on its own.

## Clean-baseline run, 2026-09-10

The router was reflashed to GL.iNet stock, the modem's band selection reset to
auto there, then our image flashed back. That removed every inherited setting
at once - band locks, TTL, MTU override - which no previous capture had.

Seven and a half minutes of heavy traffic followed: 1.75 million packets at
about 5,100/s. Results:

- **No stalls.** Zero rows where rx stood still while tx kept moving, across
  455 samples.
- **Ring healthy throughout.** `dl_qd` sawtoothed with a floor of 64, exactly
  the refill-at-half-queue point.
- **Drain loop never near a limit.** Downlink completion-ring backlog peaked at
  10 of 1024, both CPUs at 0-5 percent.
- **But `dl_db` never moved.** One value, 66, for the entire run, while `dl_wp`
  cycled the ring repeatedly. The doorbell exposure is unchanged by the reset:
  it is structural, not something the old configuration created.

One dump was written and it is a false positive worth knowing about: a
six-second window where the recorder's ping exceeded its two-second timeout
while rx was moving at 11,500/s, more than double the run's average. That is
bufferbloat under load, not a stall. The lost-ping trigger catches degradation,
which is what it is for, but a dump alone does not mean the link stopped - check
whether rx was still climbing.

The band-lock reset also did not improve the radio. Free to choose, the modem
picked a different and wider n41 carrier and came out slightly worse: RSRP -104
against -101/-103 before, SINR 12 against 15/16. So the marginal signal is the
location, not a self-inflicted lock. The one real gain was the n25 secondary,
which began reporting RSRP where it had previously reported nothing at all.

## Related: the PCIe port power-management workaround

`pcie_port_pm=off` in the bootargs is a separate fault from this one, but the
two are close enough to confuse. See the entry in `x3000/README.md` for the root
cause - an upstream change backported into the 6.12 stable series at 6.12.43
that made non-x86 boards eligible for bridge D3 for the first time.

It matters here only as an exclusion: that parameter governs the **root port**.
The modem's own runtime PM is separate, still active, and is what drives the M3
cycling that rings the downlink doorbell. Pinning the endpoint at D0 with

    echo on > /sys/bus/pci/devices/0000:01:00.0/power/control

stops those transitions entirely, which should make the doorbell exposure
permanent rather than intermittent. That is the next test: if stalls get worse
or become constant, the doorbell mechanism is confirmed and 993 is the fix; if
they stop, power transitions were causing them and the doorbell is innocent.

## Confirmed: the deadlock, and then the fix

### The capture that settles it

2026-09-10 09:26, on an image carrying 993 with the parameter off.

    09:26:29  rx=2005672  tx=694409  irq91=68126  dl_qd=127  dl_free=0
    09:27:12  rx=2005672  tx=695170  irq91=68126  dl_qd=127  dl_free=0

Forty-three seconds with `rx` frozen to the exact packet, `tx` still climbing
by 761, uplink vector 90 up 853, and downlink vector 91 not firing once. The
ring was **completely full** - 127 posted, zero free. That kills host-side
buffer starvation outright: the host had done everything it could and the modem
had consumed nothing.

Everything else was healthy at the same instant. Downlink completion-ring
backlog 1 of 1024 with both CPUs at 0-6 percent, which exonerates 991 and 992
for *entering* the stall as well as during it - the open question left by the
correction above. `m0`/`m3` frozen at 1503/1502, so no power transitions were
happening. Radio fine: RSRP -100, SINR 17, bearer up 37,128 s.

And the doorbell state, read from debugfs during the freeze:

| local rp | local wp | ctxt wp | db | modem rp |
|---|---|---|---|---|
| 66 | 65 | 65 | 66 | 46 |

The host had gone a full lap of the ring posting 127 buffers and rung the bell
zero times. `db` still points where it was one lap earlier.

### The fix, measured

With `force_db_brst_disable=1` the driver says so at probe:

    mhi-pci-generic 0000:01:00.0: ch100 IP_HW0_MBIM: forcing doorbell writes
    mhi-pci-generic 0000:01:00.0: ch101 IP_HW0_MBIM: forcing doorbell writes

and `dl_db` then equals `dl_wp` on every sample and moves every second, against
one frozen value across 455 samples with it off. Sustained 250+ Mbps with no
stalls, in the same 200-300 Mbps band where they used to appear.

### Still open

The controlled reverse test - turn 993 back off, reproduce at the same
throughput, confirm the deadlock returns - has not been completed. The first
attempt did not take: the parameter was written but the rebind read it too
early, so 993 was still active for that probe. Until that run exists the
evidence is strong but one-directional.

### How it is enabled

`x3000/files-common/etc/modules.conf` carries

    options mhi force_db_brst_disable=1

which kmodloader applies when it loads `mhi`, so the fix is live from boot with
no unbind/bind cycle. That cycle matters: it destroys and recreates `wwan0`, and
ModemManager reliably fails to find the modem again afterwards.

It cannot go on the kernel command line. `mhi` is a loadable module here
(`kmod-mhi-bus`), and OpenWrt's kmodloader takes module options from
`/etc/modules.conf` and from inline options in `/etc/modules.d/` files - it
contains no `/proc/cmdline` parsing at all. The kernel accepts an
`mhi.force_db_brst_disable=1` bootarg silently as an unused module parameter and
it then never reaches the module. Of the two files, `/etc/modules.conf` is the
right one because kmodloader applies it in `scan_module_folders()` on every
invocation, including a manual `modprobe` after an `rmmod`, whereas
`/etc/modules.d/` options are only read on the boot-loader path.

To A/B test at runtime:

    echo 0 > /sys/module/mhi/parameters/force_db_brst_disable
    echo 0000:01:00.0 > /sys/bus/pci/drivers/mhi-pci-generic/unbind
    echo 0000:01:00.0 > /sys/bus/pci/drivers/mhi-pci-generic/bind

The parameter is read at probe, so the value in place at bind time is the one
that counts. Confirm with the dmesg lines above rather than with the parameter
file.

## Instrumentation

`x3000/docs/wanlog.sh` records the ring pointers on every sample. The columns
to watch are `dl_qd` and `dl_free` - buffers posted, and free descriptors left,
both taken from the driver's own pointers - together with `dl_db`, the last
doorbell written. If `dl_wp` keeps advancing through a stall while `dl_db`
stands still, the host is posting buffers the modem is never told about. If
`dl_db` tracks `dl_wp`, the modem has been told and is ignoring it. `dl_qd=127`
with `dl_free=0` is the deadlock signature.

Reading those pointer columns needs `sysctl -w kernel.kptr_restrict=1` first;
without it the driver's own `rp`/`wp` print as hashed values.
