# The wwan0 downlink stall

Status: the stall is below the MHI bus, and it is not caused by anything in
this repo. Two candidates remain, both in the modem or the MHI host driver.

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

## What is left

**1. A burst-mode doorbell that stops being rung.** Both data channels are
`MHI_DB_BRST_ENABLE`, where `mhi_db_brstmode()` writes the doorbell register
only while `db_mode` is set and clears it after each write. The modem re-arms
it by sending `MHI_EV_CC_DB_MODE`. If that event is missed or never sent, the
host keeps posting buffers and updating `wp` in shared memory but never pokes
the doorbell, and the modem never learns the buffers are there. Testing it
means switching channels 100 and 101 to `MHI_DB_BRST_DISABLE`, which makes the
host write the doorbell on every posted buffer, at the cost of one MMIO write
each.

Note `doorbell_mode_switch` is true for these channels, so an M3 to M0 power
transition re-arms `db_mode` and rings the doorbell. That is a plausible
explanation for why replugging the LAN cable - which makes a client re-DHCP,
generating traffic that forces a resume - appears to clear the stall.

**2. The modem firmware simply stops sending.** The cellular LED has been seen
dropping from three bars to one and back around a stall. Distinguishing this
needs the modem's own registration and RRC state during a freeze.

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

## Instrumentation

`x3000/docs/wanlog.sh` records the ring pointers on every sample. The columns
to watch are `dl_out` (buffers posted and unconsumed) and `dl_db` (last
doorbell). If `dl_wp` keeps advancing through a stall while `dl_db` stands
still, the host is posting buffers the modem is never told about. If `dl_db`
tracks `dl_wp`, the modem has been told and is ignoring it.
