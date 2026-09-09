# The wwan0 downlink stall

Status: root cause narrowed to the MHI downlink channel. Not caused by anything
in this repo. Two candidates remain, both below the network stack.

## Symptom

Downlink freezes completely for one to two minutes at a time while the uplink
keeps working. Client traffic dies; unplugging and replugging the LAN cable
appears to restore it. Recovery arrives as a burst of a few thousand packets
with a few hundred to a thousand drops, then the link is normal again.

## What it is not

Each of these was tested and ruled out, not assumed away.

- **Our RX changes (991 gro_cells, 992 XDP).** Both sit above MHI. They cannot
  lose packets that never arrive, and the ring dump below shows none arrive.
- **RX buffer starvation in `mhi_net_rx_refill_work`.** This was the leading
  theory. The ring dump disproves it: 106 of 128 buffers were posted and
  waiting at the moment of the stall.
- **gro_cells backlog drops.** 60 s of sustained load, `rx_dropped` +0,
  `softnet` +0.
- **Firewall, DHCP, dnsmasq, DNSSEC, NAT64 prefix.** All above IP, and DNS
  answers keep resolving from cache through the freeze.
- **`mbim-proxy` pinning the control port.** `kill -9` on it, ModemManager
  recovered in 16 s.
- **Bufferbloat or congestion.** Congestion degrades throughput; this stops
  reception dead and then resumes at full rate.
- **The Windows NCSI indicator.** Real, but cosmetic: `dns.msftncsi.com`
  publishes a ULA AAAA that dnsmasq's rebind protection strips. Affects the
  connectivity icon only.

## The measurement that settled it

Captured 2026-09-09 16:29 on image `328ceaa639`, which enables
`CONFIG_MHI_BUS_DEBUG` for exactly this purpose.

Per-vector MHI interrupt counts during the freeze:

| interval | rx_packets | tx_packets | irq90 (uplink) | irq91 (downlink) |
|---|---|---|---|---|
| 16:29:17 - 16:29:24 | +0 | +165 | +177 | **+0** |
| 16:29:24 - 16:29:31 | +0 | +157 | +160 | **+0** |

The uplink vector tracks `tx_packets`; the downlink vector does not fire at all.
So the modem raises no downlink interrupt, and the question becomes whether it
has anywhere to write.

`IP_HW0_MBIM(101)` is the downlink channel: a 128-entry ring where the host
posts empty buffers (`wp`) and the modem consumes them (`rp`). Converting the
debugfs pointers to descriptor indices:

| | modem rp | host wp | last doorbell | posted, unconsumed |
|---|---|---|---|---|
| healthy baseline | 15 | 15 | 85 | **0** |
| during the stall | 26 | 4 | 5 | **106** |

The modem had 106 of 128 buffers available and filled none of them for the
whole freeze. The downlink event ring was drained to empty, and the controller
reported `M0 / Active / MISSION MODE` throughout, so the device was awake.

Meanwhile the uplink channel was entirely healthy: 23 descriptors outstanding
and its doorbell current with its write pointer.

**Conclusion: the host is not starving the ring. Packets never reach the host,
so nothing above the MHI bus can be responsible.**

## What is left

Two candidates, both below the driver's RX path.

**1. A burst-mode doorbell that stops being rung.** Both data channels are
configured `MHI_DB_BRST_ENABLE`, where `mhi_db_brstmode()` writes the doorbell
register only while `db_mode` is set, and clears it after each write. The modem
re-arms it by sending a `MHI_EV_CC_DB_MODE` event. If that event is missed or
never sent, the host keeps posting buffers into shared memory and updating
`wp`, but never pokes the doorbell, and the modem never learns the buffers are
there. The capture is consistent with this: the last doorbell was index 5 while
the host's write pointer had wrapped the whole ring round to index 4.

Testing it means a one-line change to the channel config
(`MHI_DB_BRST_ENABLE` -> `MHI_DB_BRST_DISABLE` on channels 100 and 101), which
makes the host write the doorbell on every posted buffer. Costs one MMIO write
per buffer; if the stall disappears, this is the cause.

**2. The modem firmware simply stops sending.** The cellular LED has been seen
dropping from three bars to one and back around a stall. Distinguishing this
needs the modem's own view during a freeze - registration state and RRC state -
rather than the host's.

Note that `doorbell_mode_switch` is true for these channels, so an M3 to M0
power transition re-arms `db_mode` and rings the doorbell. That is a plausible
explanation for why generating traffic (replugging the LAN cable, which makes a
client re-DHCP) appears to clear the stall.

## Instrumentation

`x3000/docs/wanlog.sh` records the ring pointers on every sample, so the next
capture shows the whole stall rather than one snapshot of it. The columns to
watch are `dl_out` (buffers posted and unconsumed) and `dl_db` (last doorbell).
