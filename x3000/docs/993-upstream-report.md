# Draft: reporting the MHI burst-mode doorbell deadlock upstream

Not sent yet. This is the report we would send, kept here so the argument and
the evidence stay in one place and stay revisable.

## Where it goes

    M:  Manivannan Sadhasivam <manivannan.sadhasivam@linaro.org>
    L:  mhi@lists.linux.dev
    L:  linux-arm-msm@vger.kernel.org

from `MAINTAINERS`, entry "MHI BUS".

Subject line, roughly:

    bus: mhi: host: IP_HW0 downlink deadlocks when nothing re-arms the
    burst-mode doorbell

Send as a bug report, not a patch series. The change we run locally is a debug
knob, not an upstream-shaped fix, and the right fix is a question for the
maintainer - see "What we are asking" below.

## Why this is worth their time

The device we tested is bound through an out-of-tree PCI ID patch (Qualcomm
vendor and subvendor, `0x17cb:0x0308` / `0x17cb:0x5201` - a GL.iNet variant of
the RM520N-GL not in the upstream table). That has to be disclosed up front.

It does not make the report device-specific, though. That patch binds to the
existing `mhi_quectel_rm5xx_info`, and upstream already claims the RM520N-GL
under its own IDs:

    { PCI_DEVICE(PCI_VENDOR_ID_QUECTEL, 0x1004),   /* RM520N-GL (sdx6x), eSIM */
            .driver_data = (kernel_ulong_t) &mhi_quectel_rm5xx_info },
    { PCI_DEVICE(PCI_VENDOR_ID_QUECTEL, 0x1007),   /* RM520N-GL, Lenovo variant */
            .driver_data = (kernel_ulong_t) &mhi_quectel_rm5xx_info },

Same info struct, same `modem_quectel_em1xx_config`, same
`MHI_CHANNEL_CONFIG_HW_UL(100, ...)` / `_HW_DL(101, ...)`. So a stock kernel on
an off-the-shelf RM520N-GL should be exposed identically.

## Symptom

Sustained downlink over `mhi_wwan_mbim` stops dead, tens of seconds at a time,
while the uplink keeps working and the modem stays registered. It appears above
roughly 200 Mbps and recovers on its own. The interface never changes state and
`dmesg` is clean.

## The measurement

Kernel 6.12.103, `CONFIG_MHI_BUS_DEBUG=y`, `kernel.kptr_restrict=1` so the
driver's own ring pointers are readable rather than hashed.

    09:26:29  rx=2005672  tx=694409  irq91=68126  dl_qd=127  dl_free=0
    09:27:12  rx=2005672  tx=695170  irq91=68126  dl_qd=127  dl_free=0

Forty-three seconds. `rx` frozen to the exact packet; `tx` still climbing by
761; the uplink event-ring vector up 853; the downlink event-ring vector not
firing once. The downlink ring was **completely full** - 127 posted, zero free -
which rules out host-side buffer starvation: the host had done all it could and
the device had consumed nothing.

Everything else was healthy at the same instant. Downlink completion-ring
backlog 1 of 1024, both CPUs at 0-6 percent, `M0`/`M3` counters frozen at
1503/1502, radio fine (RSRP -100, SINR 17), bearer up for 37,128 s.

Channel 101 state from debugfs during the freeze:

    local rp   66      (driver's own ring pointers)
    local wp   65
    ctxt wp    65
    db         66      (db_cfg.db_val, last real doorbell write)
    device rp  46

The host had gone a full lap of a 128-element ring and written the doorbell
zero times. `db` still pointed where it had been one lap earlier.

## Mechanism, as we read it

`MHI_CHANNEL_CONFIG_HW_UL`/`_HW_DL` set `.doorbell = MHI_DB_BRST_ENABLE` and
`.doorbell_mode_switch = true`, so `parse_ch_cfg()` selects `mhi_db_brstmode()`
as `process_db`, and that only writes while a one-shot flag is set:

    void mhi_db_brstmode(...)
    {
            if (db_cfg->db_mode) {
                    db_cfg->db_val = db_val;
                    mhi_write_db(mhi_cntrl, db_addr, db_val);
                    db_cfg->db_mode = 0;
            }
    }

Two things re-arm `db_mode`:

  * `MHI_EV_CC_DB_MODE` / `MHI_EV_CC_OOB` from the device (`main.c`, the
    `mhi_process_ctrl_ev_ring` transfer-event path), and
  * `mhi_pm_m0_transition()`, for channels whose `db_cfg.reset_req` is set -
    which `parse_ch_cfg()` takes from `doorbell_mode_switch`.

On this device the first never happens under load, and the second cannot,
because the M0 transition only occurs on resume from M3 - and `mhi_queue()`
takes a runtime-PM reference per queued buffer, so sustained traffic keeps the
device out of M3 entirely. We measured the counters standing still for the whole
freeze.

M2 is not an escape either: `states` reports **`M2: 0`** after 80 M0 and 79 M3
transitions, so this modem cycles M0 to M3 under endpoint runtime PM and never
announces M1 at all.

So under sustained traffic there is no path that re-arms the doorbell. If the
device stops asking - and it does - the host silently stops telling it about
buffers it has already posted, and the downlink deadlocks until traffic drops
far enough for a suspend/resume cycle.

## Corroboration

We could find nothing in `Documentation/mhi/` describing burst mode or the
DB_MODE event at all. The closest thing to a specification is Qualcomm's own
downstream device-tree binding, which documents `mhi,db-mode-switch` as:

    Must switch to doorbell mode whenever MHI M0 state transition happens.

That is an independent statement that M0 transitions are the re-arm trigger,
matching what we measured, and it describes no other host-side re-arm - the
device is expected to ask.

## Upstream state

We diffed the whole of `drivers/bus/mhi/host/` from 6.12.103 to mainline
master. There is no change touching `brstmode`, `db_mode`, `db_cfg` or the
doorbell logic; the one `mhi_ring_chan_db()` change in `main.c` is the removal
of the unrelated `pre_alloc`/auto-queue path. `MHI_CHANNEL_CONFIG_HW_UL`/`_DL`
still use `MHI_DB_BRST_ENABLE` with `doorbell_mode_switch = true`.

## What we run locally

A module parameter on `mhi`, default off, that downgrades `MHI_DB_BRST_ENABLE`
channels to `MHI_DB_BRST_DISABLE` in `parse_ch_cfg()` so the doorbell is written
unconditionally on every queued buffer. With it on, `db` tracks `wp` on every
sample and the stalls stop; the box has held sustained 250+ Mbps in the band
where it previously deadlocked. Cost is two MMIO writes per queued buffer.

We are not proposing that as the fix. It is a bisection tool.

## What we are asking

  * Is `doorbell_mode_switch = true` correct for these HW channels on sdx6x
    devices, or inherited? `mhi_quectel_rm5xx_info` reuses
    `modem_quectel_em1xx_config`, which is the sdx24 configuration.
  * Is the device expected to emit `MHI_EV_CC_DB_MODE` under sustained load,
    making this a modem firmware bug we should take to Quectel?
  * If not, should the host re-arm on some condition other than an M0
    transition - for instance when a channel ring fills - or should these
    channels simply not use burst mode?

We can test patches on the hardware.

## Weakness to disclose

The reverse direction has not been run. We have a clean capture of the deadlock
with the workaround off, and sustained clean operation with it on, but not a
controlled reproduction at matched throughput with it switched back off. A
maintainer will reasonably ask for that, and it should be produced before
sending. It is tracked here as task #90.

Also worth stating plainly: the pointer values above need
`CONFIG_MHI_BUS_DEBUG=y` and `kernel.kptr_restrict=1`, since the driver's own
ring pointers print through `%pK`.
