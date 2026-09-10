# Settings that live in the modem, not in this repo

The RM520N-GL keeps some configuration in its own non-volatile memory. Those
settings survive reflashing the router, including a return to GL.iNet stock
firmware, because nothing on the host ever writes them. They are invisible to
`uci show` and to git, and they will quietly shape the behaviour of any test
run against this unit until someone reads them back.

This bit us: a band lock set years earlier in GL.iNet's admin panel was still
active through every build in this repo, and was only found by asking the modem
directly.

## Reading the current state

    quectel-at 'AT+QNWPREFCFG="mode_pref"' 'AT+QNWPREFCFG="nr5g_band"' \
      'AT+QNWPREFCFG="nsa_nr5g_band"' 'AT+QNWPREFCFG="lte_band"' \
      'AT+QNWPREFCFG="nr5g_disable_mode"' 'AT+QNWPREFCFG="ue_usage_setting"'

`AT+QNWPREFCFG=?` lists everything the firmware supports. There is no
modem-side MTU setting on this firmware - that was enumerated and confirmed
absent, so MTU is host-side only.

## As set on 2026-09-10

    mode_pref          AUTO
    nr5g_band          25:41:71        <- restricted, T-Mobile US bands only
    nsa_nr5g_band      (full list)
    lte_band           (full list)
    nr5g_disable_mode  2
    ue_usage_setting   1

`nr5g_band` was deliberately narrowed from the full 28-band list. The factory
default is every band the modem supports; restoring it means writing that list
back explicitly, not resetting the router.

`nr5g_disable_mode` was set to 2 while trying to force 5G SA. The polarity is
not documented in a way we could confirm - setting 2 left the modem on NSA,
which suggests 2 disables SA rather than NSA, but that was never proven. Forcing
SA also needs `mode_pref` set to NR5G, and the one attempt at that had its write
swallowed when the AT server went briefly mute during the `CFUN` cycle.

## Cautions

Changing the radio access technology over AT can wedge the modem's USB-side AT
server - vjt removed his watchdog's `mode_toggle` recovery action for exactly
that reason. Space commands out rather than firing them back to back, and read
each write back before moving on.

`AT+CFUN=0` powers the SIM down, so ModemManager will cache a
`MM_FAILED_REASON_SIM_MISSING` error that outlives the actual condition. Clear
it with `ifdown wwan; ifup wwan`.

A radio-only cycle (`CFUN=0` then `CFUN=1`) does not reset these settings. A
full modem reset does.
