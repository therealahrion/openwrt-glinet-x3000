# When the WAN hangs

Short version: leave it broken, wait two minutes, run one command, send the
output. Everything else on this page is detail.

## 1. Do not fix it

No replugging the LAN cable, no `ifup wwan`, no reboot. Every one of those
clears the fault before it can be measured, and the LAN replug in particular
forces the exact power transition that hides the thing being investigated.

Two full minutes is the target. The recorders sample every one and five
seconds, so a stall shorter than that leaves too little to read.

## 2. Capture

    tail -40 /tmp/dl.csv; echo ---; tail -12 /tmp/wan2.csv; echo ---; 5g-info; echo ---; tail -60 /tmp/wan2-stall.log

That is the whole capture. Nothing else is needed.

## 3. Reading it

First check `ping` and `dns` in the `wan2.csv` rows. If the router itself is
still reaching 1.1.1.1 normally, the fault is on the LAN side and the modem is
not involved at all - that has happened twice and looked exactly like a modem
stall from the client's chair.

If the router is affected too:

| what the columns show | what it means |
|---|---|
| `dl_db` frozen while `dl_wp` keeps moving, `irq91` flat | the burst-mode doorbell case; 993 is the fix |
| `dl_qd` collapsing toward 0 | host ran out of RX buffers, which would make it ours |
| RSRP or SINR falling apart in `5g-info` | the radio; no code change helps |
| `er3_bk` climbing toward 1023 | the event drain loop fell behind |

Healthy reference values, measured on this hardware: `dl_qd` sawtooths between
about 65 and 127 (the floor is where the driver refills, at half the queue),
`er3_bk` sits at 1 and has never been seen above 10 of 1024, and both CPUs stay
near idle.

Note a lost ping alone triggers a dump, which catches degradation as well as
hard freezes - but it also fires on plain bufferbloat during a fast transfer.
Check whether `rx` was still climbing through the window before calling it a
stall; on 2026-09-10 a six-second dump turned out to have rx moving at twice
its average rate.

## 4. Do not touch 993 during a hang

**993 is already on.** The image sets it at every boot, from
`x3000/files-common/etc/modules.d/mhi-doorbell`, so
`/sys/module/mhi/parameters/force_db_brst_disable` reads `Y` on a running box.
Corrected 2026-09-12; this page previously said to turn it on, which was true
only before it was baked in.

Changing it either way requires an unbind/bind, and that re-initialises the MHI
channels - which clears a doorbell deadlock by itself. Whatever you did would
look like the fix.

Check what it is set to:

    cat /sys/module/mhi/parameters/force_db_brst_disable    # Y on a stock image
    dmesg | grep 'forcing doorbell writes'                  # names channels 100 and 101

The A/B that is still missing runs the other way: turn it **off** while
everything is healthy and see whether the stall comes back at matched
throughput. That is the controlled reproduction the upstream report names as its
weakness, and it has not been run.

    echo 0 > /sys/module/mhi/parameters/force_db_brst_disable
    echo 0000:01:00.0 > /sys/bus/pci/drivers/mhi-pci-generic/unbind
    echo 0000:01:00.0 > /sys/bus/pci/drivers/mhi-pci-generic/bind

Write 1 and re-probe to go back, or just reboot - the image sets it again. Do
not leave the box running with it off unattended; that is the configuration the
deadlock was captured in.

## 5. After a reboot or a flash

The recorders are part of the image now, at `/usr/bin/wanlog` and
`/usr/bin/dlwatch`, so there is nothing to fetch. `kernel.kptr_restrict=1` also
ships, in `/etc/sysctl.d/40-kptr-restrict.conf`. Just start them:

    wanlog & dlwatch &

Their logs still live in `/tmp` and are still lost on reboot - only the tools
are permanent.

`kptr_restrict` matters: without it the driver's ring pointers print as hashes
and `dl_qd`/`dl_free` record -1 for the whole run. If you are on an image
predating the sysctl file, set it by hand first with
`sysctl -w kernel.kptr_restrict=1`.

Confirm the recorders took, since a failed start is silent in the background:

    sleep 8; wc -l /tmp/dl.csv /tmp/wan2.csv

## 6. Sharing a whole capture

    collect-logs

Bundles the logs plus a snapshot of ring, radio, interrupt and dmesg state, and
prints a URL to fetch it from. Delete the copy it leaves in /www afterwards.
