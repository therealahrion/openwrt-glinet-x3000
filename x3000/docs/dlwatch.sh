#!/bin/sh
# 1 Hz downlink watcher for the GL-X3000, for catching the moment a stall
# starts rather than its aftermath.
#
# wanlog.sh samples every five seconds and spends most of that on a ping and a
# DNS lookup, which is too coarse to see a stall that only appears above
# roughly 200-300 Mbps. This does no network I/O at all: it reads four files a
# second and writes one short row, so it can run alongside a speed test.
#
# The columns that matter, and what they would mean:
#
#   dl_out    downlink descriptors posted by the host and not yet consumed by
#             the modem, out of 128. Near zero means the host could not post
#             buffers fast enough. High and frozen means the modem has
#             somewhere to write and is not writing.
#
#   er3_bk    unprocessed entries in the downlink completion ring, out of 1024.
#             This is the one to watch. mhi_ev_task() drains that ring with no
#             budget (event_quota is U32_MAX) and calls the MBIM receive path
#             inline for every entry, so all the de-aggregation, per-datagram
#             allocation and copying happens inside the drain loop. If the loop
#             cannot keep up, this backs up. 1 means drained, 1023 means the
#             ring is full and the modem has nowhere to report completions.
#
#   er2_bk    the same for the uplink ring, as a control.
#
#   cpu0/cpu1 percent busy and percent in softirq over the last second. All
#             four MHI vectors land on CPU0, and a tasklet runs on whichever
#             CPU took the interrupt, so if CPU0 saturates in softirq during a
#             fast transfer that is the drain loop falling behind.
#
# Usage:  sh /tmp/dlwatch.sh &     then run the speed test
# Output: /tmp/dl.csv
# Stop:   kill $(cat /tmp/dlwatch.pid)

IFACE=${IFACE:-wwan0}
OUT=${OUT:-/tmp/dl.csv}
PIDFILE=${PIDFILE:-/tmp/dlwatch.pid}
RING=${RING:-128}

MHI_CHAN=$(ls /sys/kernel/debug/mhi/*/channels 2>/dev/null | head -1)
MHI_DIR=${MHI_CHAN%/channels}
S=/sys/class/net/$IFACE/statistics

[ -d "$S" ] || { echo "dlwatch: no $IFACE" >&2; exit 1; }
[ -n "$MHI_CHAN" ] || { echo "dlwatch: no MHI debugfs" >&2; exit 1; }

echo $$ > "$PIDFILE"
[ -f "$OUT" ] || echo "time,rx,tx,irq90,irq91,dl_rp,dl_wp,dl_db,dl_out,er3_bk,er2_bk,cpu0_busy,cpu0_si,cpu1_busy,cpu1_si" > "$OUT"

idx() { echo $(( ( ($2 & 0xffffffff) - $1 ) / 16 )); }
gap() { echo $(( ($1 - $2 + $3) % $3 )); }

PC0T=0; PC0I=0; PC0S=0; PC1T=0; PC1I=0; PC1S=0

while :; do
	RX=$(cat $S/rx_packets)
	TX=$(cat $S/tx_packets)

	set -- $(awk '/mhi/ { t=0; for (i=2;i<=NF;i++){ if($i~/^[0-9]+$/) t+=$i; else break }; printf "%s ", t }' /proc/interrupts)
	I90=${3:--1}; I91=${4:--1}

	set -- $(awk '/IP_HW0_MBIM\(101\)/ { print $14, $18, $20, $28 }' "$MHI_CHAN" 2>/dev/null)
	if [ $# -eq 4 ]; then
		DB4=${4#0x0x}; DB4=0x$DB4
		DRP=$(idx "$1" "$2"); DWP=$(idx "$1" "$3"); DDB=$(idx "$1" "$DB4")
		DOUT=$(gap "$DWP" "$DRP" "$RING")
	else
		DRP=-1; DWP=-1; DDB=-1; DOUT=-1
	fi

	E3=-1; E2=-1
	set -- $(awk '/^Index: 3 /{ print $9, $11, $13, $15 }' "$MHI_DIR/events" 2>/dev/null)
	[ $# -eq 4 ] && E3=$(gap "$(idx "$1" "$3")" "$(idx "$1" "$4")" "$(( $2 / 16 ))")
	set -- $(awk '/^Index: 2 /{ print $9, $11, $13, $15 }' "$MHI_DIR/events" 2>/dev/null)
	[ $# -eq 4 ] && E2=$(gap "$(idx "$1" "$3")" "$(idx "$1" "$4")" "$(( $2 / 16 ))")

	set -- $(awk '/^cpu[01] /{ t=0; for(i=2;i<=NF;i++) t+=$i; print t, $5, $8 }' /proc/stat)
	C0T=$1; C0I=$2; C0S=$3; C1T=$4; C1I=$5; C1S=$6
	D0=$((C0T - PC0T)); D1=$((C1T - PC1T))
	if [ "$D0" -gt 0 ]; then
		B0=$(( (D0 - (C0I - PC0I)) * 100 / D0 )); S0=$(( (C0S - PC0S) * 100 / D0 ))
	else B0=0; S0=0; fi
	if [ "$D1" -gt 0 ]; then
		B1=$(( (D1 - (C1I - PC1I)) * 100 / D1 )); S1=$(( (C1S - PC1S) * 100 / D1 ))
	else B1=0; S1=0; fi
	PC0T=$C0T; PC0I=$C0I; PC0S=$C0S; PC1T=$C1T; PC1I=$C1I; PC1S=$C1S

	echo "$(date +%H:%M:%S),$RX,$TX,$I90,$I91,$DRP,$DWP,$DDB,$DOUT,$E3,$E2,$B0,$S0,$B1,$S1" >> "$OUT"
	sleep 1
done
