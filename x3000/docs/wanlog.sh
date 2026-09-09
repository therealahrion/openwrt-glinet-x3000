#!/bin/sh
# WAN downlink recorder for the GL-X3000.
#
# Samples the wwan0 counters and the per-vector MHI interrupt counts into a CSV
# every few seconds, and dumps the MHI ring state whenever the downlink goes
# flat while the uplink is still moving.
#
# Why the ring dump matters. When the link stalls, rx_packets freezes for
# minutes while tx_packets keeps climbing and the downlink MSI vector stops
# firing entirely. Two very different faults look identical from outside the
# kernel:
#
#   - the modem stopped writing        -> DL descriptors queued but untouched
#   - the host ran out of RX buffers   -> DL ring empty, nowhere to write
#
# /sys/kernel/debug/mhi/*/channels separates them by showing each channel's
# read and write pointers. Requires CONFIG_MHI_BUS_DEBUG=y in the running
# kernel; without it the dumps are simply empty and the CSV still works.
#
# /tmp does not survive a sysupgrade, so after every flash fetch this again:
#
#   curl -sSfL -o /tmp/wanlog.sh \
#     https://raw.githubusercontent.com/therealahrion/openwrt-glinet-x3000/openwrt-25.12/x3000/docs/wanlog.sh
#   sh /tmp/wanlog.sh &
#
# Output:
#   /tmp/wan2.csv         one row per sample
#   /tmp/wan2-stall.log   ring dumps, written only around a stall
#
# Stop it with:  kill $(cat /tmp/wanlog.pid)
#
# Written for busybox: no stat, no pgrep, no gawk extensions, and ping -W/-c
# take integers only.

IFACE=${IFACE:-wwan0}
UCI_IFACE=${UCI_IFACE:-wwan}
PING_TARGET=${PING_TARGET:-1.1.1.1}
DNS_TARGET=${DNS_TARGET:-openwrt.org}
SLEEP=${SLEEP:-5}
CSV=${CSV:-/tmp/wan2.csv}
LOG=${LOG:-/tmp/wan2-stall.log}
PIDFILE=${PIDFILE:-/tmp/wanlog.pid}

# While a stall persists, re-dump the rings every Nth sample rather than every
# one, so a two-minute freeze leaves a readable log instead of 24 dumps.
DUMP_EVERY=${DUMP_EVERY:-6}

S=/sys/class/net/$IFACE/statistics
if [ ! -d "$S" ]; then
	echo "wanlog: $IFACE has no statistics directory - is the modem up?" >&2
	exit 1
fi

echo $$ > "$PIDFILE"

# Column order matches the MHI vectors as they appear in /proc/interrupts.
# On this board that is 88/89/90/91, where 90 is the uplink completion vector
# and 91 the downlink. Confirmed by the 90 delta tracking tx_packets exactly.
[ -f "$CSV" ] || \
	echo "time,rx_pkts,rx_drop,tx_pkts,irq88,irq89,irq90,irq91,ping,dns,up" > "$CSV"

# Sum every CPU column for each MHI interrupt. Reading only CPU0 would show a
# false freeze if the vector ever migrated to the other core.
mhi_irqs() {
	awk '/mhi/ {
		t = 0
		for (i = 2; i <= NF; i++) {
			if ($i ~ /^[0-9]+$/) t += $i; else break
		}
		printf "%s,", t
	}' /proc/interrupts
}

dump() {
	{
		echo "===== $1  $(date '+%F %T')  rx=$RP tx=$TP ====="
		cat /sys/kernel/debug/mhi/*/channels 2>/dev/null
		echo "--- events ---"
		cat /sys/kernel/debug/mhi/*/events 2>/dev/null
		echo "--- states ---"
		cat /sys/kernel/debug/mhi/*/states 2>/dev/null
		echo "--- interrupts ---"
		grep mhi /proc/interrupts
		echo
	} >> "$LOG"
}

PREV_RX=-1
PREV_TX=-1
STALL=0
FIRST=1

while :; do
	RP=$(cat $S/rx_packets)
	RD=$(cat $S/rx_dropped)
	TP=$(cat $S/tx_packets)
	MI=$(mhi_irqs)

	P=$(ping -c1 -W2 "$PING_TARGET" 2>/dev/null | sed -n 's/.*time=\([0-9.]*\).*/\1/p')
	[ -z "$P" ] && P=TIMEOUT

	if nslookup "$DNS_TARGET" >/dev/null 2>&1; then D=ok; else D=FAIL; fi

	U=$(ifstatus "$UCI_IFACE" 2>/dev/null | grep -o '"up": [a-z]*' | cut -d' ' -f2)
	[ -z "$U" ] && U=unknown

	echo "$(date +%H:%M:%S),$RP,$RD,$TP,$MI$P,$D,$U" >> "$CSV"

	# One healthy dump up front, so a stall can be diffed against it.
	if [ "$FIRST" -eq 1 ]; then
		dump BASELINE
		FIRST=0
	fi

	# A stall is the downlink standing still while the uplink still moves.
	# Requiring tx to advance is what keeps idle periods out of the log - the
	# ping above guarantees traffic, so tx only stops if the link is truly gone.
	if [ "$PREV_RX" -ge 0 ] && [ "$RP" -eq "$PREV_RX" ] && [ "$TP" -gt "$PREV_TX" ]; then
		if [ "$STALL" -eq 0 ]; then
			dump STALL-BEGIN
		elif [ $((STALL % DUMP_EVERY)) -eq 0 ]; then
			dump STALL-HOLD
		fi
		STALL=$((STALL + 1))
	else
		[ "$STALL" -gt 0 ] && dump STALL-END
		STALL=0
	fi

	PREV_RX=$RP
	PREV_TX=$TP
	sleep "$SLEEP"
done
