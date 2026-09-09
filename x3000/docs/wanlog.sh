#!/bin/sh
# WAN downlink recorder for the GL-X3000.
#
# Samples wwan0's counters, the per-vector MHI interrupt counts and the MHI
# ring pointers into a CSV every few seconds, and dumps the full MHI state
# whenever the downlink goes flat while the uplink is still moving.
#
# What the ring columns mean, and why they settle the question.
#
# IP_HW0_MBIM is one 5G data channel in each direction, each a 128-entry ring
# of descriptors (drivers/bus/mhi/host/pci_generic.c, MHI_CHANNEL_CONFIG_HW_*):
#
#   channel 100  uplink,   host -> modem
#   channel 101  downlink, modem -> host
#
# For the downlink the host posts empty buffers and the modem fills them. Three
# pointers describe that, all visible in /sys/kernel/debug/mhi/*/channels:
#
#   wp   host's write pointer, in shared memory. Written by the host on every
#        buffer it posts (mhi_ring_chan_db).
#   rp   modem's read pointer, in the same shared memory. Written by the modem
#        as it consumes buffers. The host only ever initialises it.
#   db   the value of the last actual doorbell register write. Both data
#        channels run in burst mode (MHI_DB_BRST_ENABLE), where the host writes
#        the doorbell only when the modem has asked for one, so db normally
#        trails wp by a long way. That is by design, not a fault.
#
# dl_out = (wp - rp) mod 128 is therefore the number of buffers the modem has
# been given and has not filled. It splits the two faults that look identical
# from outside the kernel:
#
#   dl_out near 0        the host ran out of buffers to post - our problem,
#                        in mhi_net_rx_refill_work
#   dl_out high, frozen  the modem has somewhere to write and is not writing -
#                        below the driver, nothing above MHI can be at fault
#
# And when dl_out is high, dl_db separates those further: if dl_wp keeps
# advancing while dl_db stands still, the host is posting buffers the modem is
# never told about (a burst-mode doorbell that stopped being rung). If dl_db
# tracks dl_wp, the modem has been told and is ignoring it.
#
# m0/m3 count power-state transitions and pend is uplink packets in flight, so
# a stall that lines up with a suspend/resume cycle is visible too.
#
# Requires CONFIG_MHI_BUS_DEBUG=y. Without it the ring columns read -1 and the
# rest of the CSV still works.
#
# /tmp does not survive a sysupgrade, so after every flash fetch this again:
#
#   curl -sSfL -o /tmp/wanlog.sh \
#     https://raw.githubusercontent.com/therealahrion/openwrt-glinet-x3000/openwrt-25.12/x3000/docs/wanlog.sh
#   sh /tmp/wanlog.sh &
#
# Output:
#   /tmp/wan2.csv         one row per sample
#   /tmp/wan2-stall.log   full ring dumps, written only around a stall
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

# Ring size in descriptors, from MHI_CHANNEL_CONFIG_HW_UL/DL(.., 128, ..).
RING=${RING:-128}
RBYTES=${RBYTES:-0x800}

# While a stall persists, re-dump the rings every Nth sample rather than every
# one, so a two-minute freeze leaves a readable log instead of 24 dumps.
DUMP_EVERY=${DUMP_EVERY:-6}

# /tmp is RAM on this box and a lost ping now triggers a dump, so cap how many
# get written. Roughly 100 lines each; 40 is a few hundred KB worst case.
MAX_DUMPS=${MAX_DUMPS:-40}

MHI_CHAN=$(ls /sys/kernel/debug/mhi/*/channels 2>/dev/null | head -1)
MHI_DIR=${MHI_CHAN%/channels}

S=/sys/class/net/$IFACE/statistics
if [ ! -d "$S" ]; then
	echo "wanlog: $IFACE has no statistics directory - is the modem up?" >&2
	exit 1
fi
[ -n "$MHI_CHAN" ] || echo "wanlog: no MHI debugfs, ring columns will read -1" >&2

echo $$ > "$PIDFILE"

# Which /proc/interrupts line is which, from the driver rather than by
# correlation. Each event ring takes MSI vector (ring + 1); vector 0 is the
# BHI control interrupt and is named "bhi", while rings 0-3 are all named
# "mhi" and appear in vector order (mhi_init_irq_setup, pci_generic.c):
#
#   88  event ring 0  control and the software channels (MBIM, DUN, NMEA)
#   89  event ring 1  DIAG
#   90  event ring 2  IP_HW0_MBIM(100), uplink
#   91  event ring 3  IP_HW0_MBIM(101), downlink
#
# The debugfs events dump agrees: rings 0 and 1 hold 128 elements, rings 2
# and 3 hold 1024, matching MHI_EVENT_CONFIG_CTRL/DATA vs HW_DATA.
[ -f "$CSV" ] || echo "time,rx_pkts,rx_drop,tx_pkts,irq88,irq89,irq90,irq91,dl_qd,dl_free,dl_wp,dl_db,dev_rp,ul_qd,m0,m3,pend,ping,dns,up" > "$CSV"

# Sum every CPU column for each MHI interrupt. Reading only CPU0 would show a
# false freeze if a vector ever migrated to the other core.
mhi_irqs() {
	awk '/mhi/ {
		t = 0
		for (i = 2; i <= NF; i++) {
			if ($i ~ /^[0-9]+$/) t += $i; else break
		}
		printf "%s,", t
	}' /proc/interrupts
}

# Pull base/rp/wp/db for both data channels in one pass. Field positions are
# fixed by mhi_debugfs_channels_show(); db prints with a doubled 0x prefix.
chan_raw() {
	awk '/IP_HW0_MBIM\(100\)/ { a=$23; b=$26 }
	     /IP_HW0_MBIM\(101\)/ { c=$23; d=$26; e=$14; f=$18; g=$20; h=$28 }
	     END { gsub("0x0x","0x",h); print a,b,c,d,e,f,g,h }' \
	    "$MHI_CHAN" 2>/dev/null
}

# Pointer -> descriptor index. The modem writes rp through the PCIe inbound
# window, so its value carries a high-word offset the host's does not; mask to
# 32 bits before subtracting the ring base.
off() { L=${1#0x}; L=${L#${L%????}}; echo $(( 0x$L & (RBYTES - 1) )); }
real() { case "$1" in 0xffff*) return 0;; *) return 1;; esac; }

# Forward distance from rp to wp: descriptors posted and not yet consumed.
outstanding() { echo $(( ($2 - $1 + RBYTES) % RBYTES )); }

DUMPS=0

dump() {
	DUMPS=$((DUMPS + 1))
	if [ "$DUMPS" -gt "$MAX_DUMPS" ]; then
		[ "$DUMPS" -eq $((MAX_DUMPS + 1)) ] &&
			echo "===== further dumps suppressed after $MAX_DUMPS =====" >> "$LOG"
		return
	fi
	{
		echo "===== $1  $(date '+%F %T')  rx=$RP tx=$TP dl_qd=$DL_QD dl_free=$DL_FREE ====="
		cat "$MHI_DIR/channels" 2>/dev/null
		echo "--- events ---"
		cat "$MHI_DIR/events" 2>/dev/null
		echo "--- states ---"
		cat "$MHI_DIR/states" 2>/dev/null
		echo "--- interrupts ---"
		grep mhi /proc/interrupts
		echo "--- radio ---"
		command -v 5g-info >/dev/null 2>&1 && 5g-info 2>/dev/null
		echo "--- dmesg tail ---"
		dmesg 2>/dev/null | tail -12
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

	set -- $(chan_raw)
	if [ $# -eq 8 ]; then
		DL_WP=$(( $(off "$7") / 16 )); DL_DB=$(( $(off "${8#0x0x}") / 16 ))
		DEV_RP=$(( $(off "$6") / 16 ))
		if real "$3" && real "$4"; then
			DL_QD=$(( $(outstanding "$(off "$3")" "$(off "$4")") / 16 ))
			DL_FREE=$(( RING - 1 - DL_QD ))
		else
			DL_QD=-1; DL_FREE=-1
		fi
		if real "$1" && real "$2"; then
			UL_QD=$(( $(outstanding "$(off "$1")" "$(off "$2")") / 16 ))
		else
			UL_QD=-1
		fi
	else
		DL_WP=-1; DL_DB=-1; DEV_RP=-1; DL_QD=-1; DL_FREE=-1; UL_QD=-1
	fi

	PM=$(awk '/^M0:/ { print $2, $6, $NF }' "$MHI_DIR/states" 2>/dev/null)
	set -- $PM
	M0=${1:--1}; M3=${2:--1}; PEND=${3:--1}

	P=$(ping -c1 -W2 "$PING_TARGET" 2>/dev/null | sed -n 's/.*time=\([0-9.]*\).*/\1/p')
	[ -z "$P" ] && P=TIMEOUT

	if nslookup "$DNS_TARGET" >/dev/null 2>&1; then D=ok; else D=FAIL; fi

	U=$(ifstatus "$UCI_IFACE" 2>/dev/null | grep -o '"up": [a-z]*' | cut -d' ' -f2)
	[ -z "$U" ] && U=unknown

	echo "$(date +%H:%M:%S),$RP,$RD,$TP,$MI$DL_QD,$DL_FREE,$DL_WP,$DL_DB,$DEV_RP,$UL_QD,$M0,$M3,$PEND,$P,$D,$U" >> "$CSV"

	# One healthy dump up front, so a stall can be diffed against it.
	if [ "$FIRST" -eq 1 ]; then
		dump BASELINE
		FIRST=0
	fi

	# Two different faults have been seen, and the first version of this only
	# caught one of them.
	#
	# A hard freeze is the downlink standing still while the uplink still
	# moves: rx_packets identical across two samples with tx_packets climbing.
	# Requiring tx to advance keeps idle periods out of the log, since the
	# ping above guarantees traffic.
	#
	# But an event on 2026-09-09 around 17:11 produced no dump at all, because
	# rx never stopped for a whole five-second sample - it degraded instead,
	# with round trips running from 34 ms to 422 ms and repeated timeouts while
	# data still trickled through. A lost ping is the most direct evidence of
	# that, so treat it as a trigger too rather than waiting for a full stop.
	STALLED=0
	if [ "$PREV_RX" -ge 0 ] && [ "$RP" -eq "$PREV_RX" ] && [ "$TP" -gt "$PREV_TX" ]; then
		STALLED=1
	elif [ "$P" = TIMEOUT ]; then
		STALLED=1
	fi

	if [ "$STALLED" -eq 1 ]; then
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
