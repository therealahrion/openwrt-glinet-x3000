#!/bin/sh
# =============================================================================
# wwan0 receive-path A/B: where the datagrams are dropped, and what stops it.
#
#   sh gro-backlog-ab.sh
#
# Four load-matched windows under the same sustained download:
#   backlog-1000   GRO on, netdev_max_backlog at its default
#   backlog-2000   GRO on, twice the queue
#   backlog-4000   GRO on, four times the queue
#   threaded-1k    GRO on, default queue, NAPI moved to kernel threads
#
# What it is looking for. At ~20k datagrams/s this link overflows a queue and
# drops about 0.2% of them. Which queue depends on GRO:
#   rx_dropped moves, softnet_dropped stays 0  -> the gro_cells queue
#                                                 (net/core/gro_cells.c:32)
#   rx_dropped and softnet_dropped move together -> the RPS backlog
#                                                 (cpu_backlog_drop in dev.c)
# Both are capped by the same net.core.netdev_max_backlog. time_squeeze has
# stayed 0 throughout, so the NAPI is not running out of poll budget - the
# queues fill between polls, which is a scheduling-latency problem and the
# reason the threaded window is worth running before reaching for a bigger
# bucket.
#
# A deeper queue trades loss for latency, so each window also reports RTT under
# load. That is the number that decides whether a larger backlog is worth
# baking.
#
# Costs roughly 1.5-2 GB of cellular data. Everything is restored on exit,
# including Ctrl-C: netdev_max_backlog, the threaded flag, GRO, and the load.
# =============================================================================

WANIF=${WANIF:-wwan0}
URL=${URL:-https://hil-speed.hetzner.com/1GB.bin}
STREAMS=${STREAMS:-4}
WINDOW=${WINDOW:-12}
PINGTGT=${PINGTGT:-1.1.1.1}

say() { printf '%s\n' "$*"; }

# ---- guards ---------------------------------------------------------------
[ -d /sys/class/net/$WANIF ] || { say "FATAL: $WANIF does not exist"; exit 1; }
grep -q up /sys/class/net/$WANIF/operstate 2>/dev/null ||
	say "note: $WANIF operstate is $(cat /sys/class/net/$WANIF/operstate 2>/dev/null), continuing anyway"
command -v ethtool >/dev/null 2>&1 || { say "FATAL: ethtool not installed"; exit 1; }
command -v wget    >/dev/null 2>&1 || { say "FATAL: wget not installed"; exit 1; }

ORIG_BACKLOG=$(cat /proc/sys/net/core/netdev_max_backlog)
ORIG_THREADED=$(cat /sys/class/net/$WANIF/threaded 2>/dev/null || echo 0)
ORIG_GRO=$(ethtool -k $WANIF 2>/dev/null | awk '/^generic-receive-offload:/{print $2}')
say "starting state: netdev_max_backlog=$ORIG_BACKLOG threaded=$ORIG_THREADED gro=$ORIG_GRO"

PIDS=""
cleanup() {
	for p in $PIDS; do kill $p 2>/dev/null; done
	pkill -f "wget -qO /dev/null" 2>/dev/null
	sysctl -w net.core.netdev_max_backlog=$ORIG_BACKLOG >/dev/null 2>&1
	echo "$ORIG_THREADED" > /sys/class/net/$WANIF/threaded 2>/dev/null
	[ "$ORIG_GRO" = on ] && ethtool -K $WANIF gro on 2>/dev/null
	rm -f /tmp/.gro_ab_ping
	say ""
	say "restored: netdev_max_backlog=$(cat /proc/sys/net/core/netdev_max_backlog) threaded=$(cat /sys/class/net/$WANIF/threaded 2>/dev/null) gro=$(ethtool -k $WANIF 2>/dev/null | awk '/^generic-receive-offload:/{print $2}')"
}
trap 'say ""; say "interrupted - restoring"; cleanup; exit 130' INT TERM

# ---- counters -------------------------------------------------------------
# InReceives by header name, not by a fixed column: on the Ip: data line $2 is
# Forwarding and $3 DefaultTTL, so a hardcoded column silently reads a constant.
# Summed across v4 and v6 because the wwan is ipv4v6 and a download may take
# either, leaving the other counter flat.
in4() { awk '/^Ip:/{ if(h==""){ for(i=1;i<=NF;i++) if($i=="InReceives") c=i; h=1; next } print $c+0 }' /proc/net/snmp; }
in6() { awk '/^Ip6InReceives/{print $2+0}' /proc/net/snmp6 2>/dev/null || echo 0; }

# softnet_stat is hex, one row per CPU: processed, dropped, time_squeeze, ...
sq() {
	_d=0; _s=0
	while read -r _a _b _c _rest; do
		_d=$((_d + 0x$_b)); _s=$((_s + 0x$_c))
	done < /proc/net/softnet_stat
	echo "$_d $_s"
}

# ---- load -----------------------------------------------------------------
# Each stream restarts when its file completes, so the offered load does not
# decay mid-run. An earlier attempt without this had windows at 26768, 22989
# and 15645 datagrams/s and could not be read across.
start_load() {
	_n=0
	while [ "$_n" -lt "$STREAMS" ]; do
		( while :; do wget -qO /dev/null "$URL" || sleep 2; done ) &
		PIDS="$PIDS $!"
		_n=$((_n+1))
	done
	sleep 5
	_live=0
	for p in $PIDS; do kill -0 $p 2>/dev/null && _live=$((_live+1)); done
	say "load: $_live of $STREAMS stream drivers running against $URL"
	say "      (hosts commonly cap concurrent connections, so fewer may be moving data)"
}

# ---- one measurement window -----------------------------------------------
# The RTT sample runs in the background and `sleep` times the window. Do not be
# tempted to let ping time it: busybox ping does not take a fractional -i in
# every build, so a rejected option would end the window instantly and every
# per-second figure would be divided by almost nothing.
PING_OK=0
if ping -c 1 -W 2 "$PINGTGT" >/dev/null 2>&1; then
	PING_OK=1
elif ping -c 1 "$PINGTGT" >/dev/null 2>&1; then
	PING_OK=1
fi
[ "$PING_OK" = 1 ] || say "note: cannot ping $PINGTGT, so no RTT column (set PINGTGT= to change)"

meas() {
	_lab=$1
	: > /tmp/.gro_ab_ping
	[ "$PING_OK" = 1 ] && ping -q -c "$WINDOW" "$PINGTGT" > /tmp/.gro_ab_ping 2>&1 &

	_p0=$(cat /sys/class/net/$WANIF/statistics/rx_packets)
	_b0=$(cat /sys/class/net/$WANIF/statistics/rx_bytes)
	_r0=$(cat /sys/class/net/$WANIF/statistics/rx_dropped)
	_e0=$(cat /sys/class/net/$WANIF/statistics/rx_errors)
	_i0=$(( $(in4) + $(in6) ))
	_q0=$(sq)

	sleep "$WINDOW"

	_p1=$(cat /sys/class/net/$WANIF/statistics/rx_packets)
	_b1=$(cat /sys/class/net/$WANIF/statistics/rx_bytes)
	_r1=$(cat /sys/class/net/$WANIF/statistics/rx_dropped)
	_e1=$(cat /sys/class/net/$WANIF/statistics/rx_errors)
	_i1=$(( $(in4) + $(in6) ))
	_q1=$(sq)

	set -- $_q0; _sd0=$1; _ss0=$2
	set -- $_q1; _sd1=$1; _ss1=$2

	_rtt=$(awk -F'=' '/round-trip|rtt/{print $2}' /tmp/.gro_ab_ping 2>/dev/null | tr -d ' ')
	_loss=$(awk '/packet loss/{for(i=1;i<=NF;i++) if($i ~ /%$/){print $i; exit}}' /tmp/.gro_ab_ping 2>/dev/null)
	[ -n "$_rtt" ] || _rtt="n/a"
	[ -n "$_loss" ] || _loss="n/a"

	awk -v lab="$_lab" -v w="$WINDOW" \
	    -v dp=$((_p1-_p0)) -v ds=$((_i1-_i0)) -v db=$((_b1-_b0)) \
	    -v dd=$((_r1-_r0)) -v de=$((_e1-_e0)) \
	    -v sd=$((_sd1-_sd0)) -v ss=$((_ss1-_ss0)) \
	    -v rtt="$_rtt" -v loss="$_loss" 'BEGIN{
		if (ds<=0 || dp<=0) { printf "%-12s no traffic in the window\n", lab; exit }
		printf "%-12s %6.1f Mbit/s %6d dgram/s %6d skb/s  agg=%5.2fx\n", lab, db*8/w/1000000, dp/w, ds/w, dp/ds
		printf "%-12s rx_dropped=%-5d softnet_dropped=%-5d time_squeeze=%-4d rx_errors=%d\n", "", dd, sd, ss, de
		printf "%-12s bytes/skb=%-6d  rtt=%s  ping loss=%s\n", "", db/ds, rtt, loss
	}'
	say ""
}

# ---- run ------------------------------------------------------------------
start_load
say ""

for B in 1000 2000 4000; do
	sysctl -w net.core.netdev_max_backlog=$B >/dev/null
	meas "backlog-$B"
done

sysctl -w net.core.netdev_max_backlog=$ORIG_BACKLOG >/dev/null
echo 1 > /sys/class/net/$WANIF/threaded 2>/dev/null
say "threaded=$(cat /sys/class/net/$WANIF/threaded 2>/dev/null)  napi threads: $(ps 2>/dev/null | grep -c "[n]api/$WANIF")"
meas "threaded-1k"

cleanup
say ""
say "Read it this way:"
say "  compare only windows whose dgram/s are within about 10% of each other;"
say "  the link drifts, and drops are rate-dependent, so a slower window with"
say "  fewer drops has proved nothing."
say "  rx_dropped alone  -> the gro_cells queue overflowed"
say "  rx_dropped + softnet_dropped together -> the RPS backlog overflowed"
say "  rtt is under load, so it is the bufferbloat cost of whatever queue depth"
say "  that window was running."
