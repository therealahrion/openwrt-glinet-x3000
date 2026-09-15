#!/bin/sh
# =============================================================================
# wwan0 receive-path A/B: where the datagrams are dropped, and what stops it.
#
#   sh gro-backlog-ab.sh              the backlog sweep
#   sh gro-backlog-ab.sh --threaded   and a threaded-NAPI window
#   sh gro-backlog-ab.sh --baseline   one window at the current settings,
#                                     changing nothing
#   sh gro-backlog-ab.sh --napi       W0002: threaded NAPI A/B. Generates no
#                                     load itself - the download must be pulled
#                                     by a LAN client, or the harness competes
#                                     with the kthread it is measuring
#
# --baseline exists to answer a different question from the sweep: whether this
# box has CPU headroom left at link rate. If it does, then shortening the
# per-packet forwarding path - which is all an XDP fast path can do here - buys
# no throughput, and the only thing left to win is latency. It writes no sysctl
# and restores nothing because it changes nothing.
#
# Three load-matched windows under the same sustained download:
#   backlog-1000   GRO on, netdev_max_backlog at its default
#   backlog-2000   GRO on, twice the queue
#   backlog-4000   GRO on, four times the queue
# A fourth, threaded-1k, runs only with --threaded. The comment where it runs
# says why it is off by default.
#
# Overridable: WANIF, URL, STREAMS, WINDOW, PINGTGT. Most iterations need a
# different environment, not a different script.
#
# STREAMS is a CEILING, not a demand. The load ramps up one stream at a time and
# keeps only those the source will actually serve, so a source that caps
# concurrent connections per address - which the default URL does, at two -
# settles the run at whatever it allows and says so. There is no number to tune
# by hand and no run to throw away because half the fetchers were thrashing.
#
# What it is looking for. At ~20k datagrams/s this link overflows a queue and
# drops about 0.2% of them. Which queue depends on GRO:
#   rx_dropped moves, softnet_dropped stays 0  -> the gro_cells queue
#                                                 (net/core/gro_cells.c:32)
#   rx_dropped and softnet_dropped move together -> the RPS backlog
#                                                 (cpu_backlog_drop in dev.c)
# Both are capped by the same net.core.netdev_max_backlog. time_squeeze has
# stayed 0 throughout, so the NAPI is not running out of poll budget - the
# queues fill between polls, which is a scheduling-latency problem. That is why
# threaded NAPI is worth testing at all, but it has to be tested under a
# LAN-driven load to mean anything; see --threaded.
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

# boxstate.sh is the shared preflight and owns the state readers, the setters
# and the restore. Fetched the same way everything else here is, because this
# script is normally run from /tmp after a curl with no tree beside it.
case "$0" in */*) _bshere=${0%/*} ;; *) _bshere=. ;; esac
BOXSTATE_URL=${BOXSTATE_URL:-https://raw.githubusercontent.com/therealahrion/openwrt-glinet-x3000/openwrt-25.12/x3000/docs/boxstate.sh}
BOXSTATE=${BOXSTATE:-$_bshere/boxstate.sh}
if [ ! -r "$BOXSTATE" ]; then
	BOXSTATE=/tmp/boxstate.sh
	if [ ! -s "$BOXSTATE" ]; then
		if command -v curl >/dev/null 2>&1; then
			curl -fsSL -o "$BOXSTATE" "$BOXSTATE_URL" || true
		elif command -v wget >/dev/null 2>&1; then
			wget -q -O "$BOXSTATE" "$BOXSTATE_URL" || true
		fi
	fi
fi
if [ ! -s "$BOXSTATE" ]; then
	echo "FATAL: boxstate.sh not found beside this script and could not be" >&2
	echo "       fetched from $BOXSTATE_URL" >&2
	exit 1
fi
BOXSTATE_LIB=1 . "$BOXSTATE"
BOXSTATE_NEED=3
if [ "${BOXSTATE_API:-0}" != "$BOXSTATE_NEED" ]; then
	echo "FATAL: boxstate.sh is API ${BOXSTATE_API:-none}, this script needs $BOXSTATE_NEED." >&2
	echo "       rm -f /tmp/boxstate.sh and re-run, or pull the tree again." >&2
	exit 1
fi

say() { bs_say "$@"; }

# ---- guards ---------------------------------------------------------------
[ -d /sys/class/net/$WANIF ] || { say "FATAL: $WANIF does not exist"; exit 1; }
grep -q up /sys/class/net/$WANIF/operstate 2>/dev/null ||
	say "note: $WANIF operstate is $(cat /sys/class/net/$WANIF/operstate 2>/dev/null), continuing anyway"
command -v ethtool >/dev/null 2>&1 || { say "FATAL: ethtool not installed"; exit 1; }
command -v wget    >/dev/null 2>&1 || { say "FATAL: wget not installed"; exit 1; }

# Starting state, read through the library so it is read the same way every
# other script reads it. There are no ORIG_ variables any more: bs_set_*
# records each target's original the first time that target is touched, which
# is the difference between restoring the value this run started with and
# restoring whatever the previous A/B leg happened to leave behind. With three
# knobs the hand-rolled version was correct; it was the fourth knob somebody
# adds that it was going to get wrong.
say "starting state: netdev_max_backlog=$(bs_backlog) threaded=$(bs_threaded $WANIF) gro=$(bs_gro_effective $WANIF) xdp=$(bs_xdp_mode $WANIF)"
say "time_squeeze so far: $(bs_squeeze)"

PIDS=""
cleanup() {
	for p in $PIDS; do kill $p 2>/dev/null; done
	pkill -f "wget -qO /dev/null" 2>/dev/null
	rm -f /tmp/.gro_ab_ping
	[ -s "$LOADLOG" ] && say "fetcher errors were logged to $LOADLOG"
	bs_restore
	say ""
	say "now: netdev_max_backlog=$(bs_backlog) threaded=$(bs_threaded $WANIF) gro=$(bs_gro_effective $WANIF) xdp=$(bs_xdp_mode $WANIF)"
}
trap 'say ""; say "interrupted - restoring"; cleanup; exit 130' INT TERM

# ---- counters -------------------------------------------------------------
# InReceives by header name, not by a fixed column: on the Ip: data line $2 is
# Forwarding and $3 DefaultTTL, so a hardcoded column silently reads a constant.
# Summed across v4 and v6 because the wwan is ipv4v6 and a download may take
# either, leaving the other counter flat.
in4() { awk '/^Ip:/{ if(h==""){ for(i=1;i<=NF;i++) if($i=="InReceives") c=i; h=1; next } print $c+0 }' /proc/net/snmp; }
in6() { awk '/^Ip6InReceives/{print $2+0}' /proc/net/snmp6 2>/dev/null || echo 0; }

# /proc/stat per-CPU: user nice system idle iowait irq softirq steal ...
# Echoes total, idle and softirq jiffies summed across CPUs.
#
# Indicative only, and deliberately labelled as such in the output. This box has
# already cost three withdrawn per-packet figures because /proc/stat does not
# conserve time here, so it is read as "is there obvious headroom" and never as a
# per-packet cost. The trustworthy saturation signal in the same window is
# time_squeeze, which is a count rather than a time: NAPI increments it when it
# exhausts its poll budget, so a flat time_squeeze under a saturating load means
# the receive path is not running out of cycles.
cpu() {
	awk '/^cpu[0-9]/ {
		t = 0
		for (i = 2; i <= NF; i++) t += $i
		tot += t; idle += $5 + $6; sirq += $8
	} END { print tot+0, idle+0, sirq+0 }' /proc/stat
}

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
#
# A live-driver count is not proof of load. On 2026-09-12 a run reported "4 of 4
# stream drivers running" and then three windows of agg=0.00x, because every
# fetch was failing with "Failed to send request: Operation not permitted" and
# the count only checks that the retry loops are alive. The firewall, policy
# routing and both address families were all cleared as causes afterwards, so it
# is something in the fetcher or its concurrency. Rather than chase it: confirm
# bytes are actually arriving before measuring anything, and keep the fetcher
# stderr so the next occurrence is evidence instead of a mystery.
LOADLOG=/tmp/.gro_ab_load.log

# How many fetch failures have been logged so far.
#
# busybox grep -c prints 0 and exits non-zero when nothing matches, so the
# substitution can come back empty rather than "0"; the guard is not decoration.
fail_count() {
	_c=$(grep -c '^fetch exit' $LOADLOG 2>/dev/null)
	[ -n "$_c" ] || _c=0
	echo "$_c"
}

# Bring the load up one stream at a time, keeping only the streams the source
# will actually serve.
#
# The 2026-09-14 run asked for four streams against the default URL and got two:
# the other two sat in a retry loop failing with exit 8 every 2.5 seconds for
# the whole run. Public speed-test sources cap concurrent connections per
# address, and nothing here knew that number. The first attempt at a fix only
# refused to run, which left the operator to guess STREAMS by hand - a
# workaround, not a fix, and it hard-codes one server's limit into this script.
#
# Ramping up instead of down means the script never passes through a broken
# state and never has to be told the limit: it adds a stream, watches for three
# seconds, and keeps it only if no new failure appears. Whatever the source
# allows is what the run uses, and the number is reported rather than assumed.
#
# A stable two streams is a perfectly good load. What ruined the earlier run was
# not the count but the churn - streams thrashing on retry make the offered load
# wander, which reads as throughput drift across windows and is indistinguishable
# from the setting under test mattering.
start_load() {
	: > $LOADLOG
	PIDS=""
	_kept=0
	_n=0
	while [ "$_n" -lt "$STREAMS" ]; do
		_n=$((_n+1))
		_before=$(fail_count)
		( while :; do
			wget -qO /dev/null "$URL" 2>>$LOADLOG ||
				{ echo "fetch exit $? at $(date +%T)" >>$LOADLOG; sleep 2; }
		done ) &
		_new=$!
		sleep 3
		_after=$(fail_count)
		if [ "$_after" -gt "$_before" ]; then
			# This stream could not be added. Stop here rather than trying
			# more: a source that refused the Nth will refuse the N+1th, and
			# every extra attempt is another retry loop competing for the
			# link it is supposed to be loading.
			kill "$_new" 2>/dev/null
			say "load: source refused stream $_n - settling at $_kept"
			break
		fi
		PIDS="$PIDS $_new"
		_kept=$((_kept+1))
	done

	if [ "$_kept" -eq 0 ]; then
		say ""
		say "FATAL: not one stream could fetch $URL."
		say "       Fetcher output:"
		sed -n '1,6p' $LOADLOG | sed 's/^/         /'
		say "       Try it by hand: wget -O /dev/null \"$URL\""
		cleanup
		exit 1
	fi
	if [ "$_kept" -lt "$STREAMS" ]; then
		say "load: $_kept stream(s) holding of $STREAMS asked for - the source"
		say "      caps concurrent connections. This is fine: a stable smaller"
		say "      load measures correctly, where a thrashing larger one does not."
	else
		say "load: $_kept of $STREAMS stream(s) holding, no fetch failures"
	fi
	LOAD_BASE=$(fail_count)

	_t0=$(cat /sys/class/net/$WANIF/statistics/rx_bytes)
	sleep 3
	_t1=$(cat /sys/class/net/$WANIF/statistics/rx_bytes)
	_mb=$(( (_t1-_t0) * 8 / 3 / 1000000 ))
	if [ "$_mb" -lt 5 ]; then
		say ""
		say "FATAL: only $_mb Mbit/s arriving on $WANIF, so there is no load to measure."
		say "       Every window would have reported noise. Fetcher output:"
		sed -n '1,6p' $LOADLOG | sed 's/^/         /'
		cleanup
		exit 1
	fi
	say "load confirmed: about $_mb Mbit/s arriving on $WANIF"
}

# Failures AFTER the ramp settled are the ones that invalidate a run: they mean
# a stream that was serving has started thrashing, so the offered load moved
# under the windows. Baselined at LOAD_BASE so the ramp's own probe failures,
# which are expected and already handled, are not counted twice.
load_drift_check() {
	_now=$(fail_count)
	_since=$(( _now - ${LOAD_BASE:-0} ))
	if [ "$_since" -gt 0 ]; then
		say ""
		say "WARNING: $_since fetch failure(s) since the load settled. A stream"
		say "         dropped out mid-run, so the offered load moved and the"
		say "         throughput and rtt columns above are not comparable across"
		say "         windows. The drop counters are still valid."
	fi
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
	_c0=$(cpu)

	sleep "$WINDOW"

	_p1=$(cat /sys/class/net/$WANIF/statistics/rx_packets)
	_b1=$(cat /sys/class/net/$WANIF/statistics/rx_bytes)
	_r1=$(cat /sys/class/net/$WANIF/statistics/rx_dropped)
	_e1=$(cat /sys/class/net/$WANIF/statistics/rx_errors)
	_i1=$(( $(in4) + $(in6) ))
	_q1=$(sq)
	_c1=$(cpu)

	set -- $_q0; _sd0=$1; _ss0=$2
	set -- $_q1; _sd1=$1; _ss1=$2
	set -- $_c0; _ct0=$1; _ci0=$2; _cs0=$3
	set -- $_c1; _ct1=$1; _ci1=$2; _cs1=$3

	_rtt=$(awk -F'=' '/round-trip|rtt/{print $2}' /tmp/.gro_ab_ping 2>/dev/null | tr -d ' ')
	_loss=$(awk '/packet loss/{for(i=1;i<=NF;i++) if($i ~ /%$/){print $i; exit}}' /tmp/.gro_ab_ping 2>/dev/null)
	[ -n "$_rtt" ] || _rtt="n/a"
	[ -n "$_loss" ] || _loss="n/a"

	awk -v lab="$_lab" -v w="$WINDOW" \
	    -v dp=$((_p1-_p0)) -v ds=$((_i1-_i0)) -v db=$((_b1-_b0)) \
	    -v dd=$((_r1-_r0)) -v de=$((_e1-_e0)) \
	    -v sd=$((_sd1-_sd0)) -v ss=$((_ss1-_ss0)) \
	    -v rtt="$_rtt" -v loss="$_loss" \
	    -v ct=$((_ct1-_ct0)) -v ci=$((_ci1-_ci0)) -v cs=$((_cs1-_cs0)) 'BEGIN{
		if (ds<=0 || dp<=0) { printf "%-12s no traffic in the window\n", lab; exit }
		printf "%-12s %6.1f Mbit/s %6d dgram/s %6d skb/s  agg=%5.2fx\n", lab, db*8/w/1000000, dp/w, ds/w, dp/ds
		printf "%-12s rx_dropped=%-5d softnet_dropped=%-5d time_squeeze=%-4d rx_errors=%d\n", "", dd, sd, ss, de
		printf "%-12s bytes/skb=%-6d  rtt=%s  ping loss=%s\n", "", db/ds, rtt, loss
		if (ct > 0)
			printf "%-12s cpu busy=%.0f%% softirq=%.0f%% (indicative - /proc/stat does not conserve here;\n%-12s time_squeeze above is the count that does)\n", "", (ct-ci)*100/ct, cs*100/ct, ""
		if (dp < ds)
		    printf "%-12s ** fewer datagrams than delivered skbs: InReceives is system-wide, so this ratio is not about this interface **\n", ""
		if (db/ds > 65536)
			printf "%-12s ** bytes/skb exceeds gro_max_size 65536, so the agg figure above is loss, not coalescing **\n", ""
	}'
	say ""
}

# ---- run ------------------------------------------------------------------

# W0002: thread the gro_cells NAPI, and pin it.
#
# This mode deliberately runs BEFORE start_load and never calls it. The comment
# on --threaded below explains why that matters: a curl running on the router
# competes with the NAPI kthread for the same two cores, so an on-box load
# measures the harness starving its own kthread rather than anything about the
# driver. The load has to come from a LAN client pulling a download, with the
# router only forwarding. That rig is what tabled this test on 2026-09-12; it
# now exists.
#
# Three conditions, alternating, because a cellular link drifts on its own and
# a single before/after cannot tell drift from effect - see 23.19, where both
# arms of one cycle collapsed together and would have read as a 40% win.
#
#   softirq     threaded=0, the shipped state
#   thread      threaded=1, kthread wherever the scheduler puts it
#   thread-pin  threaded=1, kthread pinned off the CPU taking the MHI IRQ
#
# time_squeeze has read 0 in every window ever measured here, so the NAPI is
# not short of poll budget: the queues fill between polls. That is a scheduling
# latency problem, which is exactly what moving the work to a pinned kthread
# addresses - and why rtt under load, not throughput, is the number to read.
# Recovery ladder, cheapest first. The 2026-09-14 run went straight to a reboot,
# so which of these would have sufficed is unknown - worth knowing, since a
# reboot of the house router is the most expensive possible answer.
napi_recover() {
	say ""
	say "--- recovery, cheapest first ---"
	say "  kernel log is at $LOG - READ IT BEFORE REBOOTING"
	say ""
	bs_set_sysfs /sys/class/net/$WANIF/threaded 0
	sleep 3
	ping -q -c2 -W2 "$PINGTGT" >/dev/null 2>&1 && { bs_ok "threaded=0 was enough"; return 0; }
	say "  threaded=0 did not recover it"

	ip link set "$WANIF" down 2>/dev/null; sleep 2
	ip link set "$WANIF" up 2>/dev/null; sleep 5
	ping -q -c2 -W2 "$PINGTGT" >/dev/null 2>&1 && { bs_ok "link down/up was enough"; return 0; }
	say "  link down/up did not recover it. One thing a link cycle cannot reach:"
	say "  gro_cells_init() runs at netdev creation rather than at link up, so"
	say "  the queue and its length survive the cycle. Whether that is what is"
	say "  stuck here is not established - see 23.20."

	ifdown wwan 2>/dev/null; sleep 3; ifup wwan 2>/dev/null; sleep 10
	ping -q -c2 -W2 "$PINGTGT" >/dev/null 2>&1 && { bs_ok "ifdown/ifup wwan was enough"; return 0; }
	say "  ifdown/ifup did not recover it"

	say ""
	say "  Left: reload the driver, which destroys and recreates the netdev and"
	say "  with it the gro_cells queues. NOT done automatically - it can strand"
	say "  the MHI binding and leave no WAN at all until a reboot:"
	say "      rmmod mhi_wwan_mbim && modprobe mhi_wwan_mbim"
	say "  If that fails, reboot - but save $LOG off the box first."
	return 1
}

# DISABLED. Threaded NAPI is not a tuning knob on this interface - it is an
# unsafe configuration, and 23.21 shows that in source rather than in counters.
#
# gro_cells carries no lock at 6.12.103. gro_cells_receive() enqueues with the
# unlocked __skb_queue_tail() at gro_cells.c:37 and gro_cell_poll() dequeues with
# the unlocked __skb_dequeue() at :58; the only exclusion is that both run on the
# same CPU with BH disabled, which is what the /* called under BH context */
# comment at :49 is asserting. dev_set_threaded() (dev.c:6688) threads every NAPI
# on dev->napi_list with no filter, and napi_kthread_create() (dev.c:1508) uses a
# plain kthread_run(), so the resulting threads are UNBOUND. A gro_cell belonging
# to CPU 0 can then be drained from CPU 1 while CPU 0 is still enqueueing into it.
#
# Staging cannot fix that. dev_set_threaded() starts each thread before it sets
# NAPI_STATE_THREADED twelve lines later, so there is a window in which traffic
# meets an unbound thread and no userspace taskset has run yet. Both 2026-09-14
# failures happened inside seconds of the write, which is what that window looks
# like.
#
# The escape hatch below exists for one purpose: verifying a kernel that has
# W0041 applied, where the gro_cells NAPI kthreads are bound to their cells'
# CPUs. On a stock kernel there is no correct number to collect here.
#
# The rest of this mode is kept intact because it is what W0041 verification
# needs: an idle-link toggle first, irqbalance stopped for the run and restored
# after, logread captured throughout, and a stop on the first sign the link has
# gone rather than five more dead windows.
if [ "$1" = --napi ]; then
	say "W0002: threaded NAPI on $WANIF - REFUSED on a stock kernel"
	say ""
	say "gro_cells has no lock (gro_cells.c:37 and :58 are the unlocked skb"
	say "queue primitives) and relies on producer and consumer sharing a CPU"
	say "with BH disabled. Threading it creates UNBOUND kthreads (dev.c:1508),"
	say "which breaks that. 23.21 has the full chain."
	say ""
	say "Two 2026-09-14 attempts killed the downlink and each cost a reboot."
	say "A third would measure the same broken configuration."
	say ""
	if [ "${NAPI_W0041_KERNEL:-0}" != 1 ]; then
		say "This mode only makes sense on a kernel carrying W0041, which binds"
		say "each gro_cells NAPI kthread to its own cell's CPU. On such a build,"
		say "set NAPI_W0041_KERNEL=1 to run the verification."
		exit 1
	fi
	say "NAPI_W0041_KERNEL=1 - proceeding as a W0041 verification run."
	say ""

	# Evidence first: logread is a ring buffer and a reboot empties it.
	LOG=/tmp/napi-logread.txt
	: > "$LOG"
	logread -f >> "$LOG" 2>&1 &
	LOGPID=$!
	say "capturing logread to $LOG (pid $LOGPID)"

	# irqbalance moves IRQ masks underneath a placement test.
	IRQB=0
	if /etc/init.d/irqbalance running >/dev/null 2>&1; then
		IRQB=1
		/etc/init.d/irqbalance stop >/dev/null 2>&1
		say "irqbalance stopped for the run"
	fi
	napi_cleanup() {
		kill "$LOGPID" 2>/dev/null
		[ "$IRQB" = 1 ] && /etc/init.d/irqbalance start >/dev/null 2>&1
		cleanup
	}
	trap 'say ""; say "interrupted"; napi_cleanup; exit 130' INT TERM

	link_ok() { ping -q -c2 -W2 "$PINGTGT" >/dev/null 2>&1; }

	say ""
	say "--- phase 1: link healthy before anything ---"
	if link_ok; then
		bs_ok "link is up"
	else
		bs_bad "link already down - nothing to test"
		napi_cleanup; exit 1
	fi

	say ""
	say "--- phase 2: toggle threaded=1 on an IDLE link ---"
	say "  Stop any download now. Waiting 10s for the link to go quiet."
	sleep 10
	_d0=$(cat /sys/class/net/$WANIF/statistics/rx_dropped)
	bs_set_sysfs /sys/class/net/$WANIF/threaded 1
	sleep 5
	_d1=$(cat /sys/class/net/$WANIF/statistics/rx_dropped)
	say "  rx_dropped across the idle toggle: $((_d1-_d0))"
	if link_ok; then
		bs_ok "the link survived an idle toggle"
	else
		bs_bad "THE IDLE TOGGLE ALONE KILLED THE LINK"
		say "        Decisive: threaded NAPI is unsafe on this driver at any"
		say "        load, not only under one."
		napi_recover
		napi_cleanup
		exit 1
	fi

	say ""
	say "--- phase 3: start the LAN-side load, then measure ---"
	say "  The download must be pulled by a LAN CLIENT, not by this router."
	sleep 15
	_p0=$(cat /sys/class/net/$WANIF/statistics/rx_packets); sleep 5
	_p1=$(cat /sys/class/net/$WANIF/statistics/rx_packets)
	_pps=$(( (_p1 - _p0) / 5 ))
	say "  $WANIF rx: ${_pps} pkt/s"
	if [ "$_pps" -lt 2000 ]; then
		bs_bad "no saturating load - not measuring"
		bs_set_sysfs /sys/class/net/$WANIF/threaded 0
		napi_cleanup; exit 1
	fi
	meas "thread"
	if ! link_ok; then
		bs_bad "the link died under load with threaded=1"
		napi_recover; napi_cleanup; exit 1
	fi

	say ""
	say "--- phase 4: back to softirq, same load ---"
	bs_set_sysfs /sys/class/net/$WANIF/threaded 0
	sleep 5
	if ! link_ok; then
		bs_bad "the link died toggling back"
		napi_recover; napi_cleanup; exit 1
	fi
	meas "softirq"

	napi_cleanup
	say ""
	say "Both conditions ran and the link survived. Compare rtt, not throughput;"
	say "time_squeeze has never moved here, so this is about how long a datagram"
	say "waits between the IRQ and the poll, not about poll budget."
	say "Kernel log for the run: $LOG"
	exit 0
fi

start_load
say ""

# One window, current settings, nothing written and nothing to restore. The
# question it answers is whether there is CPU headroom at link rate, so it wants
# the link saturated - keep STREAMS where the sweep has it and shorten WINDOW if
# the cellular data matters.
if [ "$1" = --baseline ]; then
	meas "baseline"
	load_drift_check
	cleanup
	say "Read it this way:"
	say "  time_squeeze 0 under a saturating window means NAPI never ran out of"
	say "  poll budget, so the receive path is not short of cycles and a shorter"
	say "  per-packet path cannot buy throughput. rtt under load is then the only"
	say "  thing left for one to improve."
	exit 0
fi

for B in 1000 2000 4000; do
	bs_set_sysctl net.core.netdev_max_backlog "$B"
	meas "backlog-$B"
done

# The first setting again, last. Without this the sweep walks 1000, 2000, 4000
# once and never looks back, so a link that degrades during the run produces a
# perfect monotonic decline that is indistinguishable from "deeper backlog is
# slower" - which is exactly what the 2026-09-14 run produced: 10976, 9211 then
# 7575 dgram/s, a 31% spread against the 10% the read-it-this-way note below
# calls comparable. A separate --baseline afterwards returned 7933 dgram/s at
# backlog 1000, which is where 4000 had landed, so the decline was the load and
# not the setting.
#
# 23.19 reached the same conclusion on the Wi-Fi side and answered it by
# alternating conditions under one continuous transfer. This is the cheap
# version of that: one repeat, enough to size the drift against the effect.
bs_set_sysctl net.core.netdev_max_backlog 1000
meas "backlog-1000 (drift control)"

load_drift_check

# No explicit put-back here: bs_restore in cleanup() holds the value this run
# started with, and re-setting it by hand was how the old code could restore a
# leg's value rather than the original.

# The threaded-NAPI window is OFF by default, and not because it is dangerous to
# the box - it restores cleanly - but because it cannot give a valid answer while
# the load is generated on the router itself.
#
# Threading moves receive processing out of softirq, which preempts user tasks,
# into a normal-priority kthread, which competes with them. The four wget
# processes pulling 300 Mbit/s to /dev/null are exactly the competition. Measured
# 2026-09-12: this window took the link from 277 Mbit/s to 5.9, with 91% ping
# loss and 2927 datagrams dropped, and bytes/skb of 100937 - above gro_max_size,
# so even its aggregation figure was loss.
#
# That result says the kthread was starved by the generator, not that threaded
# NAPI is bad for this driver. Re-run it with the download driven from a LAN
# client, where nothing on the router competes for CPU, and it becomes a real
# test. Until then it measures the harness.
if [ "$1" = --threaded ]; then
	say "REFUSED - same hazard as --napi, and the same toggle."
	say ""
	say "This mode's own warning used to say the throughput collapse it produced"
	say "was the on-box curl starving the NAPI kthread of CPU. That explanation"
	say "is now in doubt: on 2026-09-14 the same toggle, under a LAN-driven load"
	say "with nothing competing on the box, took the WAN down hard enough to"
	say "need a reboot - twice. A collapse attributed to contention was more"
	say "likely the unbound-kthread race 23.21 describes, all along."
	say ""
	say "Like --napi, this only makes sense on a kernel carrying W0041."
	[ "${NAPI_W0041_KERNEL:-0}" = 1 ] || exit 1
	bs_set_sysfs /sys/class/net/$WANIF/threaded 1
	_nt=0
	for _c in /proc/[0-9]*/comm; do
		grep -q "^napi/$WANIF" "$_c" 2>/dev/null && _nt=$((_nt+1))
	done
	say "threaded=$(cat /sys/class/net/$WANIF/threaded 2>/dev/null)  napi kthreads for $WANIF: $_nt"
	meas "threaded-1k"
fi

cleanup
say ""
say "Read it this way:"
say "  FIRST compare backlog-1000 against its drift control at the end. That"
say "  pair ran at the same setting, so whatever separates them is drift and"
say "  nothing else. If the gap between them is as large as the gap between"
say "  settings, the sweep measured the link and not the backlog - which is"
say "  what happened on 2026-09-14 and is why the control exists."
say "  Then compare only windows whose dgram/s are within about 10% of each"
say "  other; the link drifts, and drops are rate-dependent, so a slower"
say "  window with fewer drops has proved nothing."
say "  rx_dropped alone  -> the gro_cells queue overflowed"
say "  rx_dropped + softnet_dropped together -> the RPS backlog overflowed"
say "  rtt is under load, so it is the bufferbloat cost of whatever queue depth"
say "  that window was running."
