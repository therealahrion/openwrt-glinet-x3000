#!/bin/sh
# mbim-capture.sh -- catch the RM520N MBIM session dying, in the act.
#
# Usage on the router (ttyd/ssh):
#   arm      : sh /tmp/mbim-capture.sh arm
#   <then run your speedtest from a LAN client>
#   collect  : sh /tmp/mbim-capture.sh collect
#   recover  : sh /tmp/mbim-capture.sh recover
#   status   : sh /tmp/mbim-capture.sh status
#   groff/gron : toggle GRO on wwan0 for the A/B
#
# Everything lands in /tmp/mbimcap/.

D=/tmp/mbimcap
mkdir -p "$D"

snap() {   # snap <tag>
	t="$1"
	{
		echo "===== snapshot $t : $(date) uptime=$(cut -d' ' -f1 /proc/uptime) ====="
		echo "--- ethtool -k wwan0 (gro/xdp relevant) ---"
		ethtool -k wwan0 2>/dev/null | grep -E 'generic-receive|large-receive|rx-gro'
		echo "--- ip -s link show wwan0 ---"
		ip -s link show wwan0 2>/dev/null
		echo "--- ip -d link show wwan0 | xdp ---"
		ip -d link show wwan0 2>/dev/null | grep -i xdp
		echo "--- MHI devices ---"
		ls /sys/bus/mhi/devices/ 2>/dev/null
		echo "--- MHI controller state ---"
		for f in /sys/bus/mhi/devices/*/state /sys/class/wwan/*/; do
			[ -e "$f" ] && echo "$f: $(cat "$f" 2>/dev/null)"
		done
		echo "--- PCIe AER / link ---"
		lspci -vv 2>/dev/null | grep -A3 -i 'advanced error\|LnkSta' | head -30
		echo "--- mmcli -L ---"
		mmcli -L 2>&1
		echo "--- mmcli -m any (state/signal) ---"
		mmcli -m any 2>&1 | grep -iE 'state|signal|power|failed|bearer' | head -25
		echo "--- NotOpened count in last 500 log lines ---"
		logread -l 500 2>/dev/null | grep -c NotOpened
		echo "--- dmesg tail ---"
		dmesg 2>/dev/null | tail -25
	} > "$D/snap-$t.txt" 2>&1
	echo "  wrote $D/snap-$t.txt"
}

case "$1" in
arm)
	rm -f "$D"/*.txt "$D"/*.pid 2>/dev/null
	echo "[1/4] raising ModemManager log level to DEBUG"
	mmcli -G DEBUG 2>&1 | sed 's/^/      /'
	echo "[2/4] starting continuous logread capture"
	( logread -f > "$D/logread.txt" 2>&1 ) &
	echo $! > "$D/logread.pid"
	echo "[3/4] starting dmesg watcher"
	( while :; do dmesg > "$D/dmesg-live.txt" 2>&1; sleep 5; done ) &
	echo $! > "$D/dmesg.pid"
	echo "[4/4] baseline snapshot"
	snap before
	echo
	echo "ARMED. Now run your speedtest from a LAN client (Ookla or fast.com)."
	echo "When it finishes and you see the modem misbehave, run:"
	echo "    sh /tmp/mbim-capture.sh collect"
	;;

collect)
	snap after
	for p in logread dmesg; do
		[ -f "$D/$p.pid" ] && kill "$(cat "$D/$p.pid")" 2>/dev/null
		rm -f "$D/$p.pid"
	done
	mmcli -G INFO >/dev/null 2>&1
	echo
	echo "================ FIRST NotOpened AND WHAT PRECEDED IT ================"
	n=$(grep -n NotOpened "$D/logread.txt" 2>/dev/null | head -1 | cut -d: -f1)
	if [ -n "$n" ]; then
		s=$((n - 60)); [ "$s" -lt 1 ] && s=1
		sed -n "${s},$((n + 10))p" "$D/logread.txt"
	else
		echo "(no NotOpened captured in this window)"
	fi
	echo
	echo "================ MBIM OPEN / CLOSE / ERROR TRAFFIC ================"
	grep -inE 'mbim.*(open|close|not opened|notopened|function error|host error)|subsys|SYS_ERR|reset|removed|reprobe' \
		"$D/logread.txt" 2>/dev/null | head -60
	echo
	echo "================ KERNEL DELTA (before -> after) ================"
	b=$(wc -l < "$D/snap-before.txt" 2>/dev/null)
	diff "$D/snap-before.txt" "$D/snap-after.txt" 2>/dev/null | head -80
	echo
	echo "Full capture in $D/  (logread.txt, dmesg-live.txt, snap-before.txt, snap-after.txt)"
	;;

recover)
	echo "restarting ModemManager (forces a fresh mbim-proxy client -> Proxy Config ->"
	echo "proxy re-opens the MBIM session; ifdown/ifup does NOT do this)"
	/etc/init.d/modemmanager restart
	i=0
	while [ $i -lt 40 ]; do
		sleep 2; i=$((i + 2))
		mmcli -L 2>/dev/null | grep -q Modem && break
	done
	echo "waited ${i}s"
	mmcli -L 2>&1
	sleep 8
	c=$(logread -l 60 2>/dev/null | grep -c NotOpened)
	echo "NotOpened in the last 60 log lines: $c   (want 0)"
	[ "$c" -eq 0 ] && echo "RECOVERED." || echo "STILL BROKEN -- try: mmcli -m any --reset"
	;;

status)
	echo "NotOpened in last 500 log lines: $(logread -l 500 2>/dev/null | grep -c NotOpened)"
	echo "last 5 mbim log lines:"
	logread -l 500 2>/dev/null | grep -i mbim | tail -5
	echo "wwan0 GRO: $(ethtool -k wwan0 2>/dev/null | grep generic-receive-offload)"
	mmcli -L 2>&1
	;;

groff)  ethtool -K wwan0 gro off; ethtool -k wwan0 | grep generic-receive-offload ;;
gron)   ethtool -K wwan0 gro on;  ethtool -k wwan0 | grep generic-receive-offload ;;

*) echo "usage: $0 {arm|collect|recover|status|groff|gron}" ;;
esac
