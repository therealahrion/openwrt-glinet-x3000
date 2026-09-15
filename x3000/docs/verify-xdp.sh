#!/bin/sh
# =============================================================================
# GL-X3000 (MT7981A, aarch64 LE) — verify the XDP hooks this tree carries on
# the modem's receive path (891's generic hook, 893's native one), the kernel
# config claims, and the telegraf footprint. Nothing is compiled on the box.
#
#   sh verify-xdp.sh              read-only + safe attach tests
#   sh verify-xdp.sh --with-drop  additionally test XDP_DROP (5s WAN blackout)
#   sh verify-xdp.sh --with-tc    additionally test tc-BPF L3/L4 on raw IP
#   sh verify-xdp.sh --traffic    start a WAN download so steps 4/6 have data
#
# The BPF objects live in bpf/ next to this script. If they are not there the
# script fetches them from the repo over HTTPS; override with BPF_DIR= or
# BPF_URL=.
#   (flags combine; --traffic is what makes the GRO test meaningful)
#
# Every mutation is undone before exit, including on Ctrl-C.
# =============================================================================
PASS=0; FAIL=0; SKIP=0
ok()   { PASS=$((PASS+1)); printf '  [ OK ]  %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  [FAIL]  %s\n' "$1"; }
skip() { SKIP=$((SKIP+1)); printf '  [skip]  %s\n' "$1"; }
info() { printf '          %s\n' "$1"; }
hdr()  { printf '\n===== %s =====\n' "$1"; }

WANIF=${WANIF:-wwan0}
D=/tmp/verify-xdp; rm -rf $D; mkdir -p $D

# Capture flags NOW: gro_measure() uses `set --`, which would clobber "$@".
for a in "$@"; do
	case "$a" in
		--with-drop) WITH_DROP=1 ;;
		--with-tc)   WITH_TC=1 ;;
		--traffic)   WITH_TRAFFIC=1 ;;
		--help|-h)   sed -n '3,12p' "$0"; exit 0 ;;
		*)           echo "unknown option: $a" >&2; exit 2 ;;
	esac
done

# boxstate.sh is the shared preflight and owns every reader this script used to
# carry its own copy of. Fetched the same way the BPF objects are, because this
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
	exit 2
fi
BOXSTATE_LIB=1 . "$BOXSTATE"
BOXSTATE_NEED=3
if [ "${BOXSTATE_API:-0}" != "$BOXSTATE_NEED" ]; then
	echo "FATAL: boxstate.sh is API ${BOXSTATE_API:-none}, this script needs $BOXSTATE_NEED." >&2
	echo "       rm -f /tmp/boxstate.sh and re-run, or pull the tree again." >&2
	exit 2
fi

# The library's gates report through bs_ok/bs_bad/bs_note. Point those at this
# script's own counters, or every gate that moved into the library would stop
# being counted in the summary at the end.
bs_ok()   { ok   "$1"; }
bs_bad()  { bad  "$1"; BS_FAILED=1; }
bs_note() { skip "$1"; }

IP=$(bs_pick_ip)
TC=$(bs_pick_tc)
if [ -z "$IP" ]; then
	echo "FATAL: no iproute2 'ip' that understands xdp." >&2
	echo "       install ip-full (CONFIG_PACKAGE_ip-full=y) and re-run." >&2
	exit 2
fi

# Load generator. Override the source with TRAFFIC_URL=, the stream count with
# TRAFFIC_STREAMS=.
#
# Two lessons are baked in here, both measured on 2026-09-12.
#
# The source is usually the ceiling, not the link. speedtest.tele2.net delivered
# 3 Mbit/s on a link that did 111 Mbit/s from proof.ovh.net in the same minute,
# and every aggregation figure taken before that date was capped by the
# generator rather than by the modem. speed.cloudflare.com answers HTTP 403 to a
# bare wget. So: rank sources before trusting a rate, and report the rate
# alongside every ratio.
#
# One stream cannot fill a cellular bandwidth-delay product. At a few hundred
# Mbit/s and 100+ ms of RTT there are megabytes in flight, which a single TCP
# connection will not hold through any loss at all. Several streams are not
# optional.
TRAFFIC_PIDS=""
TRAFFIC_STREAMS=${TRAFFIC_STREAMS:-4}
stop_traffic() {
	for p in $TRAFFIC_PIDS; do kill "$p" 2>/dev/null; done
	TRAFFIC_PIDS=""
}
start_traffic() {
	[ "$WITH_TRAFFIC" = 1 ] || return
	command -v wget >/dev/null 2>&1 || { info "no wget — drive traffic by hand"; return; }
	for u in ${TRAFFIC_URL:-} "https://proof.ovh.net/files/1Gb.dat"; do
		[ -n "$u" ] || continue
		_n=0
		while [ "$_n" -lt "$TRAFFIC_STREAMS" ]; do
			wget -qO /dev/null "$u" 2>/dev/null &
			TRAFFIC_PIDS="$TRAFFIC_PIDS $!"
			_n=$((_n+1))
		done
		sleep 3
		_live=0
		for p in $TRAFFIC_PIDS; do kill -0 "$p" 2>/dev/null && _live=$((_live+1)); done
		if [ "$_live" -gt 0 ]; then
			info "load generator: $_live of $TRAFFIC_STREAMS streams from $u"
			_r0=$(cat /sys/class/net/$WANIF/statistics/rx_bytes); sleep 3
			_r1=$(cat /sys/class/net/$WANIF/statistics/rx_bytes)
			info "offered load about $(( (_r1-_r0)*8/3/1000000 )) Mbit/s — quote this next to every ratio below"
			return
		fi
		stop_traffic
	done
	info "could not start a load generator — drive traffic by hand for steps 4, 6 and 8b"
}

cleanup() {
	stop_traffic
	$IP link set dev "$WANIF" xdp off 2>/dev/null
	$IP link set dev "$WANIF" xdpgeneric off 2>/dev/null
	$TC filter del dev "$WANIF" ingress 2>/dev/null
	[ -n "$MADE_CLSACT" ] && $TC qdisc del dev "$WANIF" clsact 2>/dev/null
	rm -rf $D
}
trap 'echo; echo "interrupted — reverting"; cleanup; exit 130' INT TERM

# ---- BPF objects ----------------------------------------------------------
# Fetched rather than embedded: OpenWrt's busybox ships without the base64
# applet, so a base64 blob in this script cannot be decoded on the router.
# They are plain little-endian eBPF bytecode, portable to any architecture;
# sources and build command are in verify-xdp-sources.md next to this file.
BPF_URL=${BPF_URL:-https://raw.githubusercontent.com/therealahrion/openwrt-glinet-x3000/openwrt-25.12/x3000/docs/bpf}
case "$0" in */*) _here=${0%/*} ;; *) _here=. ;; esac
BPF_DIR=${BPF_DIR:-$_here/bpf}

# The sha256 of each object as committed. This script used to fetch without
# checking, which meant a copy cached in $D from an older revision was used
# silently - the same trap xdp-ft-wwan.sh already guarded against. The fetch
# and the check now come from boxstate.sh, so there is one implementation
# instead of two and the thinner one is gone. Update these alongside the
# objects in bpf/.
obj_want_sha() {
	case "$1" in
	xdp_pass)       echo a862ec14a5928c05863155946a4f7b0591e623b33dfa2ffc4b0f39876a497499 ;;
	xdp_drop)       echo c8df00ebec9a03bc4224120120bef008a0b44a6b67fabbd6dd837b5403fa0379 ;;
	tc_rawip)       echo 0b45aeded4ecfc9beb21fcb216196b15c4d2dc66021e2c70f9fdc9271c7af0d2 ;;
	xdp_tail_probe) echo 2e34ea12f2189b307f6ccfcee5daf55f1632554ac6d6272a68d812198f639f31 ;;
	esac
}

fetch_objs() {
	BS_OBJDIR=$D BS_BPF_DIR=$BPF_DIR BS_BPF_URL=$BPF_URL
	for o in xdp_pass xdp_drop tc_rawip xdp_tail_probe; do
		BS_OBJNAME=$o.bpf
		BS_OBJ=$D/$o.o
		BS_WANT_SHA=$(obj_want_sha "$o")
		bs_fetch_obj || return 1
	done
}
fetch_objs

hdr "0. identity"
info "$(uname -srvm)"
info "board: $(cat /tmp/sysinfo/model 2>/dev/null || echo unknown)"
info "kernel build stamp: $(uname -v)   <- must match the HEAD this was built from"
for f in $D/xdp_pass.o $D/xdp_drop.o $D/tc_rawip.o $D/xdp_tail_probe.o; do
	[ -s "$f" ] || bad "missing $f -- put the .bpf files in $BPF_DIR, or allow the router to reach $BPF_URL"
done
[ -s $D/xdp_pass.o ] && ok "BPF objects available ($(wc -c < $D/xdp_pass.o) bytes for xdp_pass.o)"

hdr "1. kernel config as shipped"
if [ -r /proc/config.gz ]; then
	zcat /proc/config.gz > $D/kcfg
	KEYS="XDP_SOCKETS DEBUG_INFO_BTF DEBUG_INFO_BTF_MODULES NF_FLOW_TABLE
	      NF_FLOW_TABLE_INET NFT_FLOW_OFFLOAD BPF_SYSCALL BPF_JIT PAGE_POOL
	      GRO_CELLS IKCONFIG_PROC"
	case "$(uname -m)" in aarch64) KEYS="$KEYS ARM64_4K_PAGES" ;; esac
	for k in $KEYS; do
		v=$(grep -E "^(# )?CONFIG_$k( is not set|=)" $D/kcfg | head -1)
		case "$v" in
			*=y|*=m) ok "$v" ;;
			*)       bad "CONFIG_$k -> ${v:-absent from .config}" ;;
		esac
	done
else
	bad "/proc/config.gz missing — CONFIG_IKCONFIG_PROC should provide it"
fi

hdr "2. BTF, and the flowtable XDP kfunc it gates"
bs_require_btf
modprobe nf_flow_table 2>/dev/null
bs_require_kfunc nf_flow_table bpf_xdp_flow_lookup

hdr "3. $WANIF exists and advertises the new feature set"
if $IP link show "$WANIF" >/dev/null 2>&1; then
	ok "$WANIF exists"
	$IP -d link show "$WANIF" | sed -n '1,3p' | sed 's/^/          /'
	if $IP -d link show "$WANIF" 2>/dev/null | grep -qi "redirect"; then
		ok "xdp-features advertises redirect"
	else
		skip "this iproute2 does not print xdp-features (not a failure)"
	fi
else
	bad "$WANIF not present — is the modem up? set WANIF=... and re-run"
	cleanup; exit 1
fi

# --- GRO aggregation measurement -------------------------------------------
# Locate InReceives by its header name rather than by a fixed column. On the
# data line $1 is "Ip:", $2 Forwarding, $3 DefaultTTL and $4 InReceives, so a
# hardcoded $3 silently reads a constant and the IPv4 term contributes nothing.
# That bug was invisible here because the load generator downloads over IPv6 and
# the snmp6 term carried the whole measurement.
_in4() { awk '/^Ip:/{ if(h==""){ for(i=1;i<=NF;i++) if($i=="InReceives") c=i; h=1; next } print $c+0 }' /proc/net/snmp; }
_in6() { awk '/^Ip6InReceives/{print $2+0}' /proc/net/snmp6 2>/dev/null || echo 0; }

# Reports five fields: datagrams, delivered skbs, ratio, datagrams dropped,
# bytes per delivered skb.
#
# The last two are not decoration. This ratio divides a driver-side counter by an
# IP-side one, so anything discarded in between is booked as aggregation -
# gro_cells_receive() drops on backlog overflow (gro_cells.c:30-34) and bumps
# rx_dropped, and a busy link can therefore fake an arbitrarily high ratio.
# Bytes-per-skb is the independent check: it cannot exceed gro_max_size, so a
# ratio implying more than that is loss, not coalescing.
gro_measure() {
	_s=${1:-12}
	_p0=$(cat /sys/class/net/$WANIF/statistics/rx_packets)
	_b0=$(cat /sys/class/net/$WANIF/statistics/rx_bytes)
	_d0=$(cat /sys/class/net/$WANIF/statistics/rx_dropped)
	_i0=$(_in4); _j0=$(_in6)
	sleep "$_s"
	_p1=$(cat /sys/class/net/$WANIF/statistics/rx_packets)
	_b1=$(cat /sys/class/net/$WANIF/statistics/rx_bytes)
	_d1=$(cat /sys/class/net/$WANIF/statistics/rx_dropped)
	_i1=$(_in4); _j1=$(_in6)
	_dp=$((_p1-_p0)); _db=$((_b1-_b0)); _dd=$((_d1-_d0))
	_ds=$(( (_i1-_i0) + (_j1-_j0) ))
	if [ "$_ds" -gt 0 ] && [ "$_dp" -gt 0 ]; then
		awk "BEGIN{printf \"%d %d %.2f %d %d\", $_dp, $_ds, $_dp/$_ds, $_dd, $_db/$_ds}"
	else
		echo "$_dp $_ds 0 $_dd 0"
	fi
}

hdr "4. GRO baseline (no program attached)"
if [ "$WITH_TRAFFIC" = 1 ]; then
	start_traffic
else
	info "no load generator (pass --traffic to start one). Drive WAN traffic now, e.g."
	info "  wget -qO /dev/null https://speed.cloudflare.com/__down?bytes=1000000000 &"
fi
info "measuring for 12s ..."
set -- $(gro_measure 12)
BASE_RATIO=$3
info "$WANIF rx_packets=$1   IP InReceives=$2   aggregation=${3}x"
info "dropped=$4   bytes per delivered skb=$5 (gro_max_size caps this)"
if [ "$4" -gt 0 ]; then
	bad "$4 datagrams dropped - the ratio above is inflated by loss, not aggregation"
fi
if [ "$5" -gt 65536 ]; then
	bad "$5 bytes per skb exceeds gro_max_size - the ratio is not coalescing"
fi
if [ "$1" -lt 500 ]; then
	skip "only $1 packets seen — too little traffic for a meaningful ratio"
	BASE_RATIO=0
elif awk "BEGIN{exit !($3 > 1.2)}"; then
	ok "gro_cells is aggregating (${3}x) — 890 is doing its job"
else
	info "aggregation ${3}x — low, but that is traffic-shape dependent, not a failure by itself"
fi

hdr "5. attach XDP in DRV mode — the 891 ndo_bpf test"
if $IP link set dev "$WANIF" xdp obj $D/xdp_pass.o sec xdp 2>$D/err; then
	MODE=$($IP -d link show "$WANIF" | grep -oE 'xdpgeneric|xdpdrv|xdp' | head -1)
	if [ "$MODE" = "xdpgeneric" ]; then
		bad "attached in GENERIC mode — ndo_bpf is not being used"
	else
		ok "attached in DRIVER mode ('$MODE') — 891's ndo_bpf captured it"
	fi
	$IP -d link show "$WANIF" | grep -o 'prog/xdp id [0-9]* name [a-z_]*' | sed 's/^/          /'
	ATTACHED=1
else
	bad "attach failed: $(head -2 $D/err | tr '\n' ' ')"
fi

hdr "6. THE decisive test: GRO must survive the attach"
if [ "$BASE_RATIO" = "0" ]; then
	skip "no usable baseline from step 4 — rerun with sustained WAN traffic"
else
	info "keep the traffic running; measuring again for 12s ..."
	set -- $(gro_measure 12)
	info "with XDP attached: rx_packets=$1  InReceives=$2  aggregation=${3}x   (baseline ${BASE_RATIO}x)"
	if awk "BEGIN{exit !($3 < 1.15)}"; then
		bad "aggregation collapsed to ${3}x — the program landed on dev->xdp_prog (generic), GRO is off"
	elif awk "BEGIN{exit !($3 > $BASE_RATIO * 0.6)}"; then
		ok "GRO survived the attach (${3}x vs ${BASE_RATIO}x baseline) — Method A working as designed"
	else
		bad "aggregation dropped a lot (${3}x vs ${BASE_RATIO}x) — investigate"
	fi
fi

hdr "7. rx_errors must not climb while a program is attached"
if [ -z "$ATTACHED" ]; then skip "nothing attached in step 5"; else
E0=$(cat /sys/class/net/$WANIF/statistics/rx_errors)
sleep 5
E1=$(cat /sys/class/net/$WANIF/statistics/rx_errors)
[ "$E1" -eq "$E0" ] && ok "rx_errors steady at $E0" || bad "rx_errors climbed $E0 -> $E1 (XDP_ABORTED / invalid verdicts?)"
fi

hdr "8. detach"
if [ -z "$ATTACHED" ]; then skip "nothing to detach"; else
$IP link set dev "$WANIF" xdp off 2>/dev/null
$IP -d link show "$WANIF" | grep -q "prog/xdp" && bad "program still attached after detach" || ok "detached cleanly"
fi

hdr "8b. skb-mode attach must collapse GRO — the gro_cells interaction"
# This is the inverse of step 6 and the reason 891 owns ndo_bpf at all.
# generic_xdp_install() stores the program on dev->xdp_prog; netif_elide_gro()
# tests that pointer, and gro_cells_receive() consults it per datagram
# (gro_cells.c:23), dropping to bare netif_rx(). So attaching the SAME program in
# skb mode should switch GRO off. If it does not, the premise behind keeping the
# program on link->xdp_prog is wrong and 891 can be simplified.
if [ "$BASE_RATIO" = "0" ]; then
	skip "no usable baseline from step 4"
elif $IP link set dev "$WANIF" xdpgeneric obj $D/xdp_pass.o sec xdp 2>$D/err; then
	info "attached in skb mode; measuring for 12s ..."
	set -- $(gro_measure 12)
	info "skb mode: rx_packets=$1  InReceives=$2  aggregation=${3}x  dropped=$4  bytes/skb=$5"
	# Must be "xdpgeneric off", not "xdp off". With 891's ndo_bpf present,
	# dev_xdp_mode() resolves an unqualified request to XDP_MODE_DRV
	# (net/core/dev.c:9457), so "xdp off" asks to detach a DRV program that is
	# not there; dev_xdp_attach() then sees new_prog == cur_prog == NULL,
	# skips the driver call and returns 0 (dev.c:9711). A silent no-op that
	# leaves the generic program attached and makes the restore check below
	# fail for the wrong reason.
	$IP link set dev "$WANIF" xdpgeneric off 2>/dev/null
	if $IP -d link show "$WANIF" 2>/dev/null | grep -q 'prog/xdp'; then
		bad "skb-mode program still attached after 'xdpgeneric off'"
	else
		ok "skb-mode program detached"
	fi
	if [ "$4" -gt 0 ]; then
		skip "$4 datagrams dropped during the window - ratio not trustworthy"
	elif awk "BEGIN{exit !($3 < 1.15)}"; then
		ok "GRO collapsed to ${3}x in skb mode (baseline ${BASE_RATIO}x) — confirms the gro_cells/dev->xdp_prog interaction"
	else
		bad "GRO survived skb mode at ${3}x — 891's link->xdp_prog rationale does not hold, investigate"
	fi
	sleep 2
	set -- $(gro_measure 8)
	awk "BEGIN{exit !($3 > $BASE_RATIO * 0.6)}" \
		&& ok "aggregation restored to ${3}x after detach" \
		|| bad "aggregation still ${3}x after detach — state not cleaned up"
else
	skip "skb-mode attach failed: $(head -2 $D/err | tr '\n' ' ')"
fi

if [ "$WITH_DROP" = 1 ]; then
hdr "9. XDP_DROP  [5s WAN blackout — LAN/SSH unaffected]"
	P0=$(cat /sys/class/net/$WANIF/statistics/rx_packets)
	if $IP link set dev "$WANIF" xdp obj $D/xdp_drop.o sec xdp 2>$D/err; then
		sleep 5
		P1=$(cat /sys/class/net/$WANIF/statistics/rx_packets)
		$IP link set dev "$WANIF" xdp off
		D0=$((P1-P0))
		info "rx_packets moved by $D0 while XDP_DROP was attached"
		info "(the driver counts rx_packets AFTER the hook, so a working DROP keeps this near 0)"
		[ "$D0" -lt 50 ] && ok "XDP_DROP is dropping" || bad "packets still counted — DROP not taking effect"
	else
		bad "could not attach drop program: $(head -1 $D/err)"
	fi
else
	skip "XDP_DROP test (pass --with-drop to run it; 5s WAN blackout)"
fi

if [ "$WITH_TC" = 1 ]; then
hdr "10. tc-BPF on a raw-IP device: L3/L4 parse"
	if ! [ -n "$TC" ]; then
		skip "tc absent"
	else
		$TC qdisc show dev "$WANIF" | grep -q clsact || { $TC qdisc add dev "$WANIF" clsact && MADE_CLSACT=1; }
		if $TC filter add dev "$WANIF" ingress bpf da obj $D/tc_rawip.o sec classifier/rawip 2>$D/err; then
			ok "raw-IP tc-BPF program loaded and attached on ingress"
			mount -t tracefs nodev /sys/kernel/tracing 2>/dev/null
			if [ -r /sys/kernel/tracing/trace_pipe ]; then
				: > /sys/kernel/tracing/trace 2>/dev/null
				cat /sys/kernel/tracing/trace_pipe > $D/tp.out 2>/dev/null &
				_tp=$!
				sleep 5; kill $_tp 2>/dev/null
				if grep -q "RAWIP-OK v4\|RAWIP-OK v6" $D/tp.out 2>/dev/null; then
					ok "program parsed L3/L4 correctly on the raw-IP link:"
					grep "RAWIP-OK" $D/tp.out | head -3 | sed 's/^/          /'
				else
					skip "no trace output (needs live WAN traffic during the 5s window)"
				fi
			else
				skip "tracefs unavailable — cannot read bpf_printk output"
			fi
			$TC filter del dev "$WANIF" ingress 2>/dev/null
		else
			bad "tc-BPF load failed: $(head -3 $D/err | tr '\n' ' ')"
		fi
		[ -n "$MADE_CLSACT" ] && $TC qdisc del dev "$WANIF" clsact 2>/dev/null
	fi
else
	skip "tc-BPF test (pass --with-tc to run it)"
fi

hdr "11. AF_XDP — the case that used to oops"
if command -v xdp-loader >/dev/null 2>&1; then
	info "xdp-loader status:"
	xdp-loader status "$WANIF" 2>&1 | sed 's/^/          /'
	info "to test the old crash path:  xdp-loader load -m native $WANIF <af_xdp_prog.o>"
	info "then confirm nothing landed in /sys/fs/pstore/"
else
	skip "xdp-loader not installed"
fi
PST_CRASH=$(ls -1 /sys/fs/pstore/ 2>/dev/null | grep -c '^dmesg-')
PST_OTHER=$(ls -1 /sys/fs/pstore/ 2>/dev/null | grep -vc '^dmesg-')
if [ "${PST_CRASH:-0}" -gt 0 ]; then
	bad "$PST_CRASH crash record(s) in /sys/fs/pstore/ — read them:"
	ls -1 /sys/fs/pstore/ | grep '^dmesg-' | sed 's/^/            /'
else
	ok "no crash records in /sys/fs/pstore/ (no dmesg-ramoops-*)"
fi
if [ "${PST_OTHER:-0}" -gt 0 ]; then
	info "console/pmsg records present — that is pstore capturing, not a fault:"
	for f in /sys/fs/pstore/*; do
		case "${f##*/}" in dmesg-*) continue ;; esac
		info "  ${f##*/}  ($(wc -c < "$f") bytes)"
		info "    from boot: $(grep -m1 -o 'Linux version [^ ]* .*#[0-9]* SMP.*' "$f" 2>/dev/null | sed 's/.*SMP //' || echo unknown)"
	done
	info "  these survive reboots until deleted; clear with: rm /sys/fs/pstore/*"
fi

hdr "12. telegraf footprint (task #86)"
if [ -e /usr/bin/telegraf ]; then
	SZ=$(wc -c < /usr/bin/telegraf 2>/dev/null || echo 0)
	info "/usr/bin/telegraf: $((SZ/1048576)) MB uncompressed"
	if /etc/init.d/telegraf enabled 2>/dev/null; then
		bad "telegraf is ENABLED at boot"
	else
		ok "telegraf disabled at boot (97-telegraf-guard worked)"
	fi
	if ps w 2>/dev/null | grep -q "[t]elegraf"; then bad "telegraf is RUNNING"; else ok "telegraf not running"; fi
else
	ok "telegraf not installed"
fi
info "storage / memory:"
df -h / /overlay 2>/dev/null | sed 's/^/          /'
free -m 2>/dev/null | sed 's/^/          /'

hdr "13. native vs generic: bpf_xdp_adjust_tail has no room under 893"

# The one probe that separates 893's native hook from 891's generic one. Both
# attach through the same ndo_bpf and both report "prog/xdp id N" with no
# xdpgeneric qualifier, so ip -d link cannot tell them apart - that was this
# test's original method and it was wrong.
#
# 893 allocates XDP_PACKET_HEADROOM + datagram + SKB_DATA_ALIGN(sizeof(struct
# skb_shared_info)) and nothing more, so xdp_data_hard_end() lands at the end
# of the datagram and growing the tail must fail with -EINVAL. The generic path
# runs the same program over an skb whose allocation kmalloc rounded up, so the
# same call finds tailroom and succeeds. Two different answers to one question
# is only possible if they are different code.
#
# Measured 2026-09-15: xdpdrv -22, xdpgeneric 0. See xdp-methods-tested.md 24.18.
tail_probe() {   # tail_probe <xdpdrv|xdpgeneric>
	mount | grep -q '/sys/fs/bpf' || mount -t bpf bpf /sys/fs/bpf
	rm -rf "$TP_PIN" 2>/dev/null
	mkdir -p "$TP_PIN"
	bpftool prog load "$D/xdp_tail_probe.o" "$TP_PIN/prog" \
		type xdp pinmaps "$TP_PIN" 2>/dev/null || { skip "$1: prog load failed"; return 1; }
	bpftool net attach "$1" pinned "$TP_PIN/prog" dev "$WANIF" 2>/dev/null ||
		{ skip "$1: attach refused"; rm -rf "$TP_PIN"; return 1; }

	# Never read a counter that has not been shown to move. This gate exists
	# because three runs on 2026-09-15 reported zero and were read as a kernel
	# fault when the generator had silently sent nothing.
	if bs_traffic_gate "$WANIF" ping -c 10 "$PINGHOST"; then
		_seen=$(bpftool map lookup pinned "$TP_PIN/tailprobe" key 0 0 0 0 2>/dev/null |
			sed -n 's/.*"value": *//p' | tr -d ' ,')
		_ret=$(bpftool map lookup pinned "$TP_PIN/tailprobe" key 2 0 0 0 2>/dev/null |
			sed -n 's/.*"value": *//p' | tr -d ' ,')
		info "$1: saw $_seen packets, adjust_tail returned $_ret"
	else
		_seen=; _ret=
	fi

	bpftool net detach "$1" dev "$WANIF" 2>/dev/null
	rm -rf "$TP_PIN"
	[ -n "$_ret" ]
}

TP_PIN=/sys/fs/bpf/tailprobe
PINGHOST=${PINGHOST:-1.1.1.1}
# 18446744073709551594 is 2**64 - 22, which is how an unsigned map slot spells
# -EINVAL. Compared as a string: busybox arithmetic on a 64-bit value that
# large is not worth relying on inside a test.
EINVAL_U64=18446744073709551594

if [ ! -s "$D/xdp_tail_probe.o" ]; then
	skip "13: no xdp_tail_probe object"
elif tail_probe xdpdrv; then
	_drv=$_ret
	if [ "$_drv" = "$EINVAL_U64" ]; then
		ok "native: adjust_tail refused with -EINVAL - frame_sz is the true allocation"
	elif [ "$_drv" = "0" ]; then
		bad "native: adjust_tail SUCCEEDED - frame_sz is overstated, or this is not 893"
		info "  an overstated frame_sz lets the memset run past the end of the buffer"
	else
		bad "native: adjust_tail returned $_drv - neither 0 nor -EINVAL"
	fi
	if tail_probe xdpgeneric; then
		if [ "$_ret" = "$_drv" ]; then
			bad "both paths returned $_ret - they are not being told apart"
			info "  the DRV attach may have fallen back to generic"
		else
			ok "generic returned $_ret against native's $_drv - different code ran"
		fi
	fi
else
	skip "13: the native probe did not run"
fi

stop_traffic

hdr "summary"
printf '  PASS=%d  FAIL=%d  skipped=%d\n' "$PASS" "$FAIL" "$SKIP"
cleanup
[ "$FAIL" -eq 0 ] || exit 1
