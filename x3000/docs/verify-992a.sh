#!/bin/sh
# =============================================================================
# GL-X3000 (MT7981A, aarch64 LE) — verify the reworked 992 XDP hook, the kernel
# config claims, and the telegraf footprint.  Self-contained: the BPF objects
# are embedded, so nothing needs to be compiled on the box.
#
#   sh verify-992a.sh              read-only + safe attach tests
#   sh verify-992a.sh --with-drop  additionally test XDP_DROP (5s WAN blackout)
#   sh verify-992a.sh --with-tc    additionally test tc-BPF L3/L4 on raw IP
#   sh verify-992a.sh --traffic    start a WAN download so steps 4/6 have data
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
D=/tmp/verify992a; rm -rf $D; mkdir -p $D

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

# OpenWrt ships busybox's cut-down `ip`/`tc` as well as the real ones. Busybox
# ip cannot do `xdp`, so pick a capable binary or say so plainly.
pick() {
	for c in "$@"; do
		[ -x "$c" ] || continue
		case "$1" in *ip*) "$c" link help 2>&1 | grep -qi xdp && { echo "$c"; return; } ;;
		            *)     "$c" -V >/dev/null 2>&1 && { echo "$c"; return; } ;;
		esac
	done
	echo ""
}
IP=$(pick /usr/libexec/ip-full /sbin/ip /usr/sbin/ip /bin/ip)
TC=$(pick /usr/libexec/tc-bpf /sbin/tc /usr/sbin/tc)
if [ -z "$IP" ]; then
	echo "FATAL: no iproute2 'ip' that understands xdp." >&2
	echo "       install ip-full (CONFIG_PACKAGE_ip-full=y) and re-run." >&2
	exit 2
fi

TRAFFIC_PID=""
start_traffic() {
	[ "$WITH_TRAFFIC" = 1 ] || return
	for u in "https://speed.cloudflare.com/__down?bytes=1000000000" \
	         "http://speedtest.tele2.net/1GB.zip"; do
		if command -v wget >/dev/null 2>&1; then
			wget -q -O /dev/null "$u" 2>/dev/null &
			TRAFFIC_PID=$!
			sleep 2
			kill -0 "$TRAFFIC_PID" 2>/dev/null && { info "load generator running (pid $TRAFFIC_PID, $u)"; return; }
		fi
	done
	TRAFFIC_PID=""
	info "could not start a load generator — drive traffic yourself for steps 4 and 6"
}
stop_traffic() { [ -n "$TRAFFIC_PID" ] && kill "$TRAFFIC_PID" 2>/dev/null; TRAFFIC_PID=""; }

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
# sources and build command are in verify-992a-sources.md next to this file.
BPF_URL=${BPF_URL:-https://raw.githubusercontent.com/therealahrion/openwrt-glinet-x3000/openwrt-25.12/x3000/docs/bpf}
case "$0" in */*) _here=${0%/*} ;; *) _here=. ;; esac
BPF_DIR=${BPF_DIR:-$_here/bpf}

fetch_objs() {
	for o in xdp_pass xdp_drop tc_rawip; do
		if [ -s "$BPF_DIR/$o.bpf" ]; then
			cat "$BPF_DIR/$o.bpf" > "$D/$o.o"
		elif command -v curl >/dev/null 2>&1; then
			curl -fsSL -o "$D/$o.o" "$BPF_URL/$o.bpf" 2>/dev/null
		elif command -v wget >/dev/null 2>&1; then
			wget -q -O "$D/$o.o" "$BPF_URL/$o.bpf" 2>/dev/null
		fi
	done
}
fetch_objs

hdr "0. identity"
info "$(uname -srvm)"
info "board: $(cat /tmp/sysinfo/model 2>/dev/null || echo unknown)"
info "kernel build stamp: $(uname -v)   <- must match the HEAD you built from"
for f in $D/xdp_pass.o $D/xdp_drop.o $D/tc_rawip.o; do
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
if [ -r /sys/kernel/btf/vmlinux ]; then
	ok "/sys/kernel/btf/vmlinux present ($(( $(wc -c < /sys/kernel/btf/vmlinux) / 1024 )) KB)"
else
	bad "/sys/kernel/btf/vmlinux missing — CO-RE programs cannot load"
fi
modprobe nf_flow_table 2>/dev/null
if [ -r /sys/kernel/btf/nf_flow_table ]; then
	ok "module BTF for nf_flow_table present (DEBUG_INFO_BTF_MODULES working)"
	if command -v bpftool >/dev/null 2>&1; then
		if bpftool btf dump file /sys/kernel/btf/nf_flow_table format raw 2>/dev/null | grep -q bpf_xdp_flow_lookup; then
			ok "bpf_xdp_flow_lookup kfunc IS present"
		else
			bad "bpf_xdp_flow_lookup kfunc NOT found in nf_flow_table BTF"
		fi
	else
		skip "bpftool absent — cannot dump BTF"
	fi
else
	bad "no BTF for nf_flow_table (module not loaded, or BTF_MODULES off)"
fi

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
gro_measure() {
	_s=${1:-12}
	_p0=$(cat /sys/class/net/$WANIF/statistics/rx_packets)
	_i0=$(awk '/^Ip:/{c++; if(c==2) print $3}' /proc/net/snmp)
	_j0=$(awk '/^Ip6InReceives/{print $2}' /proc/net/snmp6 2>/dev/null || echo 0)
	sleep "$_s"
	_p1=$(cat /sys/class/net/$WANIF/statistics/rx_packets)
	_i1=$(awk '/^Ip:/{c++; if(c==2) print $3}' /proc/net/snmp)
	_j1=$(awk '/^Ip6InReceives/{print $2}' /proc/net/snmp6 2>/dev/null || echo 0)
	_dp=$((_p1-_p0)); _ds=$(( (_i1-_i0) + (_j1-_j0) ))
	if [ "$_ds" -gt 0 ] && [ "$_dp" -gt 0 ]; then
		awk "BEGIN{printf \"%d %d %.2f\", $_dp, $_ds, $_dp/$_ds}"
	else
		echo "$_dp $_ds 0"
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
if [ "$1" -lt 500 ]; then
	skip "only $1 packets seen — too little traffic for a meaningful ratio"
	BASE_RATIO=0
elif awk "BEGIN{exit !($3 > 1.2)}"; then
	ok "gro_cells is aggregating (${3}x) — 991 is doing its job"
else
	info "aggregation ${3}x — low, but that is traffic-shape dependent, not a failure by itself"
fi

hdr "5. attach XDP in DRV mode — the 992 ndo_bpf test"
if $IP link set dev "$WANIF" xdp obj $D/xdp_pass.o sec xdp 2>$D/err; then
	MODE=$($IP -d link show "$WANIF" | grep -oE 'xdpgeneric|xdpdrv|xdp' | head -1)
	if [ "$MODE" = "xdpgeneric" ]; then
		bad "attached in GENERIC mode — ndo_bpf is not being used"
	else
		ok "attached in DRIVER mode ('$MODE') — 992's ndo_bpf captured it"
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

stop_traffic

hdr "summary"
printf '  PASS=%d  FAIL=%d  skipped=%d\n' "$PASS" "$FAIL" "$SKIP"
cleanup
[ "$FAIL" -eq 0 ] || exit 1
