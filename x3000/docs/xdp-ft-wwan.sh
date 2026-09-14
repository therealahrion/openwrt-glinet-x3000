#!/bin/sh
# Does bpf_xdp_flow_lookup() hit on the modem interface?
#
#   xdp-ft-wwan.sh check          preflight only, changes nothing
#   xdp-ft-wwan.sh probe [secs]   attach the counting program, sample, detach
#   xdp-ft-wwan.sh status         dump counters without touching the attach
#   xdp-ft-wwan.sh off            detach and unpin
#
# Run check first. Every gate it tests is one the program silently depends on,
# so a failure names the reason rather than leaving a program that loads and
# never hits.
#
# Only the probe is here. The fastpath - NAT rewrite, L2 build, redirect - is a
# separate object, because reading fields out of struct flow_offload_tuple needs
# CO-RE relocations this kernel's BTF resolves ambiguously, and bpftool loadall
# fails the whole object when any single program fails to relocate. Keeping the
# probe apart means the measurement does not wait on that.

set -eu

IFACE=${IFACE:-wwan0}
D=${D:-/tmp/xdp-ft-wwan}
OBJ="$D/xdp_ft_probe.bpf"
PINDIR=/sys/fs/bpf/xdp_ft
MAPDIR=/sys/fs/bpf/xdp_ft_maps
SECS=${2:-30}

say()  { printf '%s\n' "$*"; }
ok()   { printf '  ok    %s\n' "$*"; }
bad()  { printf '  FAIL  %s\n' "$*"; FAILED=1; }
warn() { printf '  note  %s\n' "$*"; }

# Busybox provides an `ip` that does not understand xdp, so the binary has to be
# chosen by capability rather than by name. Same pick() and same candidate list
# as verify-992a.sh.
pick() {
	for c in "$@"; do
		[ -x "$c" ] || continue
		"$c" link help 2>&1 | grep -qi xdp && { echo "$c"; return; }
	done
	echo ""
}
IP=$(pick /usr/libexec/ip-full /sbin/ip /usr/sbin/ip /bin/ip)
if [ -z "$IP" ]; then
	echo "FATAL: no iproute2 'ip' that understands xdp." >&2
	echo "       install ip-full (CONFIG_PACKAGE_ip-full=y) and re-run." >&2
	exit 1
fi

# Fetched or read from disk, never base64 inside the script: busybox here ships
# without the base64 applet. Same layout as verify-992a.sh, whose objects this
# sits beside. Named .bpf rather than .o because of the blanket *.o gitignore.
BPF_URL=${BPF_URL:-https://raw.githubusercontent.com/therealahrion/openwrt-glinet-x3000/openwrt-25.12/x3000/docs/bpf}
case "$0" in */*) _here=${0%/*} ;; *) _here=. ;; esac
BPF_DIR=${BPF_DIR:-$_here/bpf}

fetch_obj() {
	mkdir -p "$D"
	[ -s "$OBJ" ] && return 0
	if [ -s "$BPF_DIR/xdp_ft_probe.bpf" ]; then
		cat "$BPF_DIR/xdp_ft_probe.bpf" > "$OBJ"
	elif command -v curl >/dev/null 2>&1; then
		curl -fsSL -o "$OBJ" "$BPF_URL/xdp_ft_probe.bpf" || true
	elif command -v wget >/dev/null 2>&1; then
		wget -q -O "$OBJ" "$BPF_URL/xdp_ft_probe.bpf" || true
	fi
	[ -s "$OBJ" ] || {
		say "no object: put xdp_ft_probe.bpf in $BPF_DIR, or let the router reach"
		say "$BPF_URL"
		exit 1
	}
}

check() {
	FAILED=0
	say "Preflight for $IFACE"

	command -v bpftool >/dev/null 2>&1 || bad "bpftool not installed"

	# The interface must have no L2 header. Read the ARPHRD number rather than
	# parsing iproute2's label: an ip predating ARPHRD_RAWIP prints link/[519]
	# and the label then says nothing. 519 RAWIP, 65534 NONE, 1 ETHER.
	if "$IP" link show "$IFACE" >/dev/null 2>&1; then
		AT=$(cat "/sys/class/net/$IFACE/type" 2>/dev/null || echo "")
		case "$AT" in
		519|65534) ok "$IFACE type $AT - no L2 header, IP at offset 0 as the parser assumes" ;;
		1)         bad "$IFACE type 1 (ARPHRD_ETHER) - carries an Ethernet header this parser would misread" ;;
		"")        bad "cannot read /sys/class/net/$IFACE/type" ;;
		*)         warn "$IFACE type $AT - unexpected; confirm there is no L2 header first" ;;
		esac
	else
		bad "$IFACE does not exist"
	fi

	if "$IP" -d link show "$IFACE" 2>/dev/null | grep -q 'prog/xdp'; then
		warn "$IFACE already has a program attached; run 'off' first"
	fi

	if [ -r /sys/kernel/btf/vmlinux ]; then
		ok "vmlinux BTF present ($(( $(wc -c < /sys/kernel/btf/vmlinux) / 1024 )) KB)"
	else
		bad "no /sys/kernel/btf/vmlinux - CO-RE programs cannot load"
	fi

	# nf_flow_table is a module here, so the kfunc's BTF is the module's and
	# not vmlinux - the same place verify-992a.sh looks.
	modprobe nf_flow_table 2>/dev/null || true
	if [ -r /sys/kernel/btf/nf_flow_table ]; then
		if bpftool btf dump file /sys/kernel/btf/nf_flow_table format raw 2>/dev/null \
		   | grep -q bpf_xdp_flow_lookup; then
			ok "bpf_xdp_flow_lookup is in the nf_flow_table module BTF"
		else
			bad "bpf_xdp_flow_lookup not in nf_flow_table BTF - nf_flow_table_bpf.o was not built"
		fi
	else
		bad "no BTF for nf_flow_table - module not loaded, or DEBUG_INFO_BTF_MODULES off"
	fi

	# Software flow offload on, hardware off. Hardware offload sends
	# nf_flow_table_offload_setup() down the other branch, so the device is
	# never inserted into the XDP hashtable and every lookup returns -ENOENT.
	FT=$(nft list ruleset 2>/dev/null | sed -n '/flowtable/,/}/p' || true)
	if [ -n "$FT" ]; then
		ok "a flowtable exists"
		if printf '%s' "$FT" | grep -q "\"$IFACE\""; then
			ok "$IFACE is in the flowtable device list"
		else
			bad "$IFACE is NOT in the flowtable - needs the firewall4 l3_device patch"
		fi
		if printf '%s' "$FT" | grep -q 'flags offload'; then
			bad "hardware offload is ON - every lookup will miss. Set flow_offloading_hw=0"
		else
			ok "hardware offload is off, so the XDP hashtable is populated"
		fi
	else
		bad "no flowtable in the ruleset - enable software flow offloading"
	fi

	if [ "${FAILED:-0}" -eq 0 ]; then
		say ""
		say "All gates open."
		return 0
	fi
	say ""
	say "Not ready - fix the FAIL lines above."
	return 1
}

load() {
	mount | grep -q '/sys/fs/bpf' || mount -t bpf bpf /sys/fs/bpf
	fetch_obj
	rm -rf "$PINDIR" "$MAPDIR" 2>/dev/null || true

	if ! bpftool prog loadall "$OBJ" "$PINDIR" pinmaps "$MAPDIR"; then
		say "load failed - nothing reached the kernel and nothing is attached"
		return 1
	fi
	if ! "$IP" link set dev "$IFACE" xdp pinned "$PINDIR/xdp_ft_probe" 2>"$D/err"; then
		say "attach failed - the program loaded but is not on $IFACE"
		sed -n '1,2p' "$D/err" | sed 's/^/        /'
		rm -rf "$PINDIR" "$MAPDIR" 2>/dev/null || true
		return 1
	fi
	# Confirm rather than trust the exit code: an earlier version of this
	# script reported a successful attach after ip had failed, because inside
	# an && list set -e does not fire.
	if "$IP" -d link show "$IFACE" 2>/dev/null | grep -q 'prog/xdp'; then
		ok "attached to $IFACE"
	else
		say "attach reported success but no program is on $IFACE"
		return 1
	fi
}

dump() {
	[ -e "$MAPDIR/xdp_ft_stats" ] || { say "not loaded"; return 1; }
	say ""
	say "  seen          packets the program looked at"
	say "  not_ipv4      version nibble was not 4"
	say "  frag_or_opts  fragmented, or IP options present - the flowtable declines both"
	say "  not_tcp_udp   another L4 protocol"
	say "  short         truncated before the ports"
	say "  miss          looked up, no such flow"
	say "  hit           the flowtable knew the flow"
	say "  lookup_err    the kfunc refused the request, opts.error set"
	say ""
	# Sum the per-CPU values with awk. Not python3, which a lean image may
	# lack, and no strtonum, which is a gawk extension busybox does not have.
	# bpftool's key and value layout varies between versions, so both the
	# inline and split-line forms are handled.
	bpftool map dump pinned "$MAPDIR/xdp_ft_stats" 2>/dev/null | awk '
	function h2d(x,   i, d, v) {
		v = 0; x = tolower(x)
		for (i = 1; i <= length(x); i++) {
			d = index("0123456789abcdef", substr(x, i, 1)) - 1
			if (d >= 0) v = v * 16 + d
		}
		return v
	}
	function acc(s,   i, m, v) {
		if (k < 0) return
		m = split(s, b, " "); v = 0
		for (i = m; i >= 1; i--) if (b[i] ~ /^[0-9a-fA-F][0-9a-fA-F]$/) v = v * 256 + h2d(b[i])
		tot[k] += v
	}
	BEGIN {
		split("seen not_ipv4 frag_or_opts not_tcp_udp short miss hit lookup_err", n, " ")
		k = -1; want_key = 0
	}
	/key:/ {
		line = $0; sub(/.*key:[ \t]*/, "", line)
		if (line ~ /^[0-9a-fA-F][0-9a-fA-F]/) { split(line, a, " "); k = h2d(a[1]) } else want_key = 1
		if ($0 ~ /value/) { v = $0; sub(/.*value[^:]*:[ \t]*/, "", v); acc(v) }
		next
	}
	want_key && /^[ \t]*[0-9a-fA-F][0-9a-fA-F]/ { split($0, a, " "); k = h2d(a[1]); want_key = 0; next }
	/value/ { v = $0; sub(/.*value[^:]*:[ \t]*/, "", v); if (v ~ /[0-9a-fA-F]/) acc(v); next }
	/^[ \t]*[0-9a-fA-F][0-9a-fA-F]([ \t]+[0-9a-fA-F][0-9a-fA-F])*[ \t]*$/ { acc($0) }
	END { for (i = 0; i <= 7; i++) printf "  %-13s %d\n", n[i+1], tot[i] + 0 }
	'
}

detach() {
	# Both modes: a program attached in skb mode is not cleared by `xdp off`
	# alone. Same pair cleanup() in verify-992a.sh removes.
	"$IP" link set dev "$IFACE" xdp off 2>/dev/null || true
	"$IP" link set dev "$IFACE" xdpgeneric off 2>/dev/null || true
	rm -rf "$PINDIR" "$MAPDIR" 2>/dev/null || true
	say "detached and unpinned"
}

# An interrupt during the sample would otherwise leave a program attached to
# the WAN interface. verify-992a.sh traps for the same reason.
trap 'echo; echo "interrupted - reverting"; detach; exit 130' INT TERM

case "${1:-check}" in
check)  check ;;
probe)
	check || exit 1
	load  || exit 1
	say "sampling ${SECS}s - put traffic through $IFACE now"
	RX0=$(cat "/sys/class/net/$IFACE/statistics/rx_packets" 2>/dev/null || echo 0)
	sleep "$SECS"
	RX1=$(cat "/sys/class/net/$IFACE/statistics/rx_packets" 2>/dev/null || echo 0)
	dump
	# A window with no traffic produces zeros that look like a result. The
	# driver counter is independent of the program, so it says whether the
	# sample is worth reading at all.
	RXD=$((RX1 - RX0))
	say ""
	if [ "$RXD" -lt 500 ]; then
		say "only $RXD packets crossed $IFACE during the window - too little to"
		say "conclude anything. Re-run with a download or speedtest in flight."
	else
		say "$RXD packets crossed $IFACE during the window"
	fi
	detach
	;;
status) dump ;;
off)    detach ;;
*)      sed -n '2,9p' "$0" ;;
esac
