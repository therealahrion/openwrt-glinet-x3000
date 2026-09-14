#!/bin/sh
# Load, attach and measure the flowtable-driven XDP path on wwan0.
#
#   xdp-ft-wwan.sh fetch          put the program at $OBJ, from bpf/ or the repo
#   xdp-ft-wwan.sh check          preflight only, changes nothing
#   xdp-ft-wwan.sh probe [secs]   attach the counting program, sample, detach
#   xdp-ft-wwan.sh fastpath       attach the redirecting program and leave it on
#   xdp-ft-wwan.sh status         dump counters
#   xdp-ft-wwan.sh off            detach and unpin
#
# Run `check` first. Every gate it tests is one the program silently depends on,
# so a failure here names the reason rather than leaving a program that
# loads and never hits.

set -eu

IFACE=${IFACE:-wwan0}
OBJ=${OBJ:-/tmp/xdp_ft_wwan.o}
PINDIR=/sys/fs/bpf/xdp_ft
MAPDIR=/sys/fs/bpf/xdp_ft_maps
SECS=${2:-20}

say()  { printf '%s\n' "$*"; }
ok()   { printf '  ok    %s\n' "$*"; }
bad()  { printf '  FAIL  %s\n' "$*"; FAILED=1; }
warn() { printf '  note  %s\n' "$*"; }

# Busybox provides an `ip` that does not understand xdp, so the binary has to
# be chosen by capability rather than by name. Same pick() and same candidate
# list as verify-992a.sh.
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

need() {
	command -v "$1" >/dev/null 2>&1 || { bad "$1 not installed"; return 1; }
}

check() {
	FAILED=0
	say "Preflight for $IFACE"

	need bpftool || true
	need nft || true

	# 1. The interface exists and is the raw-IP device the parser assumes.
	if "$IP" link show "$IFACE" >/dev/null 2>&1; then
		LT=$("$IP" link show "$IFACE" | sed -n 's|.*link/\([a-z]*\).*|\1|p' | head -1)
		case "$LT" in
		rawip|none|void)
			ok "$IFACE is link/$LT - no L2 header, IP at offset 0 as the parser assumes" ;;
		ether)
			bad "$IFACE is link/ether - it carries an Ethernet header this parser would misread" ;;
		*)
			warn "$IFACE is link/${LT:-unknown} - unexpected; check hard_header_len before trusting the parse" ;;
		esac
	else
		bad "$IFACE does not exist"
	fi

	# 2. 992 is loaded, so the attach lands in the driver hook and not generic.
	if "$IP" -d link show "$IFACE" 2>/dev/null | grep -q 'xdp'; then
		warn "$IFACE already has a program attached; 'off' first"
	fi
	if "$IP" -d link show "$IFACE" 2>/dev/null | grep -qi 'xdp-features'; then
		"$IP" -d link show "$IFACE" | tr ' ' '\n' | grep -i 'xdp' | sed 's/^/        /'
	fi

	# 3. BTF, without which the kfunc object was never compiled.
	if [ -r /sys/kernel/btf/vmlinux ]; then
		ok "vmlinux BTF present ($(( $(wc -c < /sys/kernel/btf/vmlinux) / 1024 )) KB)"
	else
		bad "no /sys/kernel/btf/vmlinux - DEBUG_INFO_BTF is off, the kfunc cannot exist"
	fi

	# 4. The kfunc itself. This is the gate that decides everything.
	if bpftool btf dump file /sys/kernel/btf/vmlinux format raw 2>/dev/null \
	   | grep -q 'bpf_xdp_flow_lookup'; then
		ok "bpf_xdp_flow_lookup is in the kernel BTF"
	else
		bad "bpf_xdp_flow_lookup absent - nf_flow_table_bpf.o was not built"
	fi

	# 5. Software flow offload on, hardware OFF. Hardware offload sends
	#    nf_flow_table_offload_setup() down the other branch and the device is
	#    never inserted into the XDP hashtable, so every lookup returns -ENOENT.
	FT=$(nft list ruleset 2>/dev/null | sed -n '/flowtable/,/}/p' || true)
	if [ -n "$FT" ]; then
		ok "a flowtable exists"
		if printf '%s' "$FT" | grep -q "\"$IFACE\""; then
			ok "$IFACE is in the flowtable device list"
		else
			bad "$IFACE is NOT in the flowtable - needs the firewall4 l3_device patch"
			printf '%s\n' "$FT" | sed 's/^/        /'
		fi
		if printf '%s' "$FT" | grep -q 'flags offload'; then
			bad "hardware offload is ON - every lookup will miss. Set flow_offloading_hw=0"
		else
			ok "hardware offload is off, so the XDP hashtable is populated"
		fi
	else
		bad "no flowtable in the ruleset - enable software flow offloading"
	fi

	# 6. A legal redirect target. Only devices advertising ndo_xmit qualify;
	#    devmap refuses the rest, and neither wwan0 nor an AP netdev has it.
	for t in eth0 eth1; do
		if "$IP" -d link show "$t" 2>/dev/null | grep -q 'ndo-xmit'; then
			ok "$t advertises ndo-xmit and is a legal redirect target"
		fi
	done

	[ "${FAILED:-0}" -eq 0 ] && say "" && say "All gates open." || \
		{ say ""; say "Not ready - fix the FAIL lines above."; return 1; }
}

load() {
	prog=$1
	mount | grep -q '/sys/fs/bpf' || mount -t bpf bpf /sys/fs/bpf
	fetch_obj
	rm -rf "$PINDIR" "$MAPDIR" 2>/dev/null || true
	bpftool prog loadall "$OBJ" "$PINDIR" pinmaps "$MAPDIR"
	"$IP" link set dev "$IFACE" xdp pinned "$PINDIR/$prog"
	say "attached $prog to $IFACE"
}

dump() {
	[ -e "$MAPDIR/xdp_ft_stats" ] || { say "not loaded"; return 1; }
	say ""
	say "  seen        packets the program looked at"
	say "  parse_skip  not IPv4/TCP/UDP, fragmented, options, ttl<=1, or FIN/RST"
	say "  miss        parsed, looked up, no flow"
	say "  hit         the flowtable knew the flow"
	say "  not_direct  hit, but the egress needs a neighbour lookup"
	say "  torn_down   hit a flow already being retired"
	say "  no_headroom could not grow an Ethernet header"
	say "  redirect    rewritten and sent"
	say ""
	# Sum the per-CPU values with awk. Not python3, which a lean image may lack,
	# and no strtonum, which is a gawk extension busybox does not have. bpftool's
	# key/value layout varies between versions, so both forms are handled.
	bpftool map dump pinned "$MAPDIR/xdp_ft_stats" 2>/dev/null | awk '
	function h2d(s,   i, c, d, v) {
		v = 0; s = tolower(s)
		for (i = 1; i <= length(s); i++) {
			d = index("0123456789abcdef", substr(s, i, 1)) - 1
			if (d >= 0) v = v * 16 + d
		}
		return v
	}
	BEGIN {
		split("seen parse_skip miss hit not_direct torn_down no_headroom redirect", n, " ")
		k = -1; want_key = 0
	}
	/key:/ {
		line = $0; sub(/.*key:[ \t]*/, "", line)
		if (line ~ /^[0-9a-fA-F][0-9a-fA-F]/) { split(line, a, " "); k = h2d(a[1]) }
		else want_key = 1
		# an inline "value:" may follow on the same line
		if ($0 ~ /value/) { v = $0; sub(/.*value[^:]*:[ \t]*/, "", v); acc(v) }
		next
	}
	want_key && /^[ \t]*[0-9a-fA-F][0-9a-fA-F]/ { split($0, a, " "); k = h2d(a[1]); want_key = 0; next }
	/value/ { v = $0; sub(/.*value[^:]*:[ \t]*/, "", v); if (v ~ /[0-9a-fA-F]/) acc(v); next }
	/^[ \t]*[0-9a-fA-F][0-9a-fA-F]([ \t]+[0-9a-fA-F][0-9a-fA-F])*[ \t]*$/ { acc($0) }
	function acc(s,   i, m, v) {
		if (k < 0) return
		m = split(s, b, " "); v = 0
		for (i = m; i >= 1; i--) if (b[i] ~ /^[0-9a-fA-F][0-9a-fA-F]$/) v = v * 256 + h2d(b[i])
		tot[k] += v
	}
	END { for (i = 0; i <= 7; i++) printf "  %-12s %d\n", n[i+1], tot[i] + 0 }
	'
}

# ---- BPF object -----------------------------------------------------------
# Fetched or read from disk, never base64 in the script: OpenWrt's busybox
# ships without the base64 applet, so an embedded blob cannot be decoded on the
# router. Same reasoning and same layout as verify-992a.sh, whose objects this
# sits beside. Named .bpf rather than .o because the repo's .gitignore has a
# blanket *.o rule.
BPF_URL=${BPF_URL:-https://raw.githubusercontent.com/therealahrion/openwrt-glinet-x3000/openwrt-25.12/x3000/docs/bpf}
case "$0" in */*) _here=${0%/*} ;; *) _here=. ;; esac
BPF_DIR=${BPF_DIR:-$_here/bpf}

fetch_obj() {
	[ -s "$OBJ" ] && return 0
	if [ -s "$BPF_DIR/xdp_ft_wwan.bpf" ]; then
		cat "$BPF_DIR/xdp_ft_wwan.bpf" > "$OBJ"
	elif command -v curl >/dev/null 2>&1; then
		curl -fsSL -o "$OBJ" "$BPF_URL/xdp_ft_wwan.bpf"
	elif command -v wget >/dev/null 2>&1; then
		wget -q -O "$OBJ" "$BPF_URL/xdp_ft_wwan.bpf"
	fi
	[ -s "$OBJ" ] || { say "no object: put xdp_ft_wwan.bpf in $BPF_DIR, or let the router reach $BPF_URL"; exit 1; }
}

case "${1:-check}" in
check)    check ;;
fetch)    fetch_obj && say "object at $OBJ" ;;
probe)    check && load xdp_ft_probe && say "sampling ${SECS}s..." && sleep "$SECS" && dump ;;
fastpath) check && load xdp_ft_fastpath && say "" &&
          say "Attached. Watch for trouble: a client losing connectivity means the" &&
          say "rewrite is wrong - run 'off' immediately." && dump ;;
status)   dump ;;
off)      "$IP" link set dev "$IFACE" xdp off 2>/dev/null || true
          rm -rf "$PINDIR" "$MAPDIR" 2>/dev/null || true
          say "detached and unpinned" ;;
*)        sed -n '2,12p' "$0" ;;
esac
