#!/bin/sh
# Does bpf_xdp_flow_lookup() hit on the modem interface?
#
#   xdp-ft-wwan.sh check          preflight only, changes nothing
#   xdp-ft-wwan.sh probe [secs]   attach the counting program, sample, detach
#   xdp-ft-wwan.sh dryrun [secs]  attach the fastpath's decision half, sample,
#                                 detach - counts what the rewrite would have
#                                 done without writing a byte to any packet
#   xdp-ft-wwan.sh status         dump counters without touching the attach
#   xdp-ft-wwan.sh off            detach and unpin
#
# Run check first. Every gate it tests is one the program silently depends on,
# so a failure names the reason rather than leaving a program that loads and
# never hits.
#
# Neither action writes to a packet. The fastpath - NAT rewrite, L2 build,
# redirect - is built and sits in the same object, but nothing here attaches it,
# because the dry run measured every flow on this box as FLOW_OFFLOAD_XMIT_NEIGH
# and a redirect would fire on none of them. See xdp-methods-tested.md 23.8.
#
# Two objects, for one reason that is still good. xdp_ft_probe.bpf reads nothing
# out of struct flow_offload_tuple and so carries no CO-RE relocations at all,
# while xdp_ft_wwan.bpf carries sixty-two. If a kernel bump breaks the struct
# mirrors, the probe still answers whether the kfunc itself works. The original
# reason - that a relocation in the fastpath could not resolve and bpftool
# loadall fails a whole object when one program fails - no longer applies.
#
# Both programs count IPv4 and IPv6. On this link that is the difference between
# a measurement and a flat line: the WAN is 464XLAT with DNS64 upstream and IPv4
# was 0.8% of a measured window.

set -eu

IFACE=${IFACE:-wwan0}
D=${D:-/tmp/xdp-ft-wwan}
PINDIR=/sys/fs/bpf/xdp_ft
MAPDIR=/sys/fs/bpf/xdp_ft_maps
SECS=${2:-30}

# Which object, which program in it, and what its counter slots mean. The
# probe and the dry run share every mechanism here and differ only in these
# three lines, so a fix to the harness reaches both.
case "${1:-check}" in
dryrun)
	OBJNAME=xdp_ft_wwan.bpf
	PROGNAME=xdp_ft_dryrun
	SLOTS="seen not_ip v4 v6 frag_or_opts not_tcp_udp short low_ttl tcp_teardown miss hit dir2 dir3 torn_down not_direct no_out_ifidx read_err nat66 would_redirect no_headroom redirect l3_ok l3_bad iif_ok iif_bad baddir_xmit_direct baddir_xmit_other"
	;;
*)
	OBJNAME=xdp_ft_probe.bpf
	PROGNAME=xdp_ft_probe
	SLOTS="seen not_ip v4 v6 frag_or_opts not_tcp_udp short miss hit lookup_err"
	;;
esac
OBJ="$D/$OBJNAME"

case "$0" in */*) _here=${0%/*} ;; *) _here=. ;; esac

# boxstate.sh is the shared preflight: it owns every reader this script used to
# carry its own copy of, and it is the only place a gate's wording lives. Fetch
# it the same way the objects are fetched, because this script is normally run
# from /tmp after a curl and has no tree beside it.
BOXSTATE_URL=${BOXSTATE_URL:-https://raw.githubusercontent.com/therealahrion/openwrt-glinet-x3000/openwrt-25.12/x3000/docs/boxstate.sh}
BOXSTATE=${BOXSTATE:-$_here/boxstate.sh}
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

# A stale boxstate.sh cached in /tmp from an older revision is the same trap the
# object checksum guards against, and it fails less obviously: a renamed reader
# is "not found" three screens into a run.
BOXSTATE_NEED=1
if [ "${BOXSTATE_API:-0}" != "$BOXSTATE_NEED" ]; then
	echo "FATAL: boxstate.sh is API ${BOXSTATE_API:-none}, this script needs $BOXSTATE_NEED." >&2
	echo "       rm -f /tmp/boxstate.sh and re-run, or pull the tree again so the" >&2
	echo "       two come from the same revision." >&2
	exit 1
fi

say()  { bs_say "$@"; }
ok()   { bs_ok "$@"; }
bad()  { bs_bad "$@"; FAILED=1; }
warn() { bs_note "$@"; }

IP=$(bs_pick_ip)
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

# The sha256 of each object as committed, so a copy cached in $D from an earlier
# revision cannot be used silently. That is not hypothetical: this script updates
# the moment the tree is pulled and the cached object does not, and a window run
# that way reports the previous program's counters under the current program's
# labels. The build is byte-reproducible - see xdp-ft-wwan-sources.md - so an
# exact match is the right test. These two lines and the checksums in that file
# are the same values and are updated together.
case "$OBJNAME" in
xdp_ft_wwan.bpf)
	WANT_SHA=557f1559a0bbeb001a043b4d8c185248b2ee913696202368ca7936ee7442f6f4 ;;
xdp_ft_probe.bpf)
	WANT_SHA=99851352f1cf32ae71987f5de58fcc99ee44bfff262e7fba67731cd98179419c ;;
*)	WANT_SHA= ;;
esac

obj_sha() { sha256sum "$1" 2>/dev/null | cut -d' ' -f1; }

fetch_obj() {
	mkdir -p "$D"

	# A cached object that does not match is discarded rather than reported,
	# because the recovery is always the same and doing it by hand is a step
	# that gets skipped.
	if [ -s "$OBJ" ] && [ -n "$WANT_SHA" ]; then
		have=$(obj_sha "$OBJ")
		if [ -n "$have" ] && [ "$have" != "$WANT_SHA" ]; then
			say "cached $OBJNAME is from another revision - refetching"
			rm -f "$OBJ"
		fi
	fi
	[ -s "$OBJ" ] && return 0

	if [ -s "$BPF_DIR/$OBJNAME" ]; then
		cat "$BPF_DIR/$OBJNAME" > "$OBJ"
	elif command -v curl >/dev/null 2>&1; then
		curl -fsSL -o "$OBJ" "$BPF_URL/$OBJNAME" || true
	elif command -v wget >/dev/null 2>&1; then
		wget -q -O "$OBJ" "$BPF_URL/$OBJNAME" || true
	fi
	[ -s "$OBJ" ] || {
		say "no object: put $OBJNAME in $BPF_DIR, or let the router reach"
		say "$BPF_URL"
		exit 1
	}

	# A mismatch here is the script and the object coming from different
	# revisions, which is fatal: the slot labels would name the wrong
	# counters. An image without sha256sum loses the check and says so,
	# rather than failing a box that is otherwise fine.
	if [ -n "$WANT_SHA" ]; then
		got=$(obj_sha "$OBJ")
		if [ -z "$got" ]; then
			say "note: no sha256sum on this image - object not verified"
		elif [ "$got" != "$WANT_SHA" ]; then
			say "FATAL: $OBJNAME does not match this script."
			say "  want $WANT_SHA"
			say "  got  $got"
			say "  Pull the tree again so the script and the object come"
			say "  from the same revision, then rm -rf $D"
			exit 1
		fi
	fi
}

check() {
	FAILED=0
	say "Preflight for $IFACE"

	command -v bpftool >/dev/null 2>&1 || bad "bpftool not installed"

	# The interface must have no L2 header. Read the ARPHRD number rather than
	# parsing iproute2's label: an ip predating ARPHRD_RAWIP prints link/[519]
	# and the label then says nothing. 519 RAWIP, 65534 NONE, 1 ETHER.
	if "$IP" link show "$IFACE" >/dev/null 2>&1; then
		bs_require_rawip "$IFACE"
	else
		bad "$IFACE does not exist"
	fi

	if "$IP" -d link show "$IFACE" 2>/dev/null | grep -q 'prog/xdp'; then
		warn "$IFACE already has a program attached; run 'off' first"
	fi

	bs_require_btf

	# nf_flow_table is a module here, so the kfunc's BTF is the module's and
	# not vmlinux - the same place verify-992a.sh looks.
	modprobe nf_flow_table 2>/dev/null || true
	bs_require_kfunc nf_flow_table bpf_xdp_flow_lookup

	# Software flow offload on, hardware off, and the interface in the device
	# list. Neither is changed automatically: both need `fw4 reload`, which
	# empties the flowtable and would destroy the state about to be measured.
	bs_require_flowtable "$IFACE"
	bs_require_hfo_off
	bs_note_bridge_ports

	# State that does not invalidate the window but changes how to read it.
	bs_has_shaper "$IFACE" || warn "no shaper on $IFACE - a redirect would bypass"\
" the qdisc anyway, but the baseline latency is unshaped (17.2)"
	pgrep irqbalance >/dev/null 2>&1 && warn "irqbalance is running - it can move"\
" IRQ masks mid-window"
	FAILED=$((FAILED + BS_FAILED))

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
	if ! "$IP" link set dev "$IFACE" xdp pinned "$PINDIR/$PROGNAME" 2>"$D/err"; then
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

legend() {
	say ""
	case "$PROGNAME" in
	xdp_ft_dryrun)
		say "  seen            packets the program looked at"
		say "  not_ip          version nibble was neither 4 nor 6"
		say "  v4              of those, IPv4         (observation, see below)"
		say "  v6              of those, IPv6         (observation, see below)"
		say "  frag_or_opts    v4 fragmented or carrying options; v6 carrying an"
		say "                  extension header. The flowtable declines all of them"
		say "  not_tcp_udp     another L4 protocol"
		say "  short           truncated before the ports"
		say "  low_ttl         ttl or hop limit 1 - forwarding would take it to 0"
		say "  tcp_teardown    FIN or RST, which has to reach conntrack"
		say "  miss            the flowtable did not know the flow. If this"
		say "                  dominates, the traffic is not being offloaded -"
		say "                  a connection terminating ON this router never"
		say "                  enters the flowtable at all"
		say "  hit             it did"
		say "  dir2, dir3      tuple.dir read back as 2 or 3. The kernel writes"
		say "                  dir once and then uses it as a container_of index,"
		say "                  so a value outside 0..1 would fault the kernel"
		say "                  before this program saw it. Non-zero here means"
		say "                  THIS program is misreading it, not the kernel"
		say "  torn_down       the flow is being retired"
		say "  not_direct      xmit_type is not DIRECT - NEIGH needs a lookup this"
		say "                  program cannot do, so those stay on the stack"
		say "  no_out_ifidx    DIRECT but no egress ifindex recorded"
		say "  read_err        a probe read of the flow failed"
		say "  nat66           a v6 flow carrying SNAT or DNAT    (observation)"
		say "  would_redirect  everything checked out; the rewrite would have run"
		say "  no_headroom     unused in a dry run"
		say "  redirect        unused in a dry run"
		say ""
		say "  Diagnostics for dir2/dir3, all observations:"
		say "  l3_ok/l3_bad    tuple.l3proto agrees with the packet's own family"
		say "  iif_ok/iif_bad  tuple.iifidx equals the ingress ifindex"
		say "                  Both are plain scalar reads beside the bitfield."
		say "                  Both ok means the pointer and offsets are right"
		say "                  and only the bitfield extraction is wrong; either"
		say "                  bad means the matched tuple is not the one asked"
		say "                  for and every value read through it is void,"
		say "                  would_redirect included"
		say "  baddir_xmit_*   xmit_type read from the SAME byte as the bad dir."
		say "                  Still reading DIRECT means the byte is intact"
		say ""
		say "  v4, v6, nat66 and the diagnostics are observations, not exits. They describe the"
		say "  window rather than accounting for it, and they do not sum with"
		say "  the rest: every packet counted in v4 or v6 is counted again in"
		say "  whichever exit it took."
		say ""
		say "  would_redirect over seen is the number that decides whether the"
		say "  rewrite is worth attaching at all - but only once miss is small."
		say "  Three windows were thrown away for want of that check: two"
		say "  measured IPv6 with an IPv4-only program, one measured traffic"
		say "  that terminated on the router and was never a flowtable"
		say "  candidate. The v4 and v6 slots exist so the first of those"
		say "  mistakes is visible in the same dump as the result."
		;;
	*)
		say "  seen          packets the program looked at"
		say "  not_ip        version nibble was neither 4 nor 6"
		say "  v4            of those, IPv4    (observation - does not sum)"
		say "  v6            of those, IPv6    (observation - does not sum)"
		say "  frag_or_opts  v4 fragmented or with options; v6 with an extension"
		say "                header. The flowtable declines all of them"
		say "  not_tcp_udp   another L4 protocol"
		say "  short         truncated before the ports"
		say "  miss          looked up, no such flow"
		say "  hit           the flowtable knew the flow"
		say "  lookup_err    the kfunc returned NULL. Note that an ordinary miss sets"
		say "                opts.error too (nf_flow_table_bpf.c:49), so this counts"
		say "                misses as well as refusals and the miss slot stays 0"
		;;
	esac
	say ""
}

# `status` has no way of knowing which program left the map behind, and naming
# twenty-seven slots with the probe's ten labels would print confident nonsense.
# The map itself says which: the probe declares ten entries, the dry run
# twenty-seven.
adopt_slots_from_map() {
	ents=$(bpftool map show pinned "$MAPDIR/xdp_ft_stats" 2>/dev/null \
	       | sed -n 's/.*max_entries \([0-9][0-9]*\).*/\1/p' | head -1)
	case "${ents:-}" in
	27)
		PROGNAME=xdp_ft_dryrun
		SLOTS="seen not_ip v4 v6 frag_or_opts not_tcp_udp short low_ttl tcp_teardown miss hit dir2 dir3 torn_down not_direct no_out_ifidx read_err nat66 would_redirect no_headroom redirect l3_ok l3_bad iif_ok iif_bad baddir_xmit_direct baddir_xmit_other"
		;;
	10)
		PROGNAME=xdp_ft_probe
		SLOTS="seen not_ip v4 v6 frag_or_opts not_tcp_udp short miss hit lookup_err"
		;;
	esac
}

dump() {
	[ -e "$MAPDIR/xdp_ft_stats" ] || { say "not loaded"; return 1; }
	adopt_slots_from_map
	legend
	# Ask for JSON explicitly rather than taking whatever this build's bpftool
	# prints by default. A bpftool too old for -j fails here, leaves raw empty
	# and the plain dump is parsed instead.
	raw=$(bpftool -j map dump pinned "$MAPDIR/xdp_ft_stats" 2>/dev/null) || raw=
	[ -n "$raw" ] || raw=$(bpftool map dump pinned "$MAPDIR/xdp_ft_stats" 2>/dev/null) || raw=
	if [ -z "$raw" ]; then
		say "  bpftool printed nothing for $MAPDIR/xdp_ft_stats"
		return 1
	fi

	# Sum the per-CPU values with awk. Not python3, which a lean image may
	# lack, and no strtonum, which is a gawk extension busybox does not have.
	#
	# Three output shapes have to be handled, because which one appears
	# depends on the bpftool build and on whether the map carries BTF:
	#
	#   text     key: 00 00 00 00  value (CPU 00): 27 f1 00 ...
	#   json     {"key":["0x00",...],"values":[{"cpu":0,"value":["0x27",...]}]}
	#   json+btf the same, with a "formatted" object repeating the entry in
	#            decimal (tools/bpf/bpftool/map.c:161-186, v6.12)
	#
	# The third shape carries every counter twice, so when "formatted" is
	# present only those objects are parsed and the hex arrays are dropped.
	# Counting both is a silent doubling, which is worse than a parse error.
	#
	# The JSON scan walks the buffer as a token stream rather than line by
	# line: bpftool without -p emits the whole map on one line, and a
	# line-oriented rule reading that collapses every digit in the map into
	# one number.
	out=$(printf '%s\n' "$raw" | awk -v slots="$SLOTS" '
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
	# Read the number after a JSON name, either a bare decimal or a
	# little-endian array of "0xNN" bytes. Leaves the position just past it
	# in gp so the caller can carry on from there.
	function jnum(s, p,   c, e, t, m, i, v) {
		while (p <= length(s)) {
			c = substr(s, p, 1)
			if (c == ":" || c == " " || c == "\t") { p++; continue }
			break
		}
		if (substr(s, p, 1) == "[") {
			e = index(substr(s, p), "]")
			if (e == 0) { gp = length(s) + 1; return 0 }
			t = substr(s, p + 1, e - 2)
			gp = p + e
			m = split(t, b, ","); v = 0
			for (i = m; i >= 1; i--) v = v * 256 + h2d(b[i])
			return v
		}
		v = 0
		while (p <= length(s)) {
			c = substr(s, p, 1)
			if (c >= "0" && c <= "9") { v = v * 10 + (c + 0); p++ } else break
		}
		gp = p
		return v
	}
	# Keep only the balanced object after each "formatted" name. Safe here
	# because the map key and value are integers, so no string in the dump
	# can carry an unbalanced brace.
	function fmtonly(s,   out, p, q, d, c, st, L) {
		out = ""; p = 1; L = length(s)
		while ((q = index(substr(s, p), "\"formatted\"")) > 0) {
			p = p + q + 10
			while (p <= L && substr(s, p, 1) != "{") p++
			st = p; d = 0
			while (p <= L) {
				c = substr(s, p, 1)
				if (c == "{") d++
				else if (c == "}") { d--; if (d == 0) { p++; break } }
				p++
			}
			out = out substr(s, st, p - st) " "
		}
		return out
	}
	BEGIN {
		nslot = split(slots, n, " ")
		k = -1; want_key = 0; json = 0
	}
	# Once a JSON token has been seen every later line belongs to the buffer,
	# including continuation lines carrying neither name.
	json || /"key"|"values"/ { json = 1; buf = buf $0 " "; next }
	/key:/ {
		line = $0; sub(/.*key:[ \t]*/, "", line)
		if (line ~ /^[0-9a-fA-F][0-9a-fA-F]/) { split(line, a, " "); k = h2d(a[1]) } else want_key = 1
		if ($0 ~ /value/) { v = $0; sub(/.*value[^:]*:[ \t]*/, "", v); acc(v) }
		next
	}
	want_key && /^[ \t]*[0-9a-fA-F][0-9a-fA-F]/ { split($0, a, " "); k = h2d(a[1]); want_key = 0; next }
	/value/ { v = $0; sub(/.*value[^:]*:[ \t]*/, "", v); if (v ~ /[0-9a-fA-F]/) acc(v); next }
	/^[ \t]*[0-9a-fA-F][0-9a-fA-F]([ \t]+[0-9a-fA-F][0-9a-fA-F])*[ \t]*$/ { acc($0) }
	END {
		if (json) {
			if (index(buf, "\"formatted\"")) buf = fmtonly(buf)
			k = -1; p = 1; L = length(buf)
			while (p <= L) {
				s = substr(buf, p)
				kp = index(s, "\"key\"")
				vp = index(s, "\"value\"")
				if (kp == 0 && vp == 0) break
				if (kp != 0 && (vp == 0 || kp < vp)) {
					np = p + kp + 4
					k = jnum(buf, np)
				} else {
					np = p + vp + 6
					v = jnum(buf, np)
					if (k >= 0) tot[k] += v
				}
				# Always move past the token just read, even when no
				# number followed it, or this loop never terminates.
				p = (gp > np) ? gp : np
			}
		}
		for (i = 0; i < nslot; i++) printf "  %-15s %d\n", n[i+1], tot[i] + 0
	}
	')
	printf '%s\n' "$out"

	# Eight zeros against a pinned map means the parser is the likelier
	# suspect, not the program. Reading zeros off live counters cost a whole
	# debugging round once, so show what bpftool actually printed instead of
	# leaving the next reader to discover the format the hard way.
	if ! printf '%s\n' "$out" | grep -qv ' 0$'; then
		say ""
		say "  every slot reads zero. If traffic did cross $IFACE while the"
		say "  program was attached, suspect this parser before the program."
		say "  bpftool printed:"
		printf '%s\n' "$raw" | cut -c1-200 | head -4 | sed 's/^/    /'
	fi
}

detach() {
	# Both modes: a program attached in skb mode is not cleared by `xdp off`
	# alone. Same pair cleanup() in verify-992a.sh removes.
	unhook
	rm -rf "$PINDIR" "$MAPDIR" 2>/dev/null || true
	say "detached and unpinned"
}

# Taking the program off the interface is separate from unpinning the map,
# because the sample has to stop before the counters are read. Dumping while
# still attached let a packet bump hit after that slot had been read and bump
# its exit slot before that one was, so the exits came to 39 more than the hits
# in one window - small, but it is the kind of discrepancy that gets blamed on
# the program.
unhook() {
	# Both modes: a program attached in skb mode is not cleared by `xdp off`
	# alone. Same pair cleanup() in verify-992a.sh removes.
	"$IP" link set dev "$IFACE" xdp off 2>/dev/null || true
	"$IP" link set dev "$IFACE" xdpgeneric off 2>/dev/null || true
}

# An interrupt during the sample would otherwise leave a program attached to
# the WAN interface. verify-992a.sh traps for the same reason.
trap 'echo; echo "interrupted - reverting"; detach; exit 130' INT TERM

case "${1:-check}" in
check)  check ;;
probe|dryrun)
	check || exit 1
	load  || exit 1
	say "sampling ${SECS}s - put traffic through $IFACE now"
	RX0=$(cat "/sys/class/net/$IFACE/statistics/rx_packets" 2>/dev/null || echo 0)
	sleep "$SECS"
	RX1=$(cat "/sys/class/net/$IFACE/statistics/rx_packets" 2>/dev/null || echo 0)
	# Stop counting before reading the counters, or the map is dumped under
	# live traffic and the slots are read at different instants.
	unhook
	# Never let a failed read abort the branch: set -e would take the script
	# out before detach, leaving a program attached to the WAN interface.
	dump || true
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
