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
	SLOTS="seen not_ip v4 v6 frag_or_opts not_tcp_udp short low_ttl tcp_teardown miss hit bad_dir torn_down not_direct no_out_ifidx read_err nat44 nat66 would_redirect no_headroom redirect l3_ok l3_bad iif_ok iif_bad"
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
BOXSTATE_NEED=3
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
# without the base64 applet. Same layout as verify-xdp.sh, whose objects this
# sits beside. Named .bpf rather than .o because of the blanket *.o gitignore.
BPF_URL=${BPF_URL:-https://raw.githubusercontent.com/therealahrion/openwrt-glinet-x3000/openwrt-25.12/x3000/docs/bpf}
case "$0" in */*) _here=${0%/*} ;; *) _here=. ;; esac
BPF_DIR=${BPF_DIR:-$_here/bpf}

# The shared machinery lives in boxstate.sh as of 2026-09-15: object fetch and
# verification, the load-and-confirm-the-mode attach, and the map slot parser.
# This script had the better version of all three, so those are the ones that
# moved; verify-xdp.sh now calls the same code instead of its own thinner copy.
# Binding the script's names to the library's inputs here keeps the rest of the
# file reading the way it did.
BS_OBJDIR=$D
BS_OBJ=$OBJ
BS_OBJNAME=$OBJNAME
BS_WANT_SHA=$WANT_SHA
BS_BPF_DIR=$BPF_DIR
BS_BPF_URL=$BPF_URL
BS_PINDIR=$PINDIR
BS_MAPDIR=$MAPDIR
BS_PROGNAME=$PROGNAME
BS_IFACE=$IFACE
BS_IP=$IP


# The sha256 of each object as committed, so a copy cached in $D from an earlier
# revision cannot be used silently. That is not hypothetical: this script updates
# the moment the tree is pulled and the cached object does not, and a window run
# that way reports the previous program's counters under the current program's
# labels. The build is byte-reproducible - see xdp-ft-wwan-sources.md - so an
# exact match is the right test. These two lines and the checksums in that file
# are the same values and are updated together.
case "$OBJNAME" in
xdp_ft_wwan.bpf)
	WANT_SHA=38198343560f1a0fc08e1c6a2af4699b86e2869c55e5a91f2ea2acd9443dcf63 ;;
xdp_ft_probe.bpf)
	WANT_SHA=99851352f1cf32ae71987f5de58fcc99ee44bfff262e7fba67731cd98179419c ;;
*)	WANT_SHA= ;;
esac


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

	# bs_xdp_mode rather than a 'prog/xdp' grep: the two spellings iproute2
	# uses, prog/xdp and prog/xdpgeneric, both match that pattern, and which
	# one is present decides whether 890's GRO is running. See the attach site.
	_pre=$(bs_xdp_mode "$IFACE")
	case "$_pre" in
		none|-) : ;;
		*) warn "$IFACE already has a program attached ($_pre mode); run 'off' first" ;;
	esac

	bs_require_btf

	# nf_flow_table is a module here, so the kfunc's BTF is the module's and
	# not vmlinux - the same place verify-xdp.sh looks.
	modprobe nf_flow_table 2>/dev/null || true
	bs_require_kfunc nf_flow_table bpf_xdp_flow_lookup

	# Software flow offload on, hardware off, and the interface in the device
	# list. Neither is changed automatically: both need `fw4 reload`, which
	# empties the flowtable and would destroy the state about to be measured.
	bs_require_flowtable "$IFACE"
	bs_require_hfo_off
	bs_note_bridge_ports
	bs_note_direct_scope

	# State that does not invalidate the window but changes how to read it.
	bs_has_shaper "$IFACE" || warn "no shaper on $IFACE - a redirect would bypass"\
" the qdisc anyway, but the baseline latency is unshaped (17.2)"
	pgrep irqbalance >/dev/null 2>&1 && warn "irqbalance is running - it can move"\
" IRQ masks mid-window"

	# The settings that change how the numbers read, on one line, because a
	# gates-only run would otherwise print a window with no state beside it.
	bs_state_line "$IFACE"
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
		say "  bad_dir         tuple.dir outside 0..1. The kernel writes dir"
		say "                  once and then uses it as a container_of index, so"
		say "                  a 2 or a 3 would have faulted the kernel before"
		say "                  this program saw it. Non-zero is a real anomaly"
		say "  torn_down       the flow is being retired"
		say "  not_direct      xmit_type is not DIRECT - NEIGH needs a lookup this"
		say "                  program cannot do, so those stay on the stack."
		say "                  WHICH BRIDGE PORT THE CLIENT IS ON DECIDES THIS."
		say "                  Measured 2026-09-14 over five windows: a wired"
		say "                  client on eth1 was DIRECT on 100% of hits, and the"
		say "                  same client moved to Wi-Fi was DIRECT on none, in"
		say "                  either family. A window driven from a Wi-Fi client"
		say "                  therefore reads zero here whatever else is true,"
		say "                  and that is the program being right rather than"
		say "                  failing. See xdp-methods-tested.md 23.17"
		say "  no_out_ifidx    DIRECT but no egress ifindex recorded"
		say "  read_err        a probe read of the flow failed"
		say "  nat66           a v6 flow carrying SNAT or DNAT    (observation)"
		say "  would_redirect  everything checked out; the rewrite would have run"
		say "  no_headroom     unused in a dry run"
		say "  redirect        unused in a dry run"
		say ""
		say "  nat44, nat66    a flow carrying SNAT or DNAT, by family. There is"
		say "                  no nat64 slot because no NAT64 state exists in this"
		say "                  kernel to count: on a 464XLAT link the CLAT is in"
		say "                  the modem and the NAT64 is in the carrier network,"
		say "                  so neither translation is ever a flow here"
		say "  l3_ok/l3_bad    tuple.l3proto agrees with the packet's own family"
		say "  iif_ok/iif_bad  tuple.iifidx equals the ingress ifindex"
		say "                  Both are part of the lookup key, so a tuplehash"
		say "                  disagreeing with either is not the one that was"
		say "                  asked for and everything read through it is void"
		say ""
		say "  v4, v6, nat44, nat66 and l3_ok/iif_ok are observations, not exits."
		say "  They describe the"
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
# twenty-five slots with the probe's ten labels would print confident nonsense.
# The map itself says which: the probe declares ten entries, the dry run
# twenty-five.
adopt_slots_from_map() {
	ents=$(bpftool map show pinned "$MAPDIR/xdp_ft_stats" 2>/dev/null \
	       | sed -n 's/.*max_entries \([0-9][0-9]*\).*/\1/p' | head -1)
	case "${ents:-}" in
	25)
		PROGNAME=xdp_ft_dryrun
		SLOTS="seen not_ip v4 v6 frag_or_opts not_tcp_udp short low_ttl tcp_teardown miss hit bad_dir torn_down not_direct no_out_ifidx read_err nat44 nat66 would_redirect no_headroom redirect l3_ok l3_bad iif_ok iif_bad"
		;;
	10)
		PROGNAME=xdp_ft_probe
		SLOTS="seen not_ip v4 v6 frag_or_opts not_tcp_udp short miss hit lookup_err"
		;;
	esac
}

# Read one array map and print "label value" per slot. One parser, three
# callers: the counters, the relocation constants and the byte histogram. A
# second parser written for the simpler maps would reintroduce the bugs this
# one already has fixed - the silent doubling when BTF adds a "formatted"
# object, and the whole-map-on-one-line token walk.
#
#   bs_dump_slots <map name> <space-separated labels>

# The relocation constants CO-RE patched in, and the bytes read with them.
# Diagnostic, and it comes out with the slots it explains - see 23.14.
RELO_SLOTS="dir_off dir_sz dir_lshift dir_rshift xmit_off xmit_sz xmit_lshift xmit_rshift l3_off iif_off tuple_off rhash_sz raw_lo raw_hi"

dump_relo() {
	[ -e "$MAPDIR/xdp_ft_relo" ] || return 0
	say ""
	say "relocation constants, as libbpf patched them against this kernel:"
	bs_dump_slots xdp_ft_relo "$RELO_SLOTS" || return 0
	say ""
	say "  l3_off and iif_off are the controls. Their reads agreed with the"
	say "  packet on every lookup, so whatever they say a correct offset looks"
	say "  like on this kernel is the yardstick for dir_off. Check by hand:"
	say "    l3proto and iifidx sit at tuple+40 and tuple+36, so with tuple_off"
	say "    added they pin the layout. dir's containing unit should land on the"
	say "    bitfield byte, and dir_lshift/dir_rshift should select two bits of"
	say "    it. raw_lo and raw_hi are the eight bytes actually read."
}

dump_dirbyte() {
	[ -e "$MAPDIR/xdp_ft_dirbyte" ] || return 0
	_l=""; _i=0
	while [ "$_i" -lt 256 ]; do _l="$_l b$_i"; _i=$((_i + 1)); done
	_out=$(bs_dump_slots xdp_ft_dirbyte "${_l# }" 2>/dev/null | awk '$2 != 0') || return 0
	[ -n "$_out" ] || return 0
	say ""
	say "byte at dir_off, every value seen (index is the byte, decimal):"
	printf '%s\n' "$_out"
	say ""
	say "  One value dominating means the read lands on a real field and takes"
	say "  the wrong bits out of it. A spread means it is not reading that"
	say "  field at all. For a REPLY flow with no encapsulation the bitfield"
	say "  byte should be (xmit_type << 2) | 1 - so 5 for NEIGH, 13 for DIRECT."
}

dump() {
	[ -e "$MAPDIR/xdp_ft_stats" ] || { say "not loaded"; return 1; }
	adopt_slots_from_map
	legend
	bs_dump_slots xdp_ft_stats "$SLOTS" || return 1
	dump_relo
	dump_dirbyte
}

detach() {
	# Both modes: a program attached in skb mode is not cleared by `xdp off`
	# alone. Same pair cleanup() in verify-xdp.sh removes.
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
	# alone. Same pair cleanup() in verify-xdp.sh removes.
	"$IP" link set dev "$IFACE" xdp off 2>/dev/null || true
	"$IP" link set dev "$IFACE" xdpgeneric off 2>/dev/null || true
}

# An interrupt during the sample would otherwise leave a program attached to
# the WAN interface. verify-xdp.sh traps for the same reason.
trap 'echo; echo "interrupted - reverting"; detach; exit 130' INT TERM

case "${1:-check}" in
check)  check ;;
probe|dryrun)
	check || exit 1
	bs_xdp_load_attach || exit 1
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
