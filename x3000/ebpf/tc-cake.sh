#!/bin/sh
# tc-cake.sh — manage the tc_cake_mark egress DSCP classifier.
# The cake-cooperative L3/L4 path: clsact egress filter runs BEFORE the
# root qdisc, so it only marks DSCP; cake still shapes every byte.
# Lever-off: nothing runs unless you invoke this.
#
#   ./tc-cake.sh load                       # load + pin (once)
#   ./tc-cake.sh attach <iface> <eth|rawip> # clsact egress + filter
#   ./tc-cake.sh mark <dport> <dscp>        # e.g. mark 3074 46  (game -> EF)
#   ./tc-cake.sh detach <iface>
#   ./tc-cake.sh unload
#
# Attach on your WAN egress:  ./tc-cake.sh attach wwan0 rawip
# (raw IP: L3 at offset 0. Ethernet ifaces: use 'eth', L3 at offset 14.)
#
# Coexists with cake: `tc qdisc add dev wwan0 root cake ...` stays the
# shaper; this adds the clsact hook (handle ffff:) that feeds it DSCP.

set -e
PIN=/sys/fs/bpf/tc_cake
OBJ=${OBJ:-/root/tc_cake_mark.o}

bpffs() { mkdir -p /sys/fs/bpf; mount | grep -q 'type bpf' || mount -t bpf bpf /sys/fs/bpf; }
u32() { printf '%02x %02x %02x %02x' $(($1 & 255)) $((($1>>8)&255)) $((($1>>16)&255)) $((($1>>24)&255)); }

case "$1" in
load)
	bpffs
	[ -e "$PIN/prog" ] && { echo "already loaded"; exit 0; }
	mkdir -p "$PIN"
	bpftool prog load "$OBJ" "$PIN/prog" type sched_cls pinmaps "$PIN/maps"
	echo "loaded + pinned under $PIN"
	;;
attach)
	IF=$2; MODE=$3
	[ -n "$IF" ] && [ -n "$MODE" ] || { echo "usage: $0 attach <iface> <eth|rawip>"; exit 1; }
	IDX=$(cat /sys/class/net/"$IF"/ifindex)
	OFF=0; [ "$MODE" = eth ] && OFF=14
	bpftool map update pinned "$PIN/maps/l3off_map" key hex $(u32 "$IDX") value hex $(u32 "$OFF")
	tc qdisc add dev "$IF" clsact 2>/dev/null || true
	tc filter replace dev "$IF" egress bpf object-pinned "$PIN/prog" direct-action
	echo "attached tc_cake_mark to $IF egress (ifindex $IDX, L3 offset $OFF)"
	;;
mark)
	P=$2; D=$3
	[ -n "$P" ] && [ -n "$D" ] || { echo "usage: $0 mark <dport> <dscp 0-63>"; exit 1; }
	bpftool map update pinned "$PIN/maps/port_dscp" \
		key hex $(printf '%02x %02x' $((P & 255)) $(((P>>8)&255))) \
		value hex $(printf '%02x' $((D & 63)))
	echo "dest port $P -> DSCP $D"
	;;
detach)
	tc filter del dev "$2" egress 2>/dev/null || true
	tc qdisc del dev "$2" clsact 2>/dev/null || true
	echo "detached from $2"
	;;
unload)
	for d in /sys/class/net/*; do i=$(basename "$d")
		tc filter del dev "$i" egress 2>/dev/null || true
		tc qdisc del dev "$i" clsact 2>/dev/null || true
	done
	rm -rf "$PIN"
	echo "detached everywhere, unpinned"
	;;
*)
	sed -n '2,20p' "$0"; exit 1 ;;
esac
