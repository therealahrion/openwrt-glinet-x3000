#!/bin/sh
# load-xdp.sh — manage the shared xdp_filter program on the router.
# Lever-off by design: nothing runs unless you invoke this.
#
#   ./load-xdp.sh load                      # load + pin (once)
#   ./load-xdp.sh attach <iface> <eth|rawip> [generic]
#   ./load-xdp.sh detach <iface>
#   ./load-xdp.sh stats
#   ./load-xdp.sh block4 <a.b.c.d>          # drop this source IPv4
#   ./load-xdp.sh unload                    # detach everywhere + unpin
#
# Attach modes on this box:
#   eth0/eth1  -> native (mtk_eth_soc)          : attach eth0 eth
#   wwan0      -> native ONLY with the 992 patch: attach wwan0 rawip
#   wlan*      -> generic only (mac80211)       : attach phy0-ap0 eth generic
#
# One pinned program instance serves every attachment; maps are shared,
# per-interface L2 framing comes from mode_map keyed by ifindex.

set -e
PIN=/sys/fs/bpf/xdp_filter
OBJ=${OBJ:-/root/xdp_filter.o}

bpffs() { mkdir -p /sys/fs/bpf; mount | grep -q 'type bpf' || mount -t bpf bpf /sys/fs/bpf; }

u32() {  # little-endian 4-byte key for bpftool from a decimal
	printf '%02x %02x %02x %02x' $(($1 & 255)) $((($1 >> 8) & 255)) \
		$((($1 >> 16) & 255)) $((($1 >> 24) & 255))
}

case "$1" in
load)
	bpffs
	[ -d "$PIN" ] && { echo "already loaded ($PIN)"; exit 0; }
	mkdir -p "$PIN"
	bpftool prog load "$OBJ" "$PIN/prog" pinmaps "$PIN/maps"
	echo "loaded + pinned under $PIN"
	;;
attach)
	IF=$2; MODE=$3; KIND=${4:-}
	[ -n "$IF" ] && [ -n "$MODE" ] || { echo "usage: $0 attach <iface> <eth|rawip> [generic]"; exit 1; }
	IDX=$(cat /sys/class/net/"$IF"/ifindex)
	M=0; [ "$MODE" = rawip ] && M=1
	bpftool map update pinned "$PIN/maps/mode_map" \
		key hex $(u32 "$IDX") value hex $(u32 "$M")
	if [ "$KIND" = generic ]; then
		bpftool net attach xdpgeneric pinned "$PIN/prog" dev "$IF" overwrite
	else
		bpftool net attach xdp pinned "$PIN/prog" dev "$IF" overwrite
	fi
	echo "attached to $IF (ifindex $IDX, mode $MODE${KIND:+, $KIND})"
	;;
detach)
	bpftool net detach xdp dev "$2" 2>/dev/null || true
	bpftool net detach xdpgeneric dev "$2" 2>/dev/null || true
	echo "detached from $2"
	;;
stats)
	echo "index 0/1 = pass pkts/bytes, 2/3 = drop pkts/bytes (sum across CPUs):"
	bpftool map dump pinned "$PIN/maps/stats_map"
	;;
block4)
	IP=$2; [ -n "$IP" ] || { echo "usage: $0 block4 <a.b.c.d>"; exit 1; }
	K=$(echo "$IP" | awk -F. '{printf "%02x %02x %02x %02x", $1,$2,$3,$4}')
	bpftool map update pinned "$PIN/maps/block4" key hex $K value hex 01
	echo "blocking source $IP"
	;;
block-port)
	P=$2; [ -n "$P" ] || { echo "usage: $0 block-port <dport>"; exit 1; }
	# portblock key is __u16 host-order, little-endian on this box
	bpftool map update pinned "$PIN/maps/portblock" \
		key hex $(printf '%02x %02x' $((P & 255)) $(((P >> 8) & 255))) \
		value hex 01
	echo "dropping dest port $P"
	;;
unload)
	for d in /sys/class/net/*; do
		i=$(basename "$d")
		bpftool net detach xdp dev "$i" 2>/dev/null || true
		bpftool net detach xdpgeneric dev "$i" 2>/dev/null || true
	done
	rm -rf "$PIN"
	echo "detached everywhere, unpinned"
	;;
*)
	sed -n '2,20p' "$0"; exit 1 ;;
esac
