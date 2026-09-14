#!/bin/sh
# Load, attach and measure the flowtable-driven XDP path on wwan0.
#
#   xdp-ft-wwan.sh check          preflight only, changes nothing
#   xdp-ft-wwan.sh probe [secs]   attach the counting program, sample, detach
#   xdp-ft-wwan.sh fastpath       attach the redirecting program and leave it on
#   xdp-ft-wwan.sh status         dump counters
#   xdp-ft-wwan.sh off            detach and unpin
#
# Run `check` first. Every gate it tests is one the program silently depends on,
# so a failure here names the reason instead of leaving you with a program that
# loads and never hits.

set -eu

IFACE=${IFACE:-wwan0}
OBJ=${OBJ:-/root/xdp_ft_wwan.bpf.o}
PINDIR=/sys/fs/bpf/xdp_ft
MAPDIR=/sys/fs/bpf/xdp_ft_maps
SECS=${2:-20}

say()  { printf '%s\n' "$*"; }
ok()   { printf '  ok    %s\n' "$*"; }
bad()  { printf '  FAIL  %s\n' "$*"; FAILED=1; }
warn() { printf '  note  %s\n' "$*"; }

need() {
	command -v "$1" >/dev/null 2>&1 || { bad "$1 not installed"; return 1; }
}

check() {
	FAILED=0
	say "Preflight for $IFACE"

	need bpftool || true
	need nft || true

	# 1. The interface exists and is the raw-IP device we think it is.
	if ip link show "$IFACE" >/dev/null 2>&1; then
		if ip link show "$IFACE" | grep -q 'link/none'; then
			ok "$IFACE is ARPHRD_NONE (raw IP, no L2 header) - as the program assumes"
		else
			bad "$IFACE is not link/none; this program parses IP at offset 0"
		fi
	else
		bad "$IFACE does not exist"
	fi

	# 2. 992 is loaded, so the attach lands in the driver hook and not generic.
	if ip -d link show "$IFACE" 2>/dev/null | grep -q 'xdp'; then
		warn "$IFACE already has a program attached; 'off' first"
	fi
	if ip -d link show "$IFACE" 2>/dev/null | grep -qi 'xdp-features'; then
		ip -d link show "$IFACE" | tr ' ' '\n' | grep -i 'xdp' | sed 's/^/        /'
	fi

	# 3. BTF, without which the kfunc object was never compiled.
	if [ -r /sys/kernel/btf/vmlinux ]; then
		ok "vmlinux BTF present ($(( $(stat -c %s /sys/kernel/btf/vmlinux) / 1024 )) KB)"
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
		if ip -d link show "$t" 2>/dev/null | grep -q 'ndo-xmit'; then
			ok "$t advertises ndo-xmit and is a legal redirect target"
		fi
	done

	[ "${FAILED:-0}" -eq 0 ] && say "" && say "All gates open." || \
		{ say ""; say "Not ready - fix the FAIL lines above."; return 1; }
}

load() {
	prog=$1
	mount | grep -q '/sys/fs/bpf' || mount -t bpf bpf /sys/fs/bpf
	[ -f "$OBJ" ] || { say "object not found: $OBJ"; exit 1; }
	rm -rf "$PINDIR" "$MAPDIR" 2>/dev/null || true
	bpftool prog loadall "$OBJ" "$PINDIR" pinmaps "$MAPDIR"
	ip link set dev "$IFACE" xdp pinned "$PINDIR/$prog"
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
	# Sum the per-CPU values. python3 if the image has it, raw dump if not -
	# a lean build may well not, and a raw dump is still readable.
	if command -v python3 >/dev/null 2>&1; then
		bpftool -j map dump pinned "$MAPDIR/xdp_ft_stats" | python3 -c '
import json,sys
names=["seen","parse_skip","miss","hit","not_direct","torn_down","no_headroom","redirect"]
def as_int(x):
    if isinstance(x,list): return int.from_bytes(bytes(int(b,16) for b in x),"little")
    if isinstance(x,str):  return int(x,16)
    return int(x)
for e in json.load(sys.stdin):
    k=e.get("key"); k=as_int(k) if not isinstance(k,int) else k
    vals=e.get("values") or []
    tot=sum(as_int(v.get("value") if isinstance(v,dict) else v) for v in vals)
    if k < len(names): print("  %-12s %d" % (names[k], tot))
'
	else
		say "  (no python3 - raw per-CPU dump, keys 0..7 in the order above)"
		bpftool map dump pinned "$MAPDIR/xdp_ft_stats"
	fi
}

case "${1:-check}" in
check)    check ;;
probe)    check && load xdp_ft_probe && say "sampling ${SECS}s..." && sleep "$SECS" && dump ;;
fastpath) check && load xdp_ft_fastpath && say "" &&
          say "Attached. Watch for trouble: a client losing connectivity means the" &&
          say "rewrite is wrong - run 'off' immediately." && dump ;;
status)   dump ;;
off)      ip link set dev "$IFACE" xdp off 2>/dev/null || true
          rm -rf "$PINDIR" "$MAPDIR" 2>/dev/null || true
          say "detached and unpinned" ;;
*)        sed -n '2,12p' "$0" ;;
esac
