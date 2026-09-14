#!/bin/sh
# The configuration every measurement on this box has to be read against, and
# the shared preflight the other scripts run before they measure anything.
#
# A result without its state is not comparable to anything: GRO on or off, SFO
# or HFO, steering on or off, the shaper present or absent, zram swapping or
# idle, and - on this WAN above all - which address family the traffic actually
# used. Run this with any measurement window and keep the output beside the
# numbers.
#
# Two roles in one file, chosen by how it is entered:
#
#   sh boxstate.sh                instant snapshot
#   sh boxstate.sh mix [secs]     and a timed IPv4/IPv6 split, default 30s
#   BOXSTATE_LIB=1 . boxstate.sh  define the functions and return, printing
#                                 nothing. This is what the other scripts do.
#
# One file rather than four copies, because the copies had already started to
# drift. xdp-ft-wwan.sh carried a comment admitting its pick() was the same
# pick() as verify-992a.sh; boxstate.sh and gro-backlog-ab.sh read GRO, the
# backlog and the threaded flag two different ways; and gro-backlog-ab.sh was
# the only script that read time_squeeze, which 18.3 established is the
# instrument to trust on this box. Sharing them means a fix reaches every
# caller and an instrument warning is written once.
#
# Read-only unless a caller asks for a change through bs_set_*, and everything
# so changed is restored by bs_restore, including on Ctrl-C.
#
# Space-indented on purpose: a literal tab pasted into an interactive shell
# triggers readline completion and prints every command in PATH.

# The library's contract version. A caller that needs a function this file does
# not have, or a function whose meaning changed, should say so rather than
# dying on "not found" three screens later. Bump it when a bs_* function's
# name, arguments or meaning change; adding one does not need a bump.
BOXSTATE_API=1

WAN=${WAN:-wwan0}
# Only meaningful when this file is run, not when it is sourced.
MIX_SECS=${MIX_SECS:-${2:-30}}

# ---------------------------------------------------------------- primitives

bs_say() { printf '%s\n' "$*"; }
bs_kv()  { printf '  %-26s %s\n' "$1" "$2"; }
bs_hdr() { bs_say ""; bs_say "== $*"; }
# The gate functions below report through these three by name, not by value,
# so a caller that keeps its own tally redefines them after sourcing and the
# gates then feed that tally instead of this one:
#
#   BOXSTATE_LIB=1 . boxstate.sh
#   bs_ok()   { ok   "$1"; }        # ok/bad being the caller's own counters
#   bs_bad()  { bad  "$1"; }
#   bs_note() { skip "$1"; }
#
# verify-992a.sh does exactly that. Without it its summary would have
# under-reported, because a gate that moved out of the script stopped moving
# the script's FAIL count with it.
bs_ok()   { printf '  ok    %s\n' "$*"; }
bs_bad()  { printf '  FAIL  %s\n' "$*"; BS_FAILED=1; }
bs_note() { printf '  note  %s\n' "$*"; }
bs_have() { command -v "$1" >/dev/null 2>&1; }

# Interfaces are enumerated, never listed. An earlier revision hardcoded six
# names and would not have shown a CLAT or nat46 device at all - which is
# exactly the thing that turned out to matter most here.
bs_ifaces() { for d in /sys/class/net/*; do echo "${d##*/}"; done; }

# Busybox provides an `ip` that does not understand xdp, so the binary has to
# be chosen by capability rather than by name. This used to be a pick()
# function copied into two scripts.
bs_pick_ip() {
  for c in /usr/libexec/ip-full /sbin/ip /usr/sbin/ip /bin/ip; do
    [ -x "$c" ] || continue
    "$c" link help 2>&1 | grep -qi xdp && { echo "$c"; return 0; }
  done
  echo ""
  return 0
}

# Likewise for tc: busybox tc cannot load a BPF classifier. verify-992a.sh
# picked both binaries with one function that switched on "$1" rather than on
# the candidate it was testing - so it chose the right branch only because the
# first entry of each list happened to decide it, and reordering either list
# would have silently picked the wrong test. Two functions, no switch.
bs_pick_tc() {
  for c in /usr/libexec/tc-bpf /sbin/tc /usr/sbin/tc; do
    [ -x "$c" ] || continue
    "$c" -V >/dev/null 2>&1 && { echo "$c"; return 0; }
  done
  echo ""
  return 0
}

# ------------------------------------------------------------------- readers
#
# One fact per function, each returning a bare value on stdout so a caller can
# compare it, print it, or require it without re-deriving anything.
#
# Every reader exits 0, always. "Absent" is an empty value, not an error. This
# is not tidiness: a caller running under `set -e` aborts on `x=$(reader)` when
# the reader exits non-zero, and it aborts silently, before it has printed
# anything at all. That is exactly what happened the first time xdp-ft-wwan.sh
# called bs_pick_ip - its whole preflight vanished and left an exit status and
# no output. Functions that are genuinely questions rather than readers keep a
# meaningful status, and are named as questions: bs_have, bs_ft_has,
# bs_has_shaper, bs_btf_kfunc, bs_zram_active.

# ARPHRD number: 1 ETHER, 519 RAWIP, 65534 NONE, 772 LOOPBACK.
bs_iface_type() { cat "/sys/class/net/$1/type" 2>/dev/null || true; }
bs_iface_up()   { cat "/sys/class/net/$1/operstate" 2>/dev/null || true; }
bs_mtu()        { cat "/sys/class/net/$1/mtu" 2>/dev/null || true; }

bs_gro() {
  bs_have ethtool || { echo "-"; return; }
  ethtool -k "$1" 2>/dev/null | awk '/^generic-receive-offload:/{print $2}'
}
bs_lro() {
  bs_have ethtool || { echo "-"; return; }
  ethtool -k "$1" 2>/dev/null | awk '/^large-receive-offload:/{print $2}'
}
bs_gro_max() {
  ip -d link show "$1" 2>/dev/null | tr ' ' '\n' \
    | grep -A1 '^gro_max_size$' | tail -1 || true
}
bs_threaded()  { cat "/sys/class/net/$1/threaded" 2>/dev/null || echo "-"; }
bs_backlog()   { cat /proc/sys/net/core/netdev_max_backlog 2>/dev/null || true; }
bs_steering()  { uci -q get network.globals.packet_steering 2>/dev/null || echo unset; }
bs_rps() {
  m=""
  for q in /sys/class/net/$1/queues/rx-*/rps_cpus; do
    [ -r "$q" ] && m="$m $(cat "$q")"
  done
  echo "${m# }"
}

# NAPI exhausting its poll budget. A count, not a time - which is why 18.3
# says to use it rather than /proc/stat, whose time does not conserve on this
# box. Non-zero across a window means the receive path ran out of budget.
# The columns are bare hex with no 0x, and busybox awk has no strtonum, so the
# digits are walked by hand. Column 2 is dropped, column 3 is time_squeeze.
bs_hexsum() {
  [ -r /proc/net/softnet_stat ] || { echo 0; return 0; }
  awk -v c="$1" '{n=0; s=tolower($c);
                  for(i=1;i<=length(s);i++){d=index("0123456789abcdef",substr(s,i,1))-1;
                                            if(d>=0) n=n*16+d}
                  t+=n} END{print t+0}' /proc/net/softnet_stat 2>/dev/null
}
bs_squeeze()         { bs_hexsum 3; }
bs_softnet_dropped() { bs_hexsum 2; }

bs_hfo() { uci -q get firewall.@defaults[0].flow_offloading_hw 2>/dev/null || echo unset; }
bs_sfo() { uci -q get firewall.@defaults[0].flow_offloading 2>/dev/null || echo unset; }
bs_ft_devices() {
  bs_have nft || return 0
  nft list flowtables 2>/dev/null \
    | sed -n 's/.*devices = {\(.*\)}.*/\1/p' | tr -d ' "' || true
}
bs_ft_has() { case ",$(bs_ft_devices)," in *",$1,"*) return 0 ;; *) return 1 ;; esac; }

bs_qdisc() { bs_have tc && tc qdisc show dev "$1" 2>/dev/null; return 0; }
bs_has_shaper() { bs_qdisc "$1" | grep -qE 'cake|htb|tbf'; }

bs_btf_vmlinux_kb() {
  [ -r /sys/kernel/btf/vmlinux ] || { echo ""; return 0; }
  echo $(( $(wc -c < /sys/kernel/btf/vmlinux) / 1024 ))
}
# Is a kfunc present in a module's BTF? Two arguments: module, symbol.
bs_btf_kfunc() {
  [ -r "/sys/kernel/btf/$1" ] || return 1
  bs_have bpftool || return 2
  bpftool btf dump file "/sys/kernel/btf/$1" format raw 2>/dev/null \
    | grep -q "$2"
}

# zram. It matters to a network measurement for two reasons that are easy to
# forget: compression burns cycles on the same two cores that run NAPI, and a
# box that is swapping at all is a box whose allocation latency is not what it
# looks like. Both bear directly on 14.3's question of whether this router is
# CPU-bound.
bs_zram_devices() { for d in /sys/block/zram*; do [ -d "$d" ] && echo "${d##*/}"; done; }
bs_zram_active()  { [ -n "$(bs_zram_devices)" ] && grep -q zram /proc/swaps 2>/dev/null; }

# ------------------------------------------------------- gates and mutations
#
# Three kinds of state, and the distinction is the whole point of sharing this:
#
#   require  the measurement is meaningless unless it holds, so fail early and
#            say why rather than producing a number nobody can read
#   ensure   the script needs it, can set it, and can put it back exactly
#   note     it does not invalidate the result but it changes how to read it
#
# Everything in this file exits 0 except the functions named as questions -
# bs_have, bs_ft_has, bs_has_shaper, bs_btf_kfunc, bs_zram_active - which is
# the only way a caller running under `set -e` can use it without a stray
# non-zero status killing the run before it has printed anything. A setter
# that could not do its work says so with a note line and still exits 0.
#
# Nothing that needs a service reload is ever set automatically. Flipping
# hardware offload means a uci write and `fw4 reload`, which rebuilds the
# ruleset and empties the flowtable - so a script that did it silently would
# destroy the very state it was about to measure, and would leave the box
# changed if it died in between. Those are requires, with the command printed.

BS_FAILED=0

# bs_require <label> <actual> <expected> <why it matters if it does not hold>
bs_require() {
  if [ "$2" = "$3" ]; then
    bs_ok "$1 = $2"
  else
    bs_bad "$1 = ${2:-<unset>}, need $3"
    bs_say "        $4"
  fi
}

# The undo log. One line per target, written the first time that target is
# touched, so a restore puts back what was there before this script ran rather
# than whatever the previous leg of an A/B left behind. gro-backlog-ab.sh used
# to do this with a hand-rolled ORIG_ variable per knob, which is fine for
# three knobs and wrong for the fourth somebody adds.
BS_UNDO=${BS_UNDO:-/tmp/.boxstate-undo}

bs_remember() {
  [ -f "$BS_UNDO" ] || : > "$BS_UNDO"
  grep -q "^$1|$2|" "$BS_UNDO" 2>/dev/null && return 0
  printf '%s|%s|%s\n' "$1" "$2" "$3" >> "$BS_UNDO"
}

# Every change announces itself. A dump that was taken with the box altered
# must never be readable without that fact in the same output.
bs_changed() { printf '  CHANGED  %s\n' "$*"; }

bs_set_sysctl() {
  old=$(sysctl -n "$1" 2>/dev/null)
  [ "$old" = "$2" ] && return 0
  bs_remember sysctl "$1" "$old"
  sysctl -w "$1=$2" >/dev/null 2>&1
  bs_changed "$1: $old -> $2"
}

bs_set_sysfs() {
  [ -w "$1" ] || { bs_note "$1 not writable - left alone"; return 0; }
  old=$(cat "$1" 2>/dev/null)
  [ "$old" = "$2" ] && return 0
  bs_remember sysfs "$1" "$old"
  printf '%s\n' "$2" > "$1" 2>/dev/null
  bs_changed "$1: $old -> $2"
}

bs_set_gro() {
  bs_have ethtool || { bs_note "no ethtool - GRO left alone"; return 0; }
  old=$(bs_gro "$1")
  [ "$old" = "$2" ] && return 0
  bs_remember gro "$1" "$old"
  ethtool -K "$1" gro "$2" 2>/dev/null
  bs_changed "gro $1: $old -> $2"
}

# Callers install this as their trap, so an interrupt cannot leave the box in
# a state the next measurement then silently inherits:
#
#   trap 'bs_restore; exit 130' INT TERM
#
# It is safe to call more than once and safe when nothing was changed.
bs_restore() {
  [ -s "$BS_UNDO" ] || { rm -f "$BS_UNDO"; return 0; }
  bs_say ""
  bs_say "restoring what this run changed:"
  while IFS='|' read -r kind target old; do
    [ -n "$kind" ] || continue
    case "$kind" in
    sysctl) sysctl -w "$target=$old" >/dev/null 2>&1 ;;
    sysfs)  printf '%s\n' "$old" > "$target" 2>/dev/null ;;
    gro)    [ "$old" = "-" ] || ethtool -K "$target" gro "$old" 2>/dev/null ;;
    esac
    bs_say "  $target = $old"
  done < "$BS_UNDO"
  rm -f "$BS_UNDO"
}

# The gates the XDP scripts share. Each one is a require, and each names the
# consequence rather than only the condition, because a preflight that says
# "FAIL" without saying what it breaks gets ignored on the second run.
bs_require_rawip() {
  t=$(bs_iface_type "$1")
  case "$t" in
  519|65534) bs_ok "$1 type $t - no L2 header, IP at offset 0 as the parser assumes" ;;
  1)  bs_bad "$1 type 1 (ARPHRD_ETHER) - carries an Ethernet header this parser would misread"
      bs_say "        Every field would be read 14 bytes early, including the version nibble." ;;
  "") bs_bad "cannot read /sys/class/net/$1/type - does the interface exist?" ;;
  *)  bs_note "$1 type $t - unexpected; confirm there is no L2 header first" ;;
  esac
}

bs_require_btf() {
  kb=$(bs_btf_vmlinux_kb)
  if [ -n "$kb" ]; then
    bs_ok "vmlinux BTF present (${kb} KB)"
  else
    bs_bad "/sys/kernel/btf/vmlinux missing - CO-RE programs cannot relocate"
  fi
}

bs_require_kfunc() {
  # `bs_btf_kfunc ...; rc=$?` looks equivalent and is not: a bare command is
  # not a tested context, so under a caller's `set -e` it aborts before rc is
  # ever assigned. `|| rc=$?` makes it tested and still yields the status.
  rc=0
  bs_btf_kfunc "$1" "$2" || rc=$?
  if [ "$rc" = 0 ]; then
    bs_ok "$2 is in the $1 module BTF"
  else
    case "$rc" in
    2) bs_note "bpftool absent - cannot confirm $2 in $1 BTF" ;;
    *) bs_bad "$2 not found in $1 BTF"
       bs_say "        The module is gated on DEBUG_INFO_BTF_MODULES; without it"
       bs_say "        the kfunc cannot be resolved and the program will not load." ;;
    esac
  fi
}

bs_require_hfo_off() {
  h=$(bs_hfo)
  # "unset" means uci could not be read, not that the setting is off. Reporting
  # ok here would be a gate that passes because it was never actually tested,
  # which is worse than one that fails.
  if [ "$h" = "unset" ]; then
    bs_note "cannot read flow_offloading_hw (no uci?) - hardware offload UNVERIFIED"
    bs_say "        If it is on, every bpf_xdp_flow_lookup() returns -ENOENT and"
    bs_say "        a window of all-misses looks exactly like a broken program."
    return 0
  fi
  if [ "$h" = "1" ]; then
    bs_bad "hardware offload is ON"
    bs_say "        nf_flow_table_offload_setup() then takes the other branch"
    bs_say "        (nf_flow_table_offload.c:1258) and the device is never put in"
    bs_say "        the XDP hashtable, so every bpf_xdp_flow_lookup() returns"
    bs_say "        -ENOENT. Not changed automatically: turning it off means a uci"
    bs_say "        write and 'fw4 reload', which rebuilds the ruleset and empties"
    bs_say "        the flowtable - destroying the state about to be measured."
    bs_say "        Turn it off by hand, let the flows re-form, then re-run:"
    bs_say "          uci set firewall.@defaults[0].flow_offloading_hw=0"
    bs_say "          uci commit firewall && fw4 reload"
  else
    bs_ok "hardware offload is off, so the XDP hashtable is populated"
  fi
}

bs_require_flowtable() {
  d=$(bs_ft_devices)
  if [ -z "$d" ]; then
    bs_bad "no flowtable - software flow offloading is off"
    bs_say "        Nothing is in the XDP hashtable and every lookup misses."
    return
  fi
  bs_ok "a flowtable exists"
  if bs_ft_has "$1"; then
    bs_ok "$1 is in the flowtable device list"
  else
    bs_bad "$1 is NOT in the flowtable device list ($d)"
    bs_say "        nf_flowtable_by_dev() will not find it and every lookup"
    bs_say "        returns -ENOENT. On this tree wwan0 gets there only through"
    bs_say "        the firewall4 patch 001-flowtable-fall-back-to-l3-device."
  fi
}

# A bridge master in the list satisfies hook registration but cannot answer
# which device a packet physically leaves on (nft_flow_offload.c:202), so a
# missing bridge port means XMIT_DIRECT is discarded for every client behind
# it. This is a note, not a require: it decides whether a redirect can ever
# fire, but it does not make the numbers unreadable.
bs_note_bridge_ports() {
  [ -d /sys/class/net/br-lan/brif ] || return 0
  miss=""
  for p in $(ls /sys/class/net/br-lan/brif 2>/dev/null); do
    bs_ft_has "$p" || miss="$miss $p"
  done
  [ -n "$miss" ] && bs_note "br-lan ports missing from the flowtable list:$miss" \
                 || bs_ok "every br-lan port is in the flowtable list"
}

# Sourced as a library: define everything above, print nothing, return here.
[ -n "${BOXSTATE_LIB:-}" ] && return 0

# ------------------------------------------------------------------- report

say() { bs_say "$@"; }
kv()  { bs_kv "$@"; }
hdr() { bs_hdr "$@"; }

say "box state - $(date '+%Y-%m-%d %H:%M:%S')"
kv "kernel" "$(uname -r)"
kv "cpus" "$(grep -c ^processor /proc/cpuinfo)"
[ -r /etc/openwrt_release ] && kv "release" \
  "$(sed -n "s/^DISTRIB_DESCRIPTION='\(.*\)'/\1/p" /etc/openwrt_release)"
kv "uptime" "$(cut -d' ' -f1 /proc/uptime 2>/dev/null)s"

hdr "interfaces"
for i in $(bs_ifaces); do
  t=$(bs_iface_type "$i")
  case "$t" in
    1) tn=ETHER ;; 519) tn=RAWIP ;; 65534) tn=NONE ;; 772) tn=LOOPBACK ;;
    776) tn=SIT ;; 769) tn=IP6GRE ;; *) tn=$t ;;
  esac
  printf '  %-14s type=%-9s oper=%-8s mtu=%s\n' \
    "$i" "$tn" "$(bs_iface_up "$i")" "$(bs_mtu "$i")"
done

# 464XLAT changes what an address-family-specific program can ever see, so it
# is the first thing to establish, not a footnote.
hdr "464XLAT / NAT64"
found=0
for i in $(bs_ifaces); do
  case "$i" in *clat*|*nat46*|*464*|*xlat*) say "  device: $i"; found=1 ;; esac
done
# The output is captured and tested rather than piped straight into `&&`:
# sed exits 0 on empty input, so the previous form set found=1 unconditionally
# and this section could never say "nothing found". It silently showed an empty
# block instead, which reads as "not checked" rather than "checked, absent".
_m=$(lsmod 2>/dev/null | grep -iE '^(nat46|siit|clat)')
[ -n "$_m" ] && { printf '%s\n' "$_m" | sed 's/^/  module: /'; found=1; }
# -x, an exact process-name match, not -f. `pgrep -f clatd` matches any
# process whose whole command line contains the string, which includes the
# shell that is running this script if that command line happens to mention
# it - it reported "process: 1111 bash" during testing. The address test below
# is the strong signal anyway; this is corroboration and must not invent any.
_p=$(pgrep -l -x clatd 2>/dev/null)
[ -n "$_p" ] && { printf '%s\n' "$_p" | sed 's/^/  process: /'; found=1; }
bs_have uci && uci show network 2>/dev/null | grep -iE '464|clat|nat46' | sed 's/^/  uci: /'
# The RFC 7335 service-continuity prefix on the WAN means the modem is the CLAT.
if ip -4 addr show dev "$WAN" 2>/dev/null | grep -q 'inet 192\.0\.0\.'; then
  say "  $WAN carries an RFC 7335 service-continuity address:"
  ip -4 -o addr show dev "$WAN" 2>/dev/null | awk '{print "    " $4}'
  say "  -> the CLAT is inside the modem. Linux sees native IPv4 and hands it"
  say "     to the CLAT gateway; translation happens beyond this box."
  found=1
fi
[ "$found" = 0 ] && say "  nothing found - no CLAT on this box or in the modem"

hdr "addresses"
ip -o addr show 2>/dev/null | awk '{printf "  %-14s %-6s %s\n", $2, $3, $4}'

hdr "routes and resolver"
say "  IPv4 default:"; ip -4 route show default 2>/dev/null | sed 's/^/    /'
say "  IPv6 default:"; ip -6 route show default 2>/dev/null | sed 's/^/    /'
sed -n 's/^nameserver/  nameserver/p' /etc/resolv.conf 2>/dev/null
[ -r /tmp/resolv.conf.d/resolv.conf.auto ] && \
  sed -n 's/^nameserver/  upstream/p' /tmp/resolv.conf.d/resolv.conf.auto 2>/dev/null
say "  A resolver that synthesizes AAAA for IPv4-only hosts is doing DNS64, and"
say "  every dual-stack client will then pick IPv6 for essentially everything."
say "  That decides the family mix of a window, and the mix is a property of"
say "  what the clients are doing rather than of the link: measured windows on"
say "  this box have run from 0.8% IPv4 to 99.99% IPv4 within the hour."

hdr "flow offloading"
bs_have uci && {
  kv "uci flow_offloading" "$(bs_sfo)"
  kv "uci flow_offloading_hw" "$(bs_hfo)"
}
D=$(bs_ft_devices)
if [ -n "$D" ]; then
  kv "flowtable" "present"
  say "    devices: $D"
  bs_note_bridge_ports
else
  kv "flowtable" "ABSENT - software flow offloading is off"
fi
[ "$(bs_hfo)" = "1" ] && {
  say "  NOTE: hardware offload is ON - bpf_xdp_flow_lookup() misses on every"
  say "        packet, and XMIT_DIRECT becomes reachable. The two are exclusive."
}

hdr "packet steering and RPS"
bs_have uci && kv "network.globals.packet_steering" "$(bs_steering)"
for i in $(bs_ifaces); do
  m=$(bs_rps "$i")
  [ -n "$m" ] && kv "rps_cpus $i" "$m"
done
kv "netdev_max_backlog" "$(bs_backlog)"

hdr "NAPI, GRO and offloads"
for i in $(bs_ifaces); do
  [ "$i" = lo ] && continue
  printf '  %-14s gro=%-5s lro=%-5s threaded=%-3s gro_max_size=%s\n' \
    "$i" "$(bs_gro "$i")" "$(bs_lro "$i")" "$(bs_threaded "$i")" "$(bs_gro_max "$i")"
done
kv "time_squeeze (total)" "$(bs_squeeze)"
kv "softnet dropped" "$(bs_softnet_dropped)"
say "  time_squeeze is a count of NAPI polls that exhausted their budget. It is"
say "  the instrument 18.3 says to use in place of /proc/stat, whose time does"
say "  not conserve on this box. A delta of 0 across a saturating window means"
say "  the receive path never ran out of budget."

hdr "zram and memory"
if [ -n "$(bs_zram_devices)" ]; then
  for z in $(bs_zram_devices); do
    ds=$(cat /sys/block/$z/disksize 2>/dev/null)
    alg=$(sed -n 's/.*\[\([a-z0-9-]*\)\].*/\1/p' /sys/block/$z/comp_algorithm 2>/dev/null)
    set -- $(cat /sys/block/$z/mm_stat 2>/dev/null)
    printf '  %-14s disksize=%s alg=%s orig=%s compr=%s used=%s\n' \
      "$z" "${ds:-0}" "${alg:-?}" "${1:-0}" "${2:-0}" "${3:-0}"
  done
  grep zram /proc/swaps 2>/dev/null | awk '{printf "  swap %-9s size=%s used=%s prio=%s\n", $1, $3, $4, $5}'
  bs_zram_active && say "  zram swap is ACTIVE" || say "  zram present but not in /proc/swaps"
  say "  Compression runs on the same two cores as NAPI, so a box that is"
  say "  swapping is not the box 14.3 measured. Read any CPU-bound claim"
  say "  against the used figure above rather than against the disksize."
else
  say "  no zram device"
fi
kv "swappiness" "$(cat /proc/sys/vm/swappiness 2>/dev/null)"
awk '/^(MemTotal|MemAvailable|SwapTotal|SwapFree):/{printf "  %-26s %s %s\n", $1, $2, $3}' /proc/meminfo

hdr "XDP attachments"
bs_have bpftool && bpftool net show 2>/dev/null | sed 's/^/  /' || say "  bpftool absent"
IPBIN=$(bs_pick_ip)
kv "ip that understands xdp" "${IPBIN:-NONE - install ip-full}"

hdr "IRQ placement"
grep -iE 'mhi|mtk|eth' /proc/interrupts 2>/dev/null | head -8 | sed 's/^/  /'
for n in $(grep -iE 'mhi' /proc/interrupts 2>/dev/null | sed 's/^ *\([0-9]*\):.*/\1/'); do
  [ -r "/proc/irq/$n/smp_affinity" ] && kv "irq $n affinity" "$(cat /proc/irq/$n/smp_affinity)"
done
say "  A mask permitting both CPUs while every count lands on one is the"
say "  MSI_FLAG_NO_AFFINITY behaviour: threadirqs moves the handler, not the IRQ."
pgrep irqbalance >/dev/null 2>&1 \
  && kv "irqbalance" "running - it may move those masks mid-window" \
  || kv "irqbalance" "not running"
grep -q threadirqs /proc/cmdline 2>/dev/null \
  && kv "threadirqs" "set on the cmdline" || kv "threadirqs" "not set"

hdr "shaping on $WAN"
if bs_have tc; then
  bs_qdisc "$WAN" | sed 's/^/  /'
  tc qdisc show dev "$WAN" ingress 2>/dev/null | sed 's/^/  ingress: /'
  bs_has_shaper "$WAN" || {
    say "  no shaper: fq_codel without a rate limit does not shape, and a"
    say "  download's bufferbloat is downstream, which needs ingress shaping."
  }
else
  say "  tc absent"
fi
say ""
say "  Any XDP redirect bypasses whatever is above: generic_xdp_tx() calls"
say "  netdev_start_xmit() directly, never dev_queue_xmit(). Section 17.2."

if [ "$1" = mix ]; then
  hdr "IPv4 / IPv6 split over ${MIX_SECS}s"
  say "  Put real traffic through the link now."
  # Located by header name: on the Ip: data line $2 is Forwarding and $3 is
  # DefaultTTL, so a fixed column silently reads a constant.
  in4() { awk '/^Ip:/{ if(h==""){for(i=1;i<=NF;i++) if($i=="InReceives") c=i; h=1; next} print $c+0 }' /proc/net/snmp; }
  in6() { awk '/^Ip6InReceives/{print $2+0}' /proc/net/snmp6 2>/dev/null || echo 0; }
  a4=$(in4); a6=$(in6); p0=$(cat "/sys/class/net/$WAN/statistics/rx_packets"); s0=$(bs_squeeze)
  sleep "$MIX_SECS"
  b4=$(in4); b6=$(in6); p1=$(cat "/sys/class/net/$WAN/statistics/rx_packets"); s1=$(bs_squeeze)
  d4=$((b4-a4)); d6=$((b6-a6)); dp=$((p1-p0))
  kv "$WAN rx_packets" "$dp"
  kv "IPv4 InReceives" "$d4"
  kv "IPv6 InReceives" "$d6"
  kv "time_squeeze delta" "$((s1-s0))"
  [ $((d4+d6)) -gt 0 ] && awk -v a="$d4" -v b="$d6" \
    'BEGIN{printf "  %-26s %.1f%%\n", "IPv4 share", a*100/(a+b)}'
  say ""
  say "  Read this with care, and prefer xdp-ft-wwan.sh probe where the"
  say "  question is what crosses $WAN. InReceives counts IP-layer receives"
  say "  HOST-WIDE and AFTER GRO: it includes LAN-side traffic, and it counts"
  say "  one aggregated super-packet where the wire carried thirty. A paired"
  say "  window measured 134842 IPv4 wire packets on $WAN as 4414 InReceives,"
  say "  and 8 IPv6 wire packets as 14 InReceives - the excess being LAN-side"
  say "  chatter. So this overstates IPv6 whenever WAN IPv6 is low, and it"
  say "  understates every family's packet count by the GRO ratio."
fi
say ""
