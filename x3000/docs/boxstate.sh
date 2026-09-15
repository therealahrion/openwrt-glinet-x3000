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
# pick() as verify-xdp.sh; boxstate.sh and gro-backlog-ab.sh read GRO, the
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
BOXSTATE_API=3

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
# verify-xdp.sh does exactly that. Without it its summary would have
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

# Likewise for tc: busybox tc cannot load a BPF classifier. verify-xdp.sh
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

# Which XDP mode a program is attached in, or "none".
#
# This is not cosmetic. iproute2 renders XDP_ATTACHED_DRV as "prog/xdp" and
# XDP_ATTACHED_SKB as "prog/xdpgeneric", so a pattern for 'prog/xdp' matches
# BOTH and cannot tell them apart - which is the mistake xdp-ft-wwan.sh makes at
# its attach and verify sites. The distinction is load-bearing here because only
# the skb one sets dev->xdp_prog and therefore elides GRO; see
# bs_gro_effective() below. The cases are ordered longest-first so the bare
# 'prog/xdp*' arm is reached only after the two specific spellings have failed;
# a case glob has no word boundary to anchor on, so the order IS the guard.
#
# bs_pick_ip, not a bare `ip`: busybox's applet does not understand xdp and
# prints nothing about it, so a bare `ip -d link show` would report "none" for a
# device that has a program attached. That is the whole reason bs_pick_ip
# exists, and reaching for `ip` directly here would have reintroduced the bug it
# was written to kill.
bs_xdp_mode() {
  _ip=$(bs_pick_ip)
  [ -n "$_ip" ] || { echo "-"; return; }
  _x=$("$_ip" -d link show "$1" 2>/dev/null) || { echo "-"; return; }
  case "$_x" in
    *prog/xdpgeneric*) echo generic ;;
    *prog/xdpoffload*) echo offload ;;
    *prog/xdp*)        echo native ;;
    *)                 echo none ;;
  esac
}

# Whether GRO is ACTUALLY happening, which is not what `ethtool -k` reports.
#
# netif_elide_gro() (include/linux/netdevice.h:2423) is
#
#     !(dev->features & NETIF_F_GRO) || dev->xdp_prog
#
# and dev->xdp_prog is set only by generic_xdp_install() (net/core/dev.c:5944),
# so it means "a program is attached in skb mode". ethtool sees the feature bit
# and nothing else, so it reports "on" while a generic XDP program is eliding
# GRO underneath it.
#
# That distinction decides real behaviour on this box. gro_cells_receive()
# (net/core/gro_cells.c:23) tests the same predicate and falls straight through
# to netif_rx() when it holds, so with a generic program attached the per-CPU
# gro_cells queues 991 installs are never touched at all - the WAN is back to
# its pre-991 receive path while ethtool still says GRO is on.
bs_gro_effective() {
  _f=$(bs_gro "$1")
  # "-" is bs_gro's no-ethtool answer and "" is an interface it could not read.
  # Neither means off, and reporting them as off would be the same class of
  # mistake this function exists to fix.
  case "$_f" in
    on)   : ;;
    -|"") echo "unknown (no ethtool, cannot read the feature bit)"; return ;;
    *)    echo "off (feature bit $_f)"; return ;;
  esac
  case "$(bs_xdp_mode "$1")" in
    generic) echo "off (elided by generic XDP)" ;;
    -)       echo "unknown (no xdp-capable ip, cannot rule out generic XDP)" ;;
    *)       echo "on" ;;
  esac
}
bs_lro() {
  bs_have ethtool || { echo "-"; return; }
  ethtool -k "$1" 2>/dev/null | awk '/^large-receive-offload:/{print $2}'
}
bs_gro_max() {
  ip -d link show "$1" 2>/dev/null | tr ' ' '\n' \
    | grep -A1 '^gro_max_size$' | tail -1 || true
}
# The two GRO bits the core leaves OFF, which therefore say something when set.
#
# NETIF_F_GRO is in NETIF_F_SOFT_FEATURES and register_netdevice() turns it on
# for every netdev (dev.c:10575), so reading it back says nothing - which is why
# bs_gro_effective() exists. These two are in NETIF_F_SOFT_FEATURES_OFF
# (netdev_features.h:240): exposed in hw_features, off unless somebody set them.
# So unlike gro, "on" here is a fact about this box rather than about Linux.
#
# rx-udp-gro-forwarding (NETIF_F_GRO_UDP_FWD) lets GRO aggregate UDP the router
# FORWARDS rather than terminates - udp_offload.c:654 gates the !sk case on it.
# Without it, forwarded UDP gets no GRO at all. It was turned on by hand on
# 2026-09-14 and this snapshot could not see it, which is how it got added.
bs_gro_udp_fwd() {
  bs_have ethtool || { echo "-"; return; }
  ethtool -k "$1" 2>/dev/null | awk '/^rx-udp-gro-forwarding:/{print $2}'
}
bs_gro_fraglist() {
  bs_have ethtool || { echo "-"; return; }
  ethtool -k "$1" 2>/dev/null | awk '/^rx-gro-list:/{print $2}'
}

# Elapsed time in CENTISECONDS, for windows that need to divide by it.
#
# Not `date +%s`: that is whole seconds, so a true 20.0s window reads as 20 or
# 21 depending only on where the window happened to fall inside a second - an
# 8% error on a 12s window, silently, in the divisor of every rate. wifi-encap.sh
# was doing exactly that. And not busybox `date +%s%N` either: busybox has no
# %N and prints the literal characters, which would parse as a wild number.
#
# /proc/uptime is seconds with two decimals on every Linux, so it gives
# centisecond resolution with no tools at all.
#
# The two halves are added arithmetically rather than concatenated, because
# concatenation reintroduces an octal bug: uptime "0.50" becomes the string
# "050", and $((050)) is 40, not 50. `10#` would also fix it but is a bashism
# busybox merely tolerates.
bs_now_cs() {
  read -r _u _ < /proc/uptime 2>/dev/null || { echo 0; return 0; }
  _s=${_u%.*}; _f=${_u#*.}
  _f=${_f#0}; [ -n "$_f" ] || _f=0
  echo $(( _s * 100 + _f ))
}

bs_threaded()  { cat "/sys/class/net/$1/threaded" 2>/dev/null || echo "-"; }
bs_backlog()   { cat /proc/sys/net/core/netdev_max_backlog 2>/dev/null || true; }
bs_steering()  { uci -q get network.globals.packet_steering 2>/dev/null || echo unset; }
# Read one attribute across every queue of an interface.
#
# `[ -r ]` is not a sufficient guard here and the state capture proved it: the
# 2026-09-14 clean-boot snapshot printed "cat: read error: No such file or
# directory" nine times, interleaved with the values it did read. The test
# passes because open() succeeds - the file exists with a readable mode - and
# then read() returns -ENOENT, which sysfs does when the backing object has no
# value to show. That happens on bridges and wireless vifs for xps_cpus and for
# rps_flow_cnt.
#
# So the read itself has to be allowed to fail: stderr to /dev/null, and an
# empty result contributes nothing rather than an error line. A reference
# document that prints errors between its facts invites the reader to wonder
# which of the facts also failed.
bs_qattr() {
  m=""
  for q in /sys/class/net/$1/queues/$2-*/$3; do
    [ -r "$q" ] || continue
    v=$(cat "$q" 2>/dev/null) || continue
    [ -n "$v" ] && m="$m $v"
  done
  echo "${m# }"
}

bs_rps() { bs_qattr "$1" rx rps_cpus; }

# RFS is not RPS. rps_cpus says which CPUs a queue may steer to; rps_flow_cnt
# and the global rps_sock_flow_entries say whether flows are additionally
# pinned to the CPU their socket last ran on. A box can have RPS on and RFS
# entirely off, which is the usual OpenWrt default, and the two answer
# different questions about where a packet is processed.
bs_rfs_global() { cat /proc/sys/net/core/rps_sock_flow_entries 2>/dev/null || true; }
bs_rfs() { bs_qattr "$1" rx rps_flow_cnt; }
bs_xps() { bs_qattr "$1" tx xps_cpus; }

# TCP congestion control. It decides the shape of every throughput and latency
# number this tree records, and nothing was reading it: cubic and bbr fill a
# bottleneck queue quite differently, so a bufferbloat measurement that does
# not say which one was running is not comparable to one that does.
bs_tcp_cc()       { cat /proc/sys/net/ipv4/tcp_congestion_control 2>/dev/null || true; }
bs_tcp_cc_avail() { cat /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null || true; }
bs_tcp_ecn()      { cat /proc/sys/net/ipv4/tcp_ecn 2>/dev/null || true; }
bs_tcp_sack()     { cat /proc/sys/net/ipv4/tcp_sack 2>/dev/null || true; }

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

bs_hfo() {
  # Three outcomes, not two. `uci -q get` returns non-zero for an option that
  # is simply absent, so the old reader called that "unset" and the gate below
  # degraded to UNVERIFIED - a gate that had in fact passed, reported as never
  # tested, in every window run on 2026-09-14. firewall4 declares the default
  # itself, in root/usr/share/ucode/fw4.uc:
  #     flow_offloading_hw: [ "bool", "0" ]
  # so an absent option means off. Only a missing uci is genuinely unreadable.
  bs_have uci || { echo unreadable; return 0; }
  _h=$(uci -q get firewall.@defaults[0].flow_offloading_hw 2>/dev/null)
  [ -n "$_h" ] && echo "$_h" || echo 0
  return 0
}
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
  # Only a missing uci is unverifiable. An absent option reads as 0 above,
  # because firewall4's own default is 0 - see bs_hfo. Reporting ok for a value
  # nothing could read would be a gate that passes because it was never tested,
  # which is worse than one that fails.
  if [ "$h" = "unreadable" ]; then
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

# One line of the settings that change how a number reads, for callers that run
# the gates without the full report. xdp-ft-wwan.sh dryrun printed its gates and
# nothing else, so a window could be read without knowing the congestion control
# or whether steering was on - which is the whole thing this file exists to stop.
bs_state_line() {
  bs_say "  state: cc=$(bs_tcp_cc) ecn=$(bs_tcp_ecn) steering=$(bs_steering)" \
         "rps[$1]=$(bs_rps "$1") rfs=$(bs_rfs_global) gro=$(bs_gro "$1")" \
         "threaded=$(bs_threaded "$1") backlog=$(bs_backlog) squeeze=$(bs_squeeze)"
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
  return 0
}

# Being in the list is necessary and, for a Wi-Fi port, not sufficient. Measured
# 2026-09-14 across five windows: a wired client on eth1 reached
# FLOW_OFFLOAD_XMIT_DIRECT on 100% of flowtable hits, and the same client moved
# to Wi-Fi reached it on none, in either address family.
#
# dev_fill_forward_path() (dev.c) walks while a device has ndo_fill_forward_path
# and returns -1 as soon as one of them errors; only a device with no callback
# at all falls through to DEV_PATH_ETHERNET, which is the branch that sets
# info->indev. eth1 has no callback, so it takes that branch. A Wi-Fi vif on the
# 802.3 data path has one (mac80211 iface.c:956), it delegates to the driver,
# and mt76 returns -ENODEV unless WED is active (mt7915/main.c:1776).
#
# So this reports scope rather than a pass or a fail: the list is right, and
# what benefits from it is the wired half of the bridge.
bs_note_direct_scope() {
  [ -d /sys/class/net/br-lan/brif ] || return 0
  wired="" wifi=""
  for p in $(ls /sys/class/net/br-lan/brif 2>/dev/null); do
    if [ -d "/sys/class/net/$p/wireless" ] || [ -e "/sys/class/net/$p/phy80211" ]; then
      wifi="$wifi $p"
    else
      wired="$wired $p"
    fi
  done
  # Being a plain netdev is necessary for XMIT_DIRECT but not sufficient: 23.17
  # established that the bridge PORT must also be in the flowtable device list.
  # An earlier revision reported "XMIT_DIRECT is reachable for clients on: eth1"
  # in the same snapshot whose line above said eth1 was missing from that list -
  # two contradicting statements, three lines apart, in the document every other
  # measurement is read against. Split the wired ports by what the flowtable
  # actually holds.
  _in="" _out=""
  for p in $wired; do
    if bs_ft_has "$p"; then _in="$_in $p"; else _out="$_out $p"; fi
  done
  [ -n "$_in" ]  && bs_note "XMIT_DIRECT is reachable now for clients on:$_in"
  [ -n "$_out" ] && bs_note "and would be for:$_out - plain netdevs, but not in the flowtable device list (23.17)"
  [ -n "$wifi" ] && bs_note "and never for:$wifi - the vif has an ndo_fill_forward_path that fails, whatever the list says (23.18)"
  return 0
}

# Offloaded flows, attributed to the LAN client and the bridge port it is on.
#
# Two bugs are deliberately baked out of this, because both produced confident
# wrong output before they were caught:
#
#   - The ORIGINAL tuple's src is the LAN client. A greedy `.*src=` matches the
#     REPLY tuple instead and reports the remote server, which made every
#     "LAN-side source" a public address. Take the FIRST src= field.
#   - `bridge fdb show` prints "<mac> dev <port> master <bridge>", so "dev" is
#     field 2 and the port is field 3. Reading the keyword at field 3 reported
#     every port as unknown.
bs_ct_offload() {
  [ -r /proc/net/nf_conntrack ] || return 0
  awk '/OFFLOAD/{for(i=1;i<=NF;i++) if($i ~ /^src=/){print $1" "substr($i,5); break}}' \
      /proc/net/nf_conntrack 2>/dev/null
  return 0
}

bs_port_of() {
  bs_have bridge || { echo ""; return 0; }
  _m=$(ip neigh show 2>/dev/null | awk -v i="$1" '$1==i && $2=="lladdr"{print $3; exit}')
  [ -n "$_m" ] || { echo ""; return 0; }
  bridge fdb show 2>/dev/null \
    | awk -v m="$_m" '$1==m && $2=="dev" && /master/{print $3; exit}'
  return 0
}

# Sourced as a library: define everything above, print nothing, return here.

# ---------------------------------------------------------------------------
# Shared BPF/XDP machinery.
#
# Moved here on 2026-09-15 from xdp-ft-wwan.sh, which had the better version of
# every one of these, so that verify-xdp.sh stops carrying its own. Two
# implementations of "fetch an object and check it" is how one of them ends up
# without the check - which is exactly what verify-xdp.sh's fetch_objs was.
#
# Callers set the BS_* inputs each helper names and then call it.
# ---------------------------------------------------------------------------

bs_obj_sha() { sha256sum "$1" 2>/dev/null | cut -d' ' -f1; }


bs_fetch_obj() {
    mkdir -p "$BS_OBJDIR"

    # A cached object that does not match is discarded rather than reported,
    # because the recovery is always the same and doing it by hand is a step
    # that gets skipped.
    if [ -s "$BS_OBJ" ] && [ -n "$BS_WANT_SHA" ]; then
        have=$(obj_sha "$BS_OBJ")
        if [ -n "$have" ] && [ "$have" != "$BS_WANT_SHA" ]; then
            bs_say "cached $BS_OBJNAME is from another revision - refetching"
            rm -f "$BS_OBJ"
        fi
    fi
    [ -s "$BS_OBJ" ] && return 0

    if [ -s "$BS_BPF_DIR/$BS_OBJNAME" ]; then
        cat "$BS_BPF_DIR/$BS_OBJNAME" > "$BS_OBJ"
    elif command -v curl >/dev/null 2>&1; then
        curl -fsSL -o "$BS_OBJ" "$BS_BPF_URL/$BS_OBJNAME" || true
    elif command -v wget >/dev/null 2>&1; then
        wget -q -O "$BS_OBJ" "$BS_BPF_URL/$BS_OBJNAME" || true
    fi
    [ -s "$BS_OBJ" ] || {
        bs_say "no object: put $BS_OBJNAME in $BS_BPF_DIR, or let the router reach"
        bs_say "$BS_BPF_URL"
        return 1
    }

    # A mismatch here is the script and the object coming from different
    # revisions, which is fatal: the slot labels would name the wrong
    # counters. An image without sha256sum loses the check and says so,
    # rather than failing a box that is otherwise fine.
    if [ -n "$BS_WANT_SHA" ]; then
        got=$(obj_sha "$BS_OBJ")
        if [ -z "$got" ]; then
            bs_say "note: no sha256sum on this image - object not verified"
        elif [ "$got" != "$BS_WANT_SHA" ]; then
            bs_say "FATAL: $BS_OBJNAME does not match this script."
            bs_say "  want $BS_WANT_SHA"
            bs_say "  got  $got"
            bs_say "  Pull the tree again so the script and the object come"
            bs_say "  from the same revision, then rm -rf $BS_OBJDIR"
            return 1
        fi
    fi
}

bs_xdp_load_attach() {
    mount | grep -q '/sys/fs/bpf' || mount -t bpf bpf /sys/fs/bpf
    bs_fetch_obj
    rm -rf "$BS_PINDIR" "$BS_MAPDIR" 2>/dev/null || true

    if ! bpftool prog loadall "$BS_OBJ" "$BS_PINDIR" pinmaps "$BS_MAPDIR"; then
        bs_say "load failed - nothing reached the kernel and nothing is attached"
        return 1
    fi
    if ! "${BS_IP:-ip}" link set dev "$BS_IFACE" xdp pinned "$BS_PINDIR/$BS_PROGNAME" 2>"$BS_OBJDIR/err"; then
        bs_say "attach failed - the program loaded but is not on $BS_IFACE"
        sed -n '1,2p' "$BS_OBJDIR/err" | sed 's/^/        /'
        rm -rf "$BS_PINDIR" "$BS_MAPDIR" 2>/dev/null || true
        return 1
    fi
    # Confirm rather than trust the exit code: an earlier version of this
    # script reported a successful attach after ip had failed, because inside
    # an && list set -e does not fire.
    #
    # And confirm WHICH MODE, not merely that something attached. Plain `ip
    # link set ... xdp` is best-effort: dev_xdp_mode() (net/core/dev.c:9444)
    # takes the driver's ndo_bpf if it has one and falls to skb mode if not,
    # with no retry. That choice decides whether 991's GRO survives, because
    # only the skb path sets dev->xdp_prog, which is what netif_elide_gro()
    # tests and what gro_cells_receive() checks per datagram - landing in
    # generic mode silently reverts the WAN to its pre-991 netif_rx() path.
    # A grep for 'prog/xdp' cannot see the difference: iproute2 spells the
    # skb attachment 'prog/xdpgeneric', which that pattern also matches.
    _mode=$(bs_xdp_mode "$BS_IFACE")
    case "$_mode" in
        native)
            bs_ok "attached to $BS_IFACE in native mode (991's GRO intact)" ;;
        generic)
            bs_note "attached to $BS_IFACE in GENERIC mode - dev->xdp_prog is set,"
            bs_note "  so netif_elide_gro() is now true and gro_cells_receive()"
            bs_note "  falls through to netif_rx(). 991's GRO is OFF while this"
            bs_note "  program is attached. Expect 992 to be missing from the"
            bs_note "  kernel; with it, dev_xdp_mode() would have chosen native." ;;
        offload)
            bs_ok "attached to $BS_IFACE in hardware-offload mode" ;;
        none)
            bs_say "attach reported success but no program is on $BS_IFACE"
            return 1 ;;
        *)
            bs_note "attached to $BS_IFACE, but no xdp-capable ip could read the mode"
            bs_note "  - cannot tell whether 991's GRO survived the attach" ;;
    esac
}

bs_dump_slots() {
    _map=$1
    [ -e "$BS_MAPDIR/$_map" ] || { bs_say "  $_map not pinned"; return 1; }
    # Ask for JSON explicitly rather than taking whatever this build's bpftool
    # prints by default. A bpftool too old for -j fails here, leaves raw empty
    # and the plain dump is parsed instead.
    raw=$(bpftool -j map dump pinned "$BS_MAPDIR/$_map" 2>/dev/null) || raw=
    [ -n "$raw" ] || raw=$(bpftool map dump pinned "$BS_MAPDIR/$_map" 2>/dev/null) || raw=
    if [ -z "$raw" ]; then
        bs_say "  bpftool printed nothing for $BS_MAPDIR/$_map"
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
    out=$(printf '%s\n' "$raw" | awk -v slots="$2" '
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

    # Every slot zero against a pinned map means the parser is the likelier
    # suspect, not the program. Reading zeros off live counters cost a whole
    # debugging round once, so show what bpftool actually printed instead of
    # leaving the next reader to discover the format the hard way.
    if ! printf '%s\n' "$out" | grep -qv ' 0$'; then
        bs_say ""
        bs_say "  every slot of $_map reads zero. If traffic did cross $BS_IFACE while"
        bs_say "  the program was attached, suspect this parser before the program."
        bs_say "  bpftool printed:"
        printf '%s\n' "$raw" | cut -c1-200 | head -4 | sed 's/^/    /'
    fi
}

# Read an interface's packet counters. Both directions, because one of them is
# the tell described below.
#
#   bs_dev_counters <iface>   ->  "<rx_packets> <tx_packets>"
bs_dev_counters() {
    sed -n "s/^[[:space:]]*$1:[[:space:]]*/ /p" /proc/net/dev |
        awk '{print $2, $10}'
}

# Run a traffic generator and refuse to let the caller believe a counter that
# never moved.
#
#   bs_traffic_gate <iface> <command...>
#
# Returns 0 only if the command succeeded AND the interface's packet counters
# actually changed. Prints what it saw either way.
#
# This exists because of 2026-09-15. Three consecutive XDP runs reported zero
# packets through the attached program. I read that first as "the kernel hook
# is not running" and then as "the traffic is leaving by another interface",
# and went looking at routing tables. Both were wrong. The cause was the
# generator: busybox ping accepts -i SECS but will not parse a fractional
# value, so `ping -c 20 -i 0.2` printed usage and sent nothing - and its output
# was redirected to /dev/null, which made the failure invisible.
#
# The tell was in the counters twice over and I walked past it both times:
# TRANSMIT was unchanged as well as receive. An interface that is not receiving
# is a receive problem. An interface that is not transmitting either, while
# ping reports replies, is a generator that never ran.
#
# Two rules follow, and they are enforced here rather than left to whoever
# writes the next harness: never discard a generator's output and status, and
# never read a derived counter that has not been shown to move.
bs_traffic_gate() {
    _tg_if=$1
    shift

    set -- "$@"
    _tg_before=$(bs_dev_counters "$_tg_if")
    _tg_rx0=${_tg_before% *}
    _tg_tx0=${_tg_before#* }

    _tg_out=$("$@" 2>&1)
    _tg_rc=$?

    _tg_after=$(bs_dev_counters "$_tg_if")
    _tg_rx1=${_tg_after% *}
    _tg_tx1=${_tg_after#* }

    if [ "$_tg_rc" -ne 0 ]; then
        bs_bad "traffic generator failed (exit $_tg_rc) - nothing was measured"
        printf '%s\n' "$_tg_out" | sed -n '1,3p' | sed 's/^/          /'
        return 1
    fi

    if [ "$_tg_rx1" = "$_tg_rx0" ] && [ "$_tg_tx1" = "$_tg_tx0" ]; then
        bs_bad "$_tg_if moved no packets in either direction - nothing was measured"
        bs_say "  rx $_tg_rx0 tx $_tg_tx0, unchanged. The generator exited 0 but"
        bs_say "  sent nothing, or the traffic did not use this interface."
        return 1
    fi

    bs_say "  $_tg_if rx $_tg_rx0 -> $_tg_rx1, tx $_tg_tx0 -> $_tg_tx1"
    return 0
}


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
  bs_note_direct_scope
else
  kv "flowtable" "ABSENT - software flow offloading is off"
fi
[ "$(bs_hfo)" = "1" ] && {
  say "  NOTE: hardware offload is ON - bpf_xdp_flow_lookup() misses on every"
  say "        packet, and XMIT_DIRECT becomes reachable. The two are exclusive."
}

hdr "packet steering, RPS and RFS"
bs_have uci && kv "network.globals.packet_steering" "$(bs_steering)"
for i in $(bs_ifaces); do
  m=$(bs_rps "$i");  [ -n "$m" ] && kv "rps_cpus $i" "$m"
  f=$(bs_rfs "$i");  [ -n "$f" ] && kv "rps_flow_cnt $i" "$f"
  x=$(bs_xps "$i");  [ -n "$x" ] && kv "xps_cpus $i" "$x"
done
kv "rps_sock_flow_entries" "$(bs_rfs_global)"
kv "netdev_max_backlog" "$(bs_backlog)"
say "  rps_cpus says which CPUs a queue may steer to; rps_flow_cnt and"
say "  rps_sock_flow_entries say whether flows are additionally pinned to the"
say "  CPU their socket last ran on. Both zero with rps_cpus set means RPS"
say "  without RFS, which is the usual default here."

hdr "TCP"
kv "congestion control" "$(bs_tcp_cc)"
kv "available" "$(bs_tcp_cc_avail)"
kv "ecn" "$(bs_tcp_ecn)"
kv "sack" "$(bs_tcp_sack)"
say "  cubic and bbr fill a bottleneck queue differently, so every throughput"
say "  and bufferbloat number in this tree is only comparable to another taken"
say "  under the same one. ecn: 0 off, 1 request and accept, 2 accept only."

hdr "NAPI, GRO and offloads"
for i in $(bs_ifaces); do
  [ "$i" = lo ] && continue
  printf '  %-14s gro=%-5s lro=%-5s threaded=%-3s gro_max=%-6s udp_fwd=%-4s fraglist=%s\n' \
    "$i" "$(bs_gro "$i")" "$(bs_lro "$i")" "$(bs_threaded "$i")" "$(bs_gro_max "$i")" \
    "$(bs_gro_udp_fwd "$i")" "$(bs_gro_fraglist "$i")"
done
say "  gro is set by the core on every netdev and says nothing on its own; the"
say "  effective state is gro minus any generic-mode XDP program, which is what"
say "  bs_gro_effective reads. udp_fwd and fraglist are the opposite: the core"
say "  leaves both OFF, so \"on\" there was set deliberately and belongs in any"
say "  window it was set for. udp_fwd only affects UDP this box FORWARDS."
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
# Running and enabled are different facts and only one of them survives a
# reboot. This tree's 93-irqbalance uci-default flips enabled to 1, so the init
# starts it at every boot - which is why a clean-boot snapshot finds it live.
_irqb_run=no; pgrep irqbalance >/dev/null 2>&1 && _irqb_run=yes
_irqb_cfg=$(uci -q get irqbalance.irqbalance.enabled 2>/dev/null || echo unset)
if [ "$_irqb_run" = yes ]; then
  kv "irqbalance" "running (uci enabled=$_irqb_cfg) - it may move those masks mid-window"
else
  kv "irqbalance" "not running (uci enabled=$_irqb_cfg)"
fi
[ "$_irqb_run" = no ] && [ "$_irqb_cfg" = "1" ] && \
  say "  enabled but not running: it will be back after a reboot."
grep -q threadirqs /proc/cmdline 2>/dev/null \
  && kv "threadirqs" "set on the cmdline" || kv "threadirqs" "not set"

hdr "queue discipline, every interface"
for i in $(bs_ifaces); do
  [ "$i" = lo ] && continue
  q=$(bs_qdisc "$i" | head -1)
  [ -n "$q" ] && printf '  %-14s %s\n' "$i" "$q"
done
say "  The egress qdisc shapes what leaves each interface. fq_codel without a"
say "  rate limit does not shape; cake, htb or tbf with one does. A download's"
say "  bufferbloat is on the INGRESS side of the WAN, which no egress qdisc on"
say "  wwan0 can touch - that needs an ifb and a shaper on it."

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
