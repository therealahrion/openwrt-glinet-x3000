#!/bin/sh
# Put the bridge ports into the flowtable, and measure what it buys.
#
# fw4 builds the flowtable device list from each zone's related_physdevs, which
# is fed only from a network's physdev (root/usr/share/ucode/fw4.uc, the single
# push site). A bridge PORT is not a network, so eth1, phy0-ap0 and phy1-ap0
# never enter the list however the zone is configured - and
# nft_dev_forward_path() discards the whole forward-path walk unless the device
# it landed on is in that list (nft_flow_offload.c, the
# `if (!info.indev || !nft_flowtable_find_dev(info.indev, ft)) return;` line).
# So every flow on the box read FLOW_OFFLOAD_XMIT_NEIGH, and the W0038 fast
# path had nothing it could redirect.
#
# This puts them in and measures the result. On 2026-09-14 it moved a wired
# client from 0 to 100% XMIT_DIRECT on every flowtable hit.
#
#   sh flowtable-ports.sh              report - what is in the list and what it means
#   sh flowtable-ports.sh add          put the ports in (dry run unless APPLY=1)
#   sh flowtable-ports.sh window [s]   30s of offloaded flows, attributed by port
#   sh flowtable-ports.sh off          fw4 restart - puts everything back
#
# NOTHING IS WRITTEN TO DISK. The change lives in the running ruleset only, so
# `fw4 restart` and a reboot both undo it. Making it survive means a firewall4
# patch - W0039 - not this script.
#
# Space-indented on purpose: a literal tab pasted into an interactive shell
# triggers readline completion and prints every command in PATH.

set -u

BOXSTATE_URL=${BOXSTATE_URL:-https://raw.githubusercontent.com/therealahrion/openwrt-glinet-x3000/openwrt-25.12/x3000/docs/boxstate.sh}
case "$0" in */*) _here=${0%/*} ;; *) _here=. ;; esac
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
[ -s "$BOXSTATE" ] || { echo "FATAL: boxstate.sh not found and could not be fetched." >&2; exit 1; }
BOXSTATE_LIB=1 . "$BOXSTATE"
BOXSTATE_NEED=3
if [ "${BOXSTATE_API:-0}" != "$BOXSTATE_NEED" ]; then
  echo "FATAL: boxstate.sh is API ${BOXSTATE_API:-none}, this needs $BOXSTATE_NEED." >&2
  echo "       rm -f /tmp/boxstate.sh and re-run so both come from one revision." >&2
  exit 1
fi

say() { bs_say "$@"; }
h()   { echo; echo "=== $* ==="; }

O=/tmp/fwrs.orig
N=/tmp/fwrs.new

# diff is not on this box. Busybox ships without it unless diffutils is
# installed, and a guard that depends on a missing tool fails closed but for
# the wrong reason - it reported "the edit touched more than one line" when it
# had touched exactly one. awk is always there.
linediff() {
  awk 'NR==FNR { a[FNR]=$0; n=FNR; next }
       { if (FNR<=n && $0!=a[FNR]) { printf "line %d:\n  - %s\n  + %s\n", FNR, a[FNR], $0; c++ } }
       END { if (FNR!=n) printf "LINECOUNT %d -> %d\n", n, FNR; printf "changed=%d\n", c+0 }' \
      "$1" "$2"
}

ports() {
  [ -d /sys/class/net/br-lan/brif ] || return 0
  ls /sys/class/net/br-lan/brif 2>/dev/null
  return 0
}

cmd_report() {
  h "the flowtable as it stands"
  nft list ruleset 2>/dev/null | sed -n '/flowtable ft/,/}/p'
  say
  bs_note_bridge_ports
  bs_note_direct_scope
  h "offload switches"
  say "flow_offloading    : $(bs_sfo)"
  say "flow_offloading_hw : $(bs_hfo)   (0 is required - it empties the XDP hashtable)"
}

cmd_add() {
  h "gates"
  case "$(bs_hfo)" in
    0) say "hw offload : off - ok" ;;
    unreadable) bs_bad "cannot read flow_offloading_hw"; return 1 ;;
    *) bs_bad "hardware offload is ON - every kfunc lookup would miss"; return 1 ;;
  esac
  [ "$(bs_sfo)" = "1" ] || { bs_bad "software flow offload is off - no flowtable to fix"; return 1; }

  h "generate the ruleset"
  # fw4's own output opens by flushing the table, which is why this works where
  # a bare `nft delete flowtable` is refused with EBUSY: the forward chain's
  # `flow add @ft` rule holds a reference, and flushing the table in the same
  # transaction drops the rule first.
  fw4 print > "$O" 2>/tmp/fwrs.err || { bs_bad "fw4 print failed:"; cat /tmp/fwrs.err; return 1; }
  n=$(wc -l < "$O")
  say "wrote $O, $n lines"
  [ "$n" -ge 50 ] || { bs_bad "too short to be the real ruleset"; return 1; }
  grep -q '^flush table inet fw4' "$O" || { bs_bad "no flush - loading this would append a second copy of every rule"; return 1; }

  h "the flowtable block"
  sed -n '/flowtable ft {/,/^[[:space:]]*}/p' "$O"
  # `devices = {` also matches the `define lan_devices` / `define wan_devices`
  # variables fw4 emits for rule matching. Editing one of those would change
  # which packets the rules apply to, and would be silent. Confine the
  # substitution to the flowtable block by range address, and require exactly
  # one match inside it.
  c=$(sed -n '/flowtable ft {/,/^[[:space:]]*}/p' "$O" | grep -c 'devices *= *{')
  [ "$c" = "1" ] || { bs_bad "expected exactly one devices line inside the flowtable, found $c"; return 1; }

  add=""
  for p in $(ports); do
    bs_ft_has "$p" && { say "skip $p : already in the list"; continue; }
    add="$add, \"$p\""
  done
  [ -n "$add" ] || { bs_ok "every port is already in the list - nothing to do"; return 0; }

  h "build the modified ruleset"
  sed '/flowtable ft {/,/^[[:space:]]*}/ s/\(devices *= *{[^}]*\)}/\1'"$add"' }/' "$O" > "$N"
  rep=$(linediff "$O" "$N"); echo "$rep"
  d=$(echo "$rep" | sed -n 's/^changed=//p')
  [ "$d" = "1" ] || { bs_bad "expected exactly one changed line, got ${d:-none}"; return 1; }
  say
  say "-- the defines must be untouched --"
  grep -n 'define .*_devices' "$N"

  if [ "${APPLY:-0}" != "1" ]; then
    h "dry run - nothing applied"
    say "Run it for real with:  APPLY=1 sh $0 add"
    return 0
  fi

  h "applying as one transaction"
  # nft applies a -f file atomically, so a failure anywhere rolls the whole
  # ruleset back and leaves the running firewall untouched.
  nft -f "$N" 2>/tmp/fwrs.err || { bs_bad "refused - rolled back, firewall untouched:"; cat /tmp/fwrs.err; return 1; }
  bs_ok "applied"

  h "the firewall must still be whole"
  nft list ruleset | sed -n '/flowtable ft/,/}/p'
  # grep -c exits 1 when it finds nothing even after printing 0, so a
  # `|| echo 0` fallback prints the count twice. Capture instead.
  fa=$(nft list ruleset | grep -c 'flow add' 2>/dev/null); say "flow add rules : ${fa:-0}"
  ch=$(nft list ruleset | grep -c '^[[:space:]]*chain ' 2>/dev/null); say "chains         : ${ch:-0}"
  [ "${fa:-0}" -ge 1 ] || bs_bad "the flow add rule is gone - run 'fw4 restart' now"

  h "next"
  say "The flowtable was created with the ports in it, so no flow can predate"
  say "the change and no live 'nft add' was involved. Measure it:"
  say "  sh $0 window 30      # who is offloaded, and on which port"
  say "  sh xdp-ft-wwan.sh dryrun 30   # from a WIRED client - see 23.17"
  say "Undo with:  sh $0 off"
}

cmd_window() {
  secs=${1:-30}
  h "sampling offloaded flows for ${secs}s"
  T=/tmp/ftports-samp.txt
  : > "$T"
  i=0
  while [ "$i" -lt "$secs" ]; do
    bs_ct_offload >> "$T"
    i=$((i+3)); sleep 3
  done

  h "every offloaded flow, attributed to a bridge port"
  sort -u "$T" | while read -r fam src; do
    p=$(bs_port_of "$src")
    say "  $fam  $src  -> ${p:-unknown}"
  done
  say
  say "-- samples by family --"
  awk '{print $1}' "$T" | sort | uniq -c
  say
  say "A client on a wired port can be XMIT_DIRECT; one on a Wi-Fi port cannot."
  say "That is the scope of the fast path, and 23.17 has the mechanism."
}

case "${1:-report}" in
  report) cmd_report ;;
  add)    cmd_add ;;
  window) shift; cmd_window "${1:-30}" ;;
  off)    h "restoring"; fw4 restart && bs_ok "fw4 restarted - the list is back to its generated state" ;;
  *)      echo "usage: $0 [report|add|window [secs]|off]" >&2; exit 1 ;;
esac
