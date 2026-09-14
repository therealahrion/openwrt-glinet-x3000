#!/bin/sh
# 802.3 encap offload on the Wi-Fi vifs: the lever, and what it costs.
#
# WHY THIS EXISTS
#
# A Wi-Fi client never reaches FLOW_OFFLOAD_XMIT_DIRECT, so the W0038 fast path
# can redirect nothing for it, while a wired client on eth1 reaches it on 100%
# of flowtable hits. 23.18 traced that to a chain ending in the kernel core:
#
#   dev_fill_forward_path() (net/core/dev.c) walks while a device has an
#   ndo_fill_forward_path and RETURNS -1 as soon as one of them errors. Only a
#   device with no callback at all falls through to DEV_PATH_ETHERNET, which is
#   the single case in nft_dev_path_info() that sets info->indev - and
#   info->indev is what nft_flowtable_find_dev() needs.
#
#   eth1 is a plain netdev with no callback, so it takes that branch.
#
#   A Wi-Fi vif running the 802.3 data path HAS one: mac80211 attaches
#   .ndo_fill_forward_path to ieee80211_dataif_8023_ops and to no other ops
#   struct. It delegates to the driver, and mt76 returns -ENODEV unless WED is
#   active (mt7915/main.c:1776). WED is off here, so the walk dies.
#
# Which ops struct a vif uses is decided by ieee80211_set_vif_encap_ops(), and
# ieee80211_set_sdata_offload_flags() clears IEEE80211_OFFLOAD_ENCAP_ENABLED
# when local->virt_monitors is non-zero. mt7915 sets neither MONITOR_FLAG_ACTIVE
# nor NO_VIRTUAL_MONITOR, so a plain monitor interface increments that counter
# and ieee80211_do_open() calls ieee80211_recalc_offload() on the next line.
#
# So bringing up a monitor REMOVES the callback from the AP netdev, the walk
# falls through to DEV_PATH_ETHERNET, and Wi-Fi clients become redirectable.
# Measured 2026-09-14: 0 of 348233 hits before, 153085 of 153085 after.
#
# THIS IS A DIAGNOSTIC LEVER, NOT A FIX. The fix is W0040, a three-line change
# to dev_fill_forward_path() so that -EOPNOTSUPP means "no special path" rather
# than "walk impossible" - which is what a missing callback already means.
#
#   sh wifi-encap.sh status            what state the vifs are in
#   sh wifi-encap.sh disable           monitors up  -> encap off -> DIRECT works
#   sh wifi-encap.sh enable            monitors gone -> encap on -> back to stock
#   sh wifi-encap.sh ab [secs] [cyc]   what disabling it costs, measured
#
# Nothing here is written to disk. A reboot restores the stock state.
#
# Space-indented on purpose: a literal tab pasted into an interactive shell
# triggers readline completion and prints every command in PATH.

BOXSTATE_URL=${BOXSTATE_URL:-https://raw.githubusercontent.com/therealahrion/openwrt-glinet-x3000/openwrt-25.12/x3000/docs/boxstate.sh}
case "$0" in */*) _here=${0%/*} ;; *) _here=. ;; esac
BOXSTATE=${BOXSTATE:-$_here/boxstate.sh}
if [ ! -r "$BOXSTATE" ]; then
  BOXSTATE=/tmp/boxstate.sh
  if [ ! -s "$BOXSTATE" ]; then
    command -v curl >/dev/null 2>&1 && curl -fsSL -o "$BOXSTATE" "$BOXSTATE_URL" 2>/dev/null
    [ -s "$BOXSTATE" ] || { command -v wget >/dev/null 2>&1 && wget -q -O "$BOXSTATE" "$BOXSTATE_URL"; }
  fi
fi
[ -s "$BOXSTATE" ] || { echo "FATAL: boxstate.sh not found and could not be fetched." >&2; exit 1; }
BOXSTATE_LIB=1 . "$BOXSTATE"
BOXSTATE_NEED=3
if [ "${BOXSTATE_API:-0}" != "$BOXSTATE_NEED" ]; then
  echo "FATAL: boxstate.sh is API ${BOXSTATE_API:-none}, this needs $BOXSTATE_NEED." >&2
  exit 1
fi

say() { bs_say "$@"; }
h()   { echo; echo "=== $* ==="; }

phys() { ls /sys/class/ieee80211 2>/dev/null; }
aps()  { for n in $(ls /sys/class/net); do
           [ -e "/sys/class/net/$n/phy80211" ] || continue
           [ "$(iw dev "$n" info 2>/dev/null | awk '/type/{print $2}')" = "AP" ] && echo "$n"
         done; }
monitors() { c=0; for n in $(ls /sys/class/net); do case "$n" in mon[0-9]*) c=$((c+1)) ;; esac; done; echo $c; }

do_disable() {
  i=0
  for p in $(phys); do
    iw phy "$p" interface add "mon$i" type monitor 2>/dev/null && ip link set "mon$i" up 2>/dev/null
    i=$((i+1))
  done
}
do_enable() {
  for n in $(ls /sys/class/net); do
    case "$n" in mon[0-9]*) ip link set "$n" down 2>/dev/null; iw dev "$n" del 2>/dev/null ;; esac
  done
}

# Station counters summed across every AP, plus each netdev's own tx_bytes as an
# independent read of the same traffic.
#
# %.0f, never %d: busybox awk saturates %d at INT_MAX, and a Wi-Fi byte counter
# passes 2^31 in seconds. That bug reported every throughput as 0 once.
snap() {
  tb=0; tp=0; tr=0; tf=0; nb=0
  for a in $(aps); do
    n=$(cat "/sys/class/net/$a/statistics/tx_bytes" 2>/dev/null || echo 0)
    nb=$((nb + n))
    eval "$(iw dev "$a" station dump 2>/dev/null | awk '
      /tx bytes:/   {b+=$3}
      /tx packets:/ {p+=$3}
      /tx retries:/ {r+=$3}
      /tx failed:/  {f+=$3}
      END {printf "sb=%.0f; sp=%.0f; sr=%.0f; sf=%.0f\n", b+0, p+0, r+0, f+0}')"
    tb=$((tb + sb)); tp=$((tp + sp)); tr=$((tr + sr)); tf=$((tf + sf))
  done
  echo "$tb $tp $tr $tf $nb $(bs_squeeze)"
}

interval() {
  lbl="$1"          # captured BEFORE `set --` overwrites the positional params,
                    # which once printed a byte counter where the label belonged
  s1=$(snap); t1=$(date +%s)
  sleep "$SECS"
  s2=$(snap); t2=$(date +%s)
  set -- $s1; ab=$1; ap=$2; ar=$3; af=$4; an=$5; aq=$6
  set -- $s2; bb=$1; bp=$2; br=$3; bf=$4; bn=$5; bq=$6
  d=$((t2-t1)); [ "$d" -gt 0 ] || d=1
  dsp=$((bp-ap)); dsr=$((br-ar)); dsf=$((bf-af))
  mst=$(( (bb-ab) / d * 8 / 1000000 ))
  mnd=$(( (bn-an) / d * 8 / 1000000 ))
  if [ "$dsp" -gt 0 ]; then rr=$(( dsr * 1000 / dsp )); else rr=-1; fi
  printf '%-9s sta %5d Mbit/s | netdev %5d Mbit/s | frames %9d | retries/1k %5d | failed %6d | squeeze %3d\n' \
         "$lbl" "$mst" "$mnd" "$dsp" "$rr" "$dsf" "$((bq-aq))"
}

cmd_status() {
  h "AP interfaces and stations"
  for a in $(aps); do
    c=$(iw dev "$a" station dump 2>/dev/null | grep -c '^Station')
    say "  $a: $c station(s)"
    iw dev "$a" station dump 2>/dev/null | awk -v i="  $a" '/tx bitrate:/{print i" "$0}'
  done
  h "encap offload"
  m=$(monitors)
  say "monitor interfaces: $m"
  if [ "$m" = "0" ]; then
    say "  -> ENABLED. The AP netdevs use ieee80211_dataif_8023_ops and carry"
    say "     .ndo_fill_forward_path, so the forward-path walk fails there and"
    say "     no Wi-Fi client can be XMIT_DIRECT."
  else
    say "  -> DISABLED. The AP netdevs are on ieee80211_dataif_ops with no"
    say "     callback, so the walk falls through to DEV_PATH_ETHERNET and a"
    say "     Wi-Fi client CAN be XMIT_DIRECT - provided its port is in the"
    say "     flowtable device list."
  fi
  h "flowtable"
  nft list ruleset 2>/dev/null | sed -n '/flowtable ft/,/}/p'
  bs_note_direct_scope
}

cmd_ab() {
  SECS=${1:-20}; CYCLES=${2:-4}
  h "preconditions"
  A=$(aps); [ -n "$A" ] || { bs_bad "no AP interface"; return 1; }
  n=0
  for a in $A; do
    c=$(iw dev "$a" station dump 2>/dev/null | grep -c '^Station')
    [ "$c" -gt 0 ] && say "  $a: $c station(s)  <- the client is here" || say "  $a: 0 stations"
    n=$((n+c))
  done
  [ "$n" -gt 0 ] || { bs_bad "no associated station"; return 1; }

  h "is traffic actually flowing"
  # An earlier revision produced eight rows of zeros and read like a result. It
  # was not one - nothing was transferring. Five seconds settles that before
  # three minutes are spent on it.
  p1=$(snap); sleep 5; p2=$(snap)
  set -- $p1; q1=$5
  set -- $p2; q2=$5
  mb=$(( (q2-q1) * 8 / 5 / 1000000 ))
  say "AP tx over 5s : ${mb} Mbit/s"
  if [ "$mb" -lt 20 ]; then
    bs_bad "not a saturating transfer - nothing to measure"
    say "  The traffic must be LAN-side, wired host to Wi-Fi client. A download"
    say "  over the WAN is capped far below this radio, so every condition would"
    say "  read the same. See wifiload.py."
    return 1
  fi

  h "A/B, alternating under one transfer"
  say "ON  = hardware 802.11 header path, no XMIT_DIRECT for Wi-Fi"
  say "OFF = software header path,        XMIT_DIRECT reachable"
  say
  c=1
  while [ "$c" -le "$CYCLES" ]; do
    do_enable;  sleep 3; interval "ON  #$c"
    do_disable; sleep 3; interval "OFF #$c"
    c=$((c+1))
  done
  h "restoring"
  do_enable
  say "monitor interfaces: $(monitors)"
  h "reading it"
  say "Compare ON against OFF WITHIN a cycle, never across the run - a client's"
  say "rate adaptation drifts on its own, and alternating is what makes that"
  say "drift visible as cycle-to-cycle spread instead of hiding it in a mean."
  say "If the ON/OFF gap is smaller than that spread, the cost is below what"
  say "this rig resolves, which is a result rather than a failure."
  say
  say "Check the wired source is not the ceiling: 'ethtool eth1 | grep -i speed'."
  say "A gigabit source caps the test near 989 Mbit/s whatever the radio can do."
}

case "${1:-status}" in
  status)  cmd_status ;;
  disable) do_disable; say "monitor interfaces: $(monitors)"; cmd_status ;;
  enable)  do_enable;  say "monitor interfaces: $(monitors)" ;;
  ab)      shift; cmd_ab "$@" ;;
  *) echo "usage: $0 [status|disable|enable|ab [secs] [cycles]]" >&2; exit 1 ;;
esac
