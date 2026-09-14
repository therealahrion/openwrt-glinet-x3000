#!/bin/sh
# The configuration every measurement on this box has to be read against.
#
# A result without its state is not comparable to anything: GRO on or off, SFO
# or HFO, steering on or off, the shaper present or absent, and - on this WAN
# above all - which address family the traffic actually used. Run this with any
# measurement window and keep the output beside the numbers.
#
#   sh boxstate.sh            instant snapshot
#   sh boxstate.sh mix [secs] and a timed IPv4/IPv6 split, default 30s
#
# Read-only throughout. Space-indented on purpose: a literal tab pasted into an
# interactive shell triggers readline completion and prints every command in
# PATH.
#
# Interfaces are enumerated, never listed. An earlier revision hardcoded six
# names and would not have shown a CLAT or nat46 device at all - which is
# exactly the thing that turned out to matter most here.

WAN=${WAN:-wwan0}
MIX_SECS=${2:-30}
say() { printf '%s\n' "$*"; }
kv()  { printf '  %-26s %s\n' "$1" "$2"; }
hdr() { say ""; say "== $*"; }
have() { command -v "$1" >/dev/null 2>&1; }
ifaces() { for d in /sys/class/net/*; do echo "${d##*/}"; done; }

say "box state - $(date '+%Y-%m-%d %H:%M:%S')"
kv "kernel" "$(uname -r)"
kv "cpus" "$(grep -c ^processor /proc/cpuinfo)"
[ -r /etc/openwrt_release ] && kv "release" \
  "$(sed -n "s/^DISTRIB_DESCRIPTION='\(.*\)'/\1/p" /etc/openwrt_release)"

hdr "interfaces"
for i in $(ifaces); do
  d=/sys/class/net/$i
  t=$(cat "$d/type" 2>/dev/null)
  case "$t" in
    1) tn=ETHER ;; 519) tn=RAWIP ;; 65534) tn=NONE ;; 772) tn=LOOPBACK ;;
    776) tn=SIT ;; 769) tn=IP6GRE ;; *) tn=$t ;;
  esac
  printf '  %-14s type=%-9s oper=%-8s mtu=%s\n' \
    "$i" "$tn" "$(cat "$d/operstate" 2>/dev/null)" "$(cat "$d/mtu" 2>/dev/null)"
done

# 464XLAT changes what an address-family-specific program can ever see, so it
# is the first thing to establish, not a footnote.
hdr "464XLAT / NAT64"
found=0
for i in $(ifaces); do
  case "$i" in *clat*|*nat46*|*464*|*xlat*) say "  device: $i"; found=1 ;; esac
done
lsmod 2>/dev/null | grep -iE '^(nat46|siit|clat)' | sed 's/^/  module: /' && found=1
pgrep -l -f clatd 2>/dev/null | sed 's/^/  process: /' && found=1
have uci && uci show network 2>/dev/null | grep -iE '464|clat|nat46' | sed 's/^/  uci: /'
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

hdr "flow offloading"
if have uci; then
  kv "uci flow_offloading" "$(uci -q get firewall.@defaults[0].flow_offloading || echo unset)"
  kv "uci flow_offloading_hw" "$(uci -q get firewall.@defaults[0].flow_offloading_hw || echo unset)"
fi
if have nft; then
  FT=$(nft list flowtables 2>/dev/null)
  if [ -n "$FT" ]; then
    kv "flowtable" "present"
    printf '%s\n' "$FT" | sed -n 's/.*devices = {\(.*\)}.*/\1/p' | tr -d ' "' \
      | sed 's/^/    devices: /'
    # The list has two jobs: hook registration, and answering which device a
    # packet physically leaves on (nft_flow_offload.c:202). A bridge master can
    # only satisfy the first, so a missing bridge port means XMIT_DIRECT is
    # discarded for every client behind it.
    if [ -d /sys/class/net/br-lan/brif ]; then
      D=$(printf '%s\n' "$FT" | sed -n 's/.*devices = {\(.*\)}.*/\1/p' | tr -d ' "')
      miss=""
      for p in $(ls /sys/class/net/br-lan/brif 2>/dev/null); do
        case ",$D," in *",$p,"*) ;; *) miss="$miss $p" ;; esac
      done
      [ -n "$miss" ] && say "    bridge ports MISSING from the list:$miss" \
                     || say "    every br-lan port is in the list"
    fi
  else
    kv "flowtable" "ABSENT - software flow offloading is off"
  fi
fi
[ "$(uci -q get firewall.@defaults[0].flow_offloading_hw 2>/dev/null)" = "1" ] && {
  say "  NOTE: hardware offload is ON - bpf_xdp_flow_lookup() misses on every"
  say "        packet, and XMIT_DIRECT becomes reachable. The two are exclusive."
}

hdr "packet steering and RPS"
have uci && kv "network.globals.packet_steering" \
  "$(uci -q get network.globals.packet_steering || echo unset)"
for i in $(ifaces); do
  m=""
  for q in /sys/class/net/$i/queues/rx-*/rps_cpus; do
    [ -r "$q" ] && m="$m $(cat "$q")"
  done
  [ -n "$m" ] && kv "rps_cpus $i" "$m"
done
kv "netdev_max_backlog" "$(cat /proc/sys/net/core/netdev_max_backlog 2>/dev/null)"

hdr "NAPI, GRO and offloads"
for i in $(ifaces); do
  [ "$i" = lo ] && continue
  gro="-"; lro="-"
  if have ethtool; then
    gro=$(ethtool -k "$i" 2>/dev/null | awk '/^generic-receive-offload:/{print $2}')
    lro=$(ethtool -k "$i" 2>/dev/null | awk '/^large-receive-offload:/{print $2}')
  fi
  printf '  %-14s gro=%-5s lro=%-5s threaded=%-3s gro_max_size=%s\n' \
    "$i" "${gro:--}" "${lro:--}" \
    "$(cat /sys/class/net/$i/threaded 2>/dev/null || echo -)" \
    "$(ip -d link show "$i" 2>/dev/null | tr ' ' '\n' | grep -A1 '^gro_max_size$' | tail -1)"
done

hdr "XDP attachments"
have bpftool && bpftool net show 2>/dev/null | sed 's/^/  /' || say "  bpftool absent"

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
if have tc; then
  tc qdisc show dev "$WAN" 2>/dev/null | sed 's/^/  /'
  tc qdisc show dev "$WAN" ingress 2>/dev/null | sed 's/^/  ingress: /'
  tc qdisc show dev "$WAN" 2>/dev/null | grep -qE 'cake|htb|tbf' \
    || say "  no shaper: fq_codel without a rate limit does not shape, and a"
  tc qdisc show dev "$WAN" 2>/dev/null | grep -qE 'cake|htb|tbf' \
    || say "  download's bufferbloat is downstream, which needs ingress shaping."
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
  a4=$(in4); a6=$(in6); p0=$(cat "/sys/class/net/$WAN/statistics/rx_packets")
  sleep "$MIX_SECS"
  b4=$(in4); b6=$(in6); p1=$(cat "/sys/class/net/$WAN/statistics/rx_packets")
  d4=$((b4-a4)); d6=$((b6-a6)); dp=$((p1-p0))
  kv "$WAN rx_packets" "$dp"
  kv "IPv4 InReceives" "$d4"
  kv "IPv6 InReceives" "$d6"
  [ $((d4+d6)) -gt 0 ] && awk -v a="$d4" -v b="$d6" \
    'BEGIN{printf "  %-26s %.1f%%\n", "IPv4 share", a*100/(a+b)}'
  say "  This is the ceiling on what any IPv4-only program can ever see here."
fi
say ""
