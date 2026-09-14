# BPF source for `xdp-ft-wwan.sh`

Same arrangement as `verify-992a-sources.md`, for the same reasons: the objects
live in `bpf/` as `.bpf` files so the repo's blanket `*.o` rule does not swallow
them, they ship as files rather than base64 because busybox here has no `base64`
applet, and each source sits next to its object so the object is auditable and
reproducible.

| file | what it is |
|---|---|
| `bpf/xdp_ft_probe.bpf` | the probe object, little-endian eBPF, DWARF stripped and `.BTF` kept |
| `bpf/xdp_ft_probe.bpf.c` | the probe source |
| `bpf/xdp_ft_wwan.bpf` | the fastpath object, same treatment |
| `bpf/xdp_ft_wwan.bpf.c` | the fastpath source |
| `xdp-ft-wwan.sh` | preflight, fetch, attach, sample, detach |

Two objects rather than one, and the reason has changed. It was that `bpftool
prog loadall` fails the whole object when any single program in it fails to
relocate, so while the fastpath could not relocate it took the probe down with
it. That is fixed. What is still true, and is now the reason, is that
`xdp_ft_probe.bpf` carries **no CO-RE relocations at all** where
`xdp_ft_wwan.bpf` carries sixty-two: the probe reads nothing out of `struct
flow_offload_tuple`, only tests the returned pointer for NULL. If a kernel bump
breaks the struct mirrors, the probe still answers whether the kfunc itself
works. It is the canary, and canaries are kept in their own cage.

Kept as separate `.c` files rather than inlined here: the fastpath is roughly 700
lines, where the three objects in `verify-992a-sources.md` are a dozen each.

Both programs handle IPv4 and IPv6. The first revision was IPv4 only; on this
link that made every counter a flat line, for the reason set out under
[The scope was wrong for this link](#the-scope-was-wrong-for-this-link-and-the-fix-was-the-easier-program)
below.

## Build

clang 18, any host — eBPF bytecode is architecture-neutral. Run from
`x3000/docs/`:

```sh
for o in xdp_ft_probe xdp_ft_wwan; do
	clang -O2 -g -Wall -Wextra -target bpf -mcpu=v3 \
	      -fdebug-compilation-dir=. \
	      -idirafter /usr/include/$(uname -m)-linux-gnu \
	      -c bpf/$o.bpf.c -o bpf/$o.bpf
	llvm-strip -g bpf/$o.bpf
done
```

`llvm-strip -g`, never plain `strip`. It drops DWARF and keeps `.BTF`, and
`.BTF` is what CO-RE needs to relocate the kernel struct offsets at load time.
An object stripped the wrong way loads and then misreads every field, which
looks like a kernel bug rather than a build mistake.

`-fdebug-compilation-dir=.` is what makes the checksums below mean anything.
Without it clang records the absolute source path in `.BTF`, which survives
`llvm-strip -g`, so the same source built in two directories produces two
different files — identical bytecode, different sha256. With it the embedded
path is `./bpf/<name>.bpf.c` and the build reproduces byte for byte anywhere.

sha256 of the committed objects. `xdp-ft-wwan.sh` carries the same two values
and checks the object it is about to load against them, because the script
updates the moment the tree is pulled and a copy cached in `/tmp/xdp-ft-wwan`
does not — a window run that way reports the previous program's counters under
the current program's labels. Update both places together:

```
99851352f1cf32ae71987f5de58fcc99ee44bfff262e7fba67731cd98179419c  bpf/xdp_ft_probe.bpf
6fdce11f67ef6e6d42812e0e95ff535abf82d9426e59766b4d6be0250a14b3e2  bpf/xdp_ft_wwan.bpf
```

## What the three programs do

`xdp_ft_probe` parses the packet, calls `bpf_xdp_flow_lookup()`, counts the
result in a per-CPU array and returns `XDP_PASS`. It changes nothing, and it
answers the question section 16.5 of `xdp-methods-tested.md` raised and nothing
had tested: whether the kfunc actually hits on `wwan0`.

It declares the kfunc's return type opaque, exactly as the in-tree selftest
`tools/testing/selftests/bpf/progs/xdp_flowtable.c` does. Nothing is read out of
the returned tuplehash, only tested for NULL, so it carries no relocation against
`struct flow_offload` at all.

`xdp_ft_dryrun` runs the fastpath's whole decision path — lookup, direction,
container walk, flags, teardown, `xmit_type`, egress ifindex, and the NAT values
themselves — counts what it would have done, and returns `XDP_PASS` without
writing a byte. It exists because `would_redirect / seen` is the number that
decides whether the rewrite is worth attaching at all, and getting it should not
require risking a connection.

`xdp_ft_fastpath` adds the NAT rewrite, the TTL decrement, an Ethernet header via
`bpf_xdp_adjust_head()` and `XDP_REDIRECT` to a wired port.

The two share one `decide()` function rather than two copies of the same logic,
and the counters are bumped inside it, so the dry run and the real path cannot
drift into measuring different things.

**Every rejection has its own counter, and that is not cosmetic.** An earlier
revision pooled six parse failures into one `parse_skip` slot. A window then
returned 145880 of 146062 in that slot and it took a full cycle to work out the
traffic had been IPv6 — a family counter would have said so on sight. The parser
now returns the slot that rejected the packet and the caller bumps it, so twenty
slots account for every packet and any window that measured the wrong thing says
which wrong thing it measured.

Three of the twenty — `v4`, `v6` and `nat66` — are **observations rather than
exits**. They describe the window instead of accounting for it and do not sum
with the rest: a packet counted in `v6` is counted again in whichever exit it
took. `v4` and `v6` exist so that the family split, which on this link changes
hour to hour and decides whether a window means anything, is readable in the
same dump as the result rather than from a separate run of `boxstate.sh mix`.

**Reads are gathered before anything is written.** Every read through the flow is
a probe read of a computed address and can fail. `decide()` reads all of them,
including both translated addresses and ports, before `commit()` touches the
packet — a read that failed midway through a rewrite would put a half-translated
packet on the stack, which is worse than not accelerating the flow.

## The relocation that blocked the fastpath, and why it is gone

The fastpath was rejected at load for months of work with:

```
libbpf: relo #7: relocation decision ambiguity: success 90056 != success 90242
```

That message comes from `relo_core.c:1369`, where libbpf finds more than one
candidate type matching a relocation and the candidates disagree on the result.
`struct flow_offload` appears in more than one loaded BTF on this box, so there
are two candidates.

The split between what survives that and what does not is the useful part:

- **Field relocations resolve.** libbpf compares candidates on `bit_offset`
  first (`relo_core.c:1361`). The two definitions come from the same header, so
  every field sits at the same offset and every `FIELD_*` relocation agrees.
- **Type-id relocations cannot.** A BTF type ID is an index into one particular
  BTF, so two BTFs give two different IDs for the same struct by construction.
  There is nothing for libbpf to reconcile and it refuses to guess.

Dumping the object's `.BTF.ext` showed, at that revision, 28 CO-RE relocations,
of which exactly one was a type-id relocation, and it was relo #7:

```
relo #7   insn 300   TYPE_ID_TARGET   type_id 60   access '0'
```

That was `bpf_core_type_id_kernel(struct flow_offload___local)`, the second
argument to `bpf_rdonly_cast()`. The cast was there to make the hand-written
`container_of()` result trusted enough to dereference — but nothing in the
program dereferences it. Every read goes through `bpf_core_read()`, which is
`bpf_probe_read_kernel()` and takes an arbitrary kernel address, so the pointer
never needed to be trusted. `bpf_probe_read_kernel` is reachable from XDP under
`CAP_PERFMON` (`kernel/bpf/helpers.c`, `bpf_base_func_proto`), which root has.

Removing the cast removes the object's only `TYPE_ID_TARGET` relocation. The
remaining 27 were all `FIELD_*` and resolved unchanged. The current object, with
both families, carries 62 — 40 `FIELD_BYTE_OFFSET`, 20 more for the two bitfield
reads, and 2 `TYPE_SIZE` — and still not one type-id relocation. A rebuild that
produces one has reintroduced the bug.

The general rule worth keeping: **a program that reads kernel structs through
`bpf_core_read()` can be relocated against a type that appears in several BTFs;
a program that takes that type's BTF id cannot.** Where both are options, the
probe read is the portable one.

`bpf_core_type_size()` is safe where `bpf_core_type_id_kernel()` is not, and for
exactly the same reason the field relocations are: its value comes from the
layout, which every candidate agrees on, rather than from an index into one
particular BTF. The object now carries two `TYPE_SIZE` relocations and no
type-id relocation at all.

## The verifier rejection behind it, and why it is gone

With the relocation resolved the object reached the verifier and was rejected
there instead:

```
172: (57) r1 &= 255   ; R1 = scalar(smin=0, smax=umax=3)
173: (27) r1 *= -88   ; R1 = scalar(smax=0x7ffffffffffffff8, umax=0xfffffffffffffff8)
175: (0f) r3 += r1
math between ptr_ pointer and register with unbounded min value is not allowed
```

That is `container_of()` written as arithmetic: `th - dir * sizeof(tuplehash)`.
The verifier cannot carry a bound through a multiply by a negative constant, so
a register it knew to hold 0..3 came back with `smin` at `S64_MIN`, and
`check_reg_sane_offset()` refuses pointer math against an unbounded minimum.

Two things are worth noting about that trace. The `dir <= 1` test three
instructions earlier does not help: llvm applies it to a *copy* of the register,
and the masking in between breaks the link back to the original, so `r1` is
still 0..3 at the multiply. And the same function that rejects an unbounded
minimum **explicitly permits a known constant offset, negative included** — it
only rejects constants beyond `BPF_MAX_VAR_OFF`.

So the fix is to write it as a branch on `dir` with constant offsets, one arm
per direction, and no arithmetic on `dir` at all. The generated code is what it
should be:

```
294: r4 = 0x58        <- the TYPE_SIZE relocation, patched at load
295: if w4 == 0 goto  <- the guard
298: r1 -= r4         <- pointer minus a known constant
...
370: r2 = 0x58
374: r1 += r2
```

No multiply, two known-constant offsets, and the size is relocated rather than
taken from `sizeof()` on a local mirror that is only as right as the header it
was copied from.

## Things the source depends on, each read from v6.12.103

- `bpf_xdp_flow_lookup()` resolves its flowtable from `xdp->rxq->dev`. On
  `wwan0` that is the real netdev, because 992 runs the program through
  `do_xdp_generic()`, whose rxq comes from `netif_get_rxqueue(skb)`
  (`dev.c:5079`). On the wired ports it is `eth->dummy_dev` and every lookup
  misses — which is why this program is for `wwan0` and nowhere else.
- The packet has no Ethernet header. `wwan0` is `ARPHRD_RAWIP` (519) with
  `hard_header_len` 0, and 991 anchors `mac_header` at `skb->data`, so
  `mac_len` is 0 and the IP header is at `ctx->data`. The in-tree selftest this
  is modelled on parses `ethhdr` and would read the first two octets of the
  source address as an EtherType.
- NAT direction handling is copied case by case from `nf_flow_snat_ip()` and
  `nf_flow_dnat_ip()` in `net/netfilter/nf_flow_table_ip.c`.
- Only `FLOW_OFFLOAD_XMIT_DIRECT` flows are handled. `NEIGH` needs a neighbour
  lookup the program cannot do, and those get `XDP_PASS`.
- **Corrected:** the redirect target does *not* need `NETDEV_XDP_ACT_NDO_XMIT`
  here. That gate is `devmap.c:488`, on the native and devmap paths. This program
  runs in generic mode, where `bpf_redirect()` by ifindex goes through
  `xdp_do_generic_redirect()` (`filter.c:4554`), and the only test applied is
  `xdp_ok_fwd_dev()` — `IFF_UP` and the MTU. So an AP netdev is a legal target
  too, which an earlier version of this file wrongly ruled out.
- **`generic_xdp_tx()` bypasses the qdisc.** It calls `netdev_start_xmit()`
  directly rather than `dev_queue_xmit()`, so anything shaped on the target
  interface is skipped for redirected packets. This is a real behavioural change,
  not a detail.
- **The skb's metadata is left inconsistent by the head adjustment.** After
  `bpf_xdp_adjust_head(-14)`, `bpf_prog_run_generic_xdp()` pushes the 14 bytes
  back onto the skb and fixes `mac_header`, then calls
  `skb_reset_network_header()` — which points the network header at the new
  Ethernet header rather than the IP header. It then tests whether the program
  changed the Ethernet header by comparing the *original* `h_proto`, which on a
  raw-IP interface was read from offset 12 of the IP header, the first two octets
  of the source address. That will essentially never equal `0x0800`, so the
  branch always fires: `__skb_push(skb, ETH_HLEN)` then `eth_type_trans()`. Push
  fourteen, pull fourteen, so `skb->data` and `skb->len` come out right and the
  bytes on the wire are correct — but `skb->mac_header` ends up fourteen bytes
  before the header, in headroom, and `skb->protocol` is set from whatever is
  there. Not yet established whether the mtk transmit path cares.
- Keep the firewall on **software** flow offloading. Hardware offload sends
  `nf_flow_table_offload_setup()` down the other branch
  (`nf_flow_table_offload.c:1258`) and the device is never inserted into the XDP
  hashtable, so every lookup returns `-ENOENT`.
- `wwan0` reaches the flowtable at all only because of this tree's firewall4
  patch `001-flowtable-fall-back-to-l3-device`.

## State

**The probe runs, and the kfunc hits.** Measured on the box, one 30-second
sample with a download in flight:

| counter | value | share |
|---|---|---|
| `seen` | 26043 | equal to the `rx_packets` delta, exactly |
| `hit` | 25619 | 98.37% |
| `lookup_err` | 423 | 1.62% |
| `not_ipv4` (as the slot was then named) | 1 | |
| everything else | 0 | |

25619 + 423 + 1 = 26043, so every packet is accounted for. `seen` matching the
driver's own counter exactly means the program sits in front of the whole receive
path rather than a sample of it. This is the measurement section 16.5 asked for:
`bpf_xdp_flow_lookup()` works on a raw-IP modem interface.

**One correction to the probe's own counters.** The split between `miss` and
`lookup_err` is wrong. `bpf_xdp_flow_tuple_lookup()` returns `ERR_PTR(-ENOENT)`
when `flow_offload_lookup()` finds nothing (`nf_flow_table_bpf.c:48-49`), and the
caller then sets `opts->error` from it (`:95-96`), so an ordinary miss sets the
error too. `ST_MISS` is unreachable, and the 423 are flow misses, not kfunc
refusals. The other two error codes the kfunc can set — `-EINVAL` for a bad
`opts_len`, `-EAFNOSUPPORT` for a family that is neither v4 nor v6 — do not
depend on the packet, so 25619 hits rules both out; the program should record the
error value rather than leaving that as an inference.

**The fastpath loads.** `bpftool prog loadall` accepts the object on the box:
relocation and the verifier both pass, for the first time since the program was
written. It has still never been attached, so the rewrite has never executed.

**The four-BTF hypothesis is confirmed by measurement, not inferred from the
error.** `struct flow_offload` is defined in four loaded BTFs here —
`nf_flow_table`, `nf_flow_table_inet`, `nf_tables` and `nft_flow_offload`. So
libbpf was choosing among four candidate type ids; 90056 and 90242 were simply
the first pair it compared. `struct flow_offload_tuple_rhash` measures 88 bytes
in the kernel's own BTF, which is what the local mirror computes, so the old
`sizeof()` was right — it is now relocated rather than merely lucky.

**The dry run says the rewrite would never fire. Not rarely — never.** One
30-second sample, 236046 packets:

| counter | value | |
|---|---|---|
| `seen` | 236046 | equal to the `rx_packets` delta |
| `hit` | 233120 | 98.8% |
| `miss` | 2784 | |
| `parse_skip` | 142 | |
| `torn_down` | 27 | |
| `not_direct` | 233093 | **every hit that was not torn down** |
| `would_redirect` | **0** | |

142 + 2784 + 27 + 233093 = 236046, so every packet is accounted for. Every flow
on this box is `FLOW_OFFLOAD_XMIT_NEIGH`; not one is `XMIT_DIRECT`.

### The scope was wrong for this link, and the fix was the easier program

> **Correction, 2026-09-14.** "IPv4 is 0.8% of its traffic" was one window of
> one workload. Later windows on the same box measured 99.99% IPv4 and 99.7%
> IPv6 within the hour, with two independent instruments agreeing in a paired
> window. The 464XLAT topology below stands; the ratio does not. Both families
> were still the right build, for a better reason: **a single-family program
> measures nothing about the other half, and which half is live changes with
> the workload.** See `xdp-methods-tested.md` 23.13.

Measured 2026-09-14: **this WAN is 464XLAT, and in one speedtest window IPv4
was 0.8% of its traffic.**

`wwan0` carries `inet 192.0.0.2/27` with `default via 192.0.0.1` — the RFC 7335
service-continuity prefix — and there is no `nat46` module, `clatd` or separate
device, so the CLAT is inside the modem. Linux sees genuine IPv4 and the program
was on the right interface. There is simply almost none of it: the carrier
resolvers do DNS64, so every dual-stack client picks IPv6 for everything. Over a
30-second speedtest, 44 IPv4 `InReceives` against 5329 IPv6.

So the IPv4-only object, working perfectly, reached under one percent of the
link. Both programs now handle both families.

**Three things made the v6 arm cheaper than the v4 one, and one made it dearer
than I said it would be.**

Cheaper:

- The kfunc already speaks it. `bpf_xdp_flow_lookup()` has a `case AF_INET6:`
  arm filling `src_v6`/`dst_v6` from `fib_tuple->ipv6_src`/`ipv6_dst`
  (`nf_flow_table_bpf.c:84-88`), so the lookup needed no kernel change.
- No header checksum to repair. IPv6 has none, and `hop_limit` is not covered by
  the L4 pseudo-header either, so the decrement is bare — which is exactly what
  the kernel does at `nf_flow_table_ip.c:682`. The v4 arm has to fix `iph->check`
  after both the address change and the TTL decrement; the v6 arm fixes nothing.
- No extension-header walk. `nf_flow_tuple_ipv6()` switches on `nexthdr` and
  returns −1 on anything that is not TCP, UDP or GRE (`:593-608`), so a packet
  carrying a hop-by-hop or fragment header is not in the flowtable at all and
  walking past it could only produce a lookup that cannot hit. The program
  declines them for the same reason, and counts them apart from ICMPv6 so
  "not TCP or UDP" does not quietly hide "TCP behind an option header".

Dearer, and this is a **correction to what the previous revision of this file
asserted**. It said "native IPv6 has no NAT — the entire address-and-port rewrite
and all of its checksum arithmetic disappear." That is wrong. The flowtable
implements NAT66 for v6 exactly as it does for v4: `nf_flow_snat_ipv6()` at
`nf_flow_table_ip.c:516` and `nf_flow_dnat_ipv6()` at `:539`, both reaching the
same peer-tuple fields, with `inet_proto_csum_replace16()` repairing the L4
checksum across four 32-bit words. A program that ignored `NF_FLOW_SNAT` on a v6
flow would forward it untranslated. The rewrite is implemented, and a `nat66`
counter records whether it ever fires here — expected to stay at zero on a
routed prefix, but measured rather than assumed.

What survives of the original claim is the narrower and still useful version:
**the v6 rewrite is the simpler one, not the absent one.**

### A defect the v6 work turned up in the v4 rewrite

Reading `nf_flow_nat_ip_udp()` to model the v6 equivalent showed the v4 arm
missing a guard the kernel has:

```c
	if (udph->check || skb->ip_summed == CHECKSUM_PARTIAL) {
		inet_proto_csum_replace4(&udph->check, skb, addr, new_addr, true);
		if (!udph->check)
			udph->check = CSUM_MANGLED_0;
	}
```

A UDP checksum that lands on `0x0000` after a rewrite reads as *no checksum* on
the wire, so the kernel writes the numerically equivalent `0xffff` instead. This
file did not. That is a silent one-in-65536 corruption per rewritten datagram,
in a path no test would ever have reached, and it applies to both the address
and the port rewrite (`nf_flow_nat_port_udp()` does the same). Both arms now do
it, TCP excepted — `0x0000` is a legal TCP checksum and must be written as it
stands.

The guard is visible in the generated code:

```
2527: w3 = -0x1              <- 0xffff, the mangled-zero default
2528: if w4 == 0xffff goto   <- the folded sum whose complement is zero
2529: w3 = w2                <- otherwise the computed value
2530: if w8 == 0x11 goto     <- and only for IPPROTO_UDP
2533: *(u16 *)(r2 + 0x0) = r3
```

### Three windows that measured nothing, and what they cost

Worth recording, because each failure mode is a live trap for anyone repeating
this and none of them announced themselves:

| window | what it showed | why it was worthless |
|---|---|---|
| dry run after adding `eth1` | `parse_skip` 145880 of 146062 | the download resolved AAAA. That revision was IPv4-only, so every packet failed the version nibble before the flowtable was ever consulted |
| `curl -4` on the router | 66108 `lookup_err` of 66114 IPv4 packets | `curl` ran *on the box*, so the connections terminated locally. The flowtable only ever holds **forwarded** flows, so it correctly knew none of them |
| both of the above | `hit` 6 and 16 | with the flow table empty of the traffic, `not_direct` had nothing to count |

The preconditions a valid window needs, in order: **traffic the program can
parse** (the `v4` and `v6` slots say what arrived, and `not_ip` plus
`frag_or_opts` say what was declined), **forwarded through the box** (or `miss`
dominates), and **flows created after any flowtable change** (the route is
computed once, at flow creation). The legend in `xdp-ft-wwan.sh` states all
three.

Only the first of these is fixed by the v6 work. A window still measures nothing
if the traffic terminates on the router, and still measures the wrong thing if
the flows predate a flowtable change.

### Why nothing is XMIT_DIRECT, and it is structural

`nft_dev_path_info()` sets `FLOW_OFFLOAD_XMIT_DIRECT` in exactly two places:

- `case DEV_PATH_BRIDGE` (`nft_flow_offload.c:154`) — the forward-path walk has
  to cross a bridge, and `nft_dev_forward_path()` then requires the device it
  lands on to be one `nft_flowtable_find_dev()` finds in the flowtable's own
  hook list (`:202`), or it returns before copying any MAC.
- `nf_flowtable_hw_offload(flowtable) && nft_is_valid_ether_device(...)`
  (`:168`) — **which requires hardware offload to be on.**

The second is closed by construction here. Hardware offload has to stay *off* for
any of this to work, because `nf_flow_table_offload_setup()` only populates the
XDP hashtable while it is off (`nf_flow_table_offload.c:1258`) — the sixth line
of this script's own preflight. The setting that makes the kfunc answer is the
setting that forecloses `XMIT_DIRECT`. Section 10.2 recorded hardware offload and
the kfunc as mutually exclusive; this is a second and sharper edge of the same
blade, and it was not visible until the dry run measured it.

The upload direction cannot reach the first route either: the walk starts at
`dst_cache->dev`, which for a LAN-to-WAN flow is `wwan0`, and
`nft_is_valid_ether_device()` rejects it outright — `ARPHRD_RAWIP`, not
`ARPHRD_ETHER`, with no `ETH_ALEN` address. That direction is not what this
program handles, but it explains why nothing in the table is ever direct.

### What would make it fire

`bpf_fib_lookup()` is available to XDP (`xdp_func_proto`,
`bpf_xdp_fib_lookup_proto`) and returns `ifindex`, `smac` and `dmac` on
`BPF_FIB_LKUP_RET_SUCCESS`. It is what the in-tree `xdp_fwd` sample uses, and it
resolves exactly what `XMIT_NEIGH` means the kernel has not cached.

That gives a design with no `XMIT_DIRECT` dependency at all: use the flowtable
for the one thing only it can provide, the NAT translation, and `bpf_fib_lookup()`
for the egress device and the MAC addresses. The lookup has to run on the
*translated* addresses, so the order is flow lookup, NAT, FIB lookup, build L2,
redirect.

**Whether it is worth building is a separate question, and the dry run argues
both ways.** A 98.8% flowtable hit rate means the software flow offload is
already doing its job on nearly every packet. What an XDP program can save on top
of that is the netfilter ingress dispatch and `nf_flow_offload_ip_hook()`'s own
work — real, but modest — against a FIB lookup it has to pay for and the qdisc
bypass it cannot avoid. That trade has not been measured. The NAT rewrite in
particular has been through a compiler and nothing else. A wrong checksum shows
up as clients losing connectivity, so `probe` comes first and `off` stays to
hand.

**Fixed since that was written**, and the paragraph that used to sit here said
otherwise for a revision longer than it should have: the reads that feed the
packet rewrite were unchecked, so a failed probe read would have written a zero
into the packet. `decide()` now gathers every value — both translated addresses,
both ports, the egress ifindex and both MAC addresses — and checks every read
before `commit()` touches a byte, which is the property described under *Reads
are gathered before anything is written* above.

Still open, in order of how much they matter:

- **`would_redirect` is non-zero for the first time, and is not yet
  trustworthy.** 221258 packets, 48% of an IPv6 window. The same window read
  `tuple.dir` back as 2 or 3 on 41–50% of its lookups, which the kernel cannot
  hold — `dir` is written once at `nf_flow_table_core.c:27` and then used as a
  `container_of` index, so a 2 or 3 would fault the kernel before this program
  saw it. Since `dir` selects the container walk and the NAT peer fields, a read
  wrong half the time is not reliably right the rest of it. This revision adds
  the counters that discriminate the candidates — `l3_ok`/`iif_ok` checked
  against the packet, and `xmit_type` read from the same byte as the bad `dir`.
  Nothing about the redirect should be believed until they come back.
- **`XMIT_DIRECT` is reachable after all** — the claim above that it is not is
  retracted; see `xdp-methods-tested.md` 23.13. The hardware-offload route at
  `:168` is still closed by construction, but the `DEV_PATH_BRIDGE` route at
  `:154` is open.
- **Three variables move together** between the windows that redirect and the
  ones that do not: address family, wired against WiFi, and which bridge port
  the flow uses. One at a time will separate them; asserting the family
  explanation now would repeat the mistake the 0.8% figure made.
- **The rewrite has never executed.** Not once, in either family, so the
  checksum arithmetic has been through a compiler and a disassembler and
  nothing else.
