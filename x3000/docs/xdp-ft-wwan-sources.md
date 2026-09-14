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

Two objects rather than one, and the split is not cosmetic. `bpftool prog
loadall` fails the whole object when any single program in it fails to relocate,
so while the fastpath could not relocate it took the probe down with it and the
measurement could never run. Apart, the probe loads regardless of the fastpath's
state.

Kept as separate `.c` files rather than inlined here: the fastpath is roughly 400
lines, where the three objects in `verify-992a-sources.md` are a dozen each.

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

sha256 of the committed objects:

```
c4371b7a76baf9e6eb99bad111cdbb64b416bbcf701f71eaf30fb61bbc276602  bpf/xdp_ft_probe.bpf
6b725e40f94f42c240c9ffce522951f314d15e3f5f2d1f73de3d91dd8f2f3a7e  bpf/xdp_ft_wwan.bpf
```

## What the two programs do

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

Dumping the object's `.BTF.ext` showed 28 CO-RE relocations, of which exactly one
was a type-id relocation, and it was relo #7:

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
remaining 27 are all `FIELD_*` and resolve unchanged.

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
| `not_ipv4` | 1 | |
| everything else | 0 | |

25619 + 423 + 1 = 26043, so every packet is accounted for. `seen` matching the
driver's own counter exactly means the program sits in front of the whole receive
path rather than a sample of it. This is the measurement section 16.5 asked for:
`bpf_xdp_flow_lookup()` works on a raw-IP modem interface.

**One correction to the probe's own counters.** The split between `miss` and
`lookup_err` is wrong. `bpf_xdp_flow_tuple_lookup()` returns `ERR_PTR(-ENOENT)`
when `flow_offload_lookup()` finds nothing (`nf_flow_table_bpf.c:47-48`), and the
caller then sets `opts->error` from it (`:94-97`), so an ordinary miss sets the
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

**Next is the dry run, not the rewrite.** `xdp-ft-wwan.sh dryrun` attaches
`xdp_ft_dryrun`, which decides everything and writes nothing. The NAT rewrite in
particular has been through a compiler and nothing else. A wrong checksum shows
up as clients losing connectivity, so `probe` comes first and `off` stays to
hand.

Known and deliberately not yet fixed, because one change at a time: the reads
that feed the packet rewrite are unchecked. `flags` is checked, since a silent
zero there would redirect with no translation at all, but the address and port
reads are not, and a failed probe read would write a zero into the packet. The
fix is to gather every value before mutating anything, and it is worth doing
before the program is ever left attached.
