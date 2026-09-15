# Native XDP on wwan0: design note

Status: **written as 893. Nothing here is built, and nothing here is measured.**
Every API contract below was read at `v6.12.103`; every statement about this
tree's driver was read against the source after 890, 891 and 892 are applied.

This supersedes the framing in W0026. It is not a page-pool rewrite.

## The premise that was wrong

W0026 has been carried as "the page-pool rewrite of the RX refill is the only
route to XNF01 there", on the understanding that MBIM datagrams live packed
inside a shared NTB with no per-packet headroom, so native XDP would need the
receive path rebuilt around exclusively-owned buffers.

That is not what the driver does, and never was. Pristine upstream
`mhi_wwan_mbim.c:319-324`:

```c
skbn = netdev_alloc_skb(link->ndev, dgram_len);
if (!skbn)
        continue;

skb_put(skbn, dgram_len);
skb_copy_bits(skb, dgram_offset, skbn->data, dgram_len);
```

Every datagram is **copied out of the NTB into its own fresh allocation**. No
clone, no sharing, no aliasing with any other packet. The buffer is exclusively
owned from the moment it exists.

891 then added headroom to that allocation:

```c
headroom = xdp_prog ? XDP_PACKET_HEADROOM : 0;

skbn = netdev_alloc_skb(link->ndev, headroom + dgram_len);
skb_reserve(skbn, headroom);
skb_put(skbn, dgram_len);
```

So with a program attached, each datagram already sits in a privately-owned
buffer with **256 bytes in front of it**. That is everything `xdp_prepare_buff()`
asks for, and 256 comfortably clears the 40-byte `sizeof(struct xdp_frame)` floor
that `xdp_convert_buff_to_frame()` needs for `XDP_REDIRECT` and cpumap.

The gap between here and native XDP is not the buffer. It is that the buffer is
wrapped in an skb *before* the program runs instead of after.

## What the driver has, and what it lacks

Counted in the tree with the full series applied.

| present (891 built this) | count | missing | count |
|---|---|---|---|
| `ndo_bpf` | 4 | `xdp_rxq_info_reg` | 0 |
| `xdp_prog` | 12 | `xdp_init_buff` | 0 |
| `XDP_PACKET_HEADROOM` | 3 | `xdp_prepare_buff` | 0 |
| `skb_reserve` | 1 | `bpf_prog_run_xdp` | 0 |
| `do_xdp_generic` | 5 | `xdp_do_redirect` | 0 |
| `bpf_prog_put` | 1 | `xdp_do_flush` | 0 |
| | | `build_skb` | 0 |
| | | `napi_alloc_frag` | 0 |
| | | `bpf_net_ctx_set` | 0 |
| | | `ndo_xdp_xmit` | 0 |

The attach path, the program pointer, the RCU lifetime discipline and the
headroom reservation are done. What is missing is the buffer type and the
verdict handling.

## Verified API contracts

Read at `v6.12.103`, because getting any of these wrong is how this becomes a
crash rather than a feature.

**`bpf_net_ctx_set()` is nesting-safe** (`include/linux/filter.h:774`). It
returns `NULL` if `current->bpf_net_context` is already set, and
`bpf_net_ctx_clear(NULL)` is a no-op (`:786`). So the set/clear pair can be
taken unconditionally around the loop without checking whether something
upstream already took it. `do_xdp_generic()` (`dev.c:5290`) uses exactly this
idiom, which is what 891 currently relies on.

**Registration** (`include/net/xdp.h:339`):

```c
int __xdp_rxq_info_reg(struct xdp_rxq_info *xdp_rxq,
                       struct net_device *dev, u32 queue_index,
                       unsigned int napi_id, u32 frag_size);
```

with `xdp_rxq_info_reg(rxq, dev, queue_index, napi_id)` as the wrapper passing
`frag_size = 0`. `napi_id` may be 0. Then
`xdp_rxq_info_reg_mem_model(rxq, MEM_TYPE_PAGE_SHARED, NULL)` - `MEM_TYPE_PAGE_SHARED`
is the split-page refcount model at `xdp.h:42`, which is what a frag allocation is.

**Buffer setup** (`xdp.h:122`, `:130`):

```c
xdp_init_buff(&xdp, frame_sz, rxq);
xdp_prepare_buff(&xdp, hard_start, headroom, data_len, meta_valid);
```

**The tailroom rule, which is the one that bites** (`xdp.h:147`):

```c
#define xdp_data_hard_end(xdp)                          \
        ((xdp)->data_hard_start + (xdp)->frame_sz -     \
         SKB_DATA_ALIGN(sizeof(struct skb_shared_info)))
```

with the comment "same area (and size) is used for XDP_PASS, when constructing
the SKB via build_skb()". So `frame_sz` **must include** the `skb_shared_info`
tailroom. This is the trap: `netdev_alloc_skb()` adds that tailroom internally
and invisibly, so today's code never had to think about it. A raw frag
allocation must do the arithmetic explicitly.

## The design

### Allocation

```
alloc_sz  = XDP_PACKET_HEADROOM
          + dgram_len
          + SKB_DATA_ALIGN(sizeof(struct skb_shared_info))

frame_sz  = alloc_sz
hard_start = the frag
data       = hard_start + XDP_PACKET_HEADROOM
```

The copy is unchanged - `skb_copy_bits(skb, dgram_offset, data, dgram_len)` -
same source, same length, same cost as today. Nothing about the NTB parse or
892's bounds checks changes.

Note what this arithmetic means for `bpf_xdp_adjust_tail()`: `xdp_data_hard_end`
lands exactly at the end of the datagram, so there is **no room to grow the
tail**. A program that tries gets `-EINVAL`, which is a defined outcome rather
than corruption. Adding slack is a deliberate decision with a per-packet memory
cost, and should be made on evidence rather than by default.

### The loop

```
bpf_net_ctx = bpf_net_ctx_set(&__bpf_net_ctx);     /* once, before the loop */

for each datagram:
        frag = allocate(alloc_sz)
        copy datagram to frag + XDP_PACKET_HEADROOM
        xdp_init_buff(&xdp, alloc_sz, &link->xdp_rxq)
        xdp_prepare_buff(&xdp, frag, XDP_PACKET_HEADROOM, dgram_len, false)

        act = bpf_prog_run_xdp(prog, &xdp)
        switch (act):
          XDP_PASS      -> build_skb(frag, alloc_sz)
                           skb_reserve(skb, xdp.data - xdp.data_hard_start)
                           skb_put(skb, xdp.data_end - xdp.data)
                           ... rejoin today's path from skbn->protocol onward
          XDP_DROP      -> free the frag.  NO SKB EVER ALLOCATED.
          XDP_REDIRECT  -> xdp_do_redirect(ndev, &xdp, prog)
          XDP_TX        -> not implemented initially; XDP_ABORTED
          default       -> bpf_warn_invalid_xdp_action, XDP_ABORTED

xdp_do_flush();                                    /* once, after the loop */
bpf_net_ctx_clear(bpf_net_ctx);
```

`skb_reserve`/`skb_put` after `build_skb()` must use the *post-program* `xdp.data`
and `xdp.data_end`, not the original offsets, because `bpf_xdp_adjust_head()` may
have moved them. That is the whole point of having headroom.

### Why the win is real

On `XDP_DROP` no skb is allocated at all - today's path allocates one, runs the
program on it, and frees it. On `XDP_REDIRECT` the 256 bytes of headroom make
`xdp_convert_buff_to_frame()` succeed, which is what puts cpumap within reach.

**cpumap is the point.** The MBIM receive path runs on one CPU - the MHI DL
tasklet - and cpumap redirect is the mechanism for moving per-packet work off
it. That is also why W0045 (873) had to land first: without it,
`__xdp_build_skb_from_frame()` runs `eth_type_trans()` over the IP header and
`ip_forward()` drops every redirected packet.

## Hazards

**Context.** The RX path runs in the MHI DL tasklet, which the driver's own
comment at `mhi_wwan_mbim.c:384` already records. That is softirq context with
BH disabled, so `this_cpu` state in the redirect ring is safe and the tasklet
cannot migrate mid-execution. `rcu_read_lock()` is already held across the loop
at `:545`. `xdp_do_flush()` must be called on the same CPU before leaving, which
the single flush after the loop satisfies.

**`frame_sz` is the sharp edge.** It must be the true allocation size including
`SKB_DATA_ALIGN(sizeof(struct skb_shared_info))`, or `bpf_xdp_adjust_tail()`'s
memset runs past the end of the buffer. This is the same class of mistake
section 24.2 already caught once, on the same subject.

**`build_skb()` needs the frag to be a real page frag**, not a kmalloc'd
pointer with no page backing, because `skb_free_head()` will treat it
accordingly. `napi_alloc_frag()` is the wrong helper here - it is documented for
NAPI context - so the allocation helper needs choosing deliberately against the
tasklet context rather than copied from an Ethernet driver.

**Memory accounting changes.** Today's `netdev_alloc_skb()` charges an skb per
datagram. A frag allocation with a deferred `build_skb()` charges differently,
and the `truesize` seen by GRO and by socket accounting will not be what it was.
890's gro_cells path is downstream of this, so any change there needs
re-measuring, not assuming.

**XDP_TX needs `ndo_xdp_xmit`** on the MHI UL path. Deliberately out of scope
for a first cut: returning `XDP_ABORTED` for it is honest and keeps the change
reviewable.

## Verification plan

Nothing here is measured, so the plan matters more than the code. These are
T0056 through T0060 on the matrix, against build B0011, which does not exist
yet.

1. **Attach a counting program and confirm the path is native**, not generic -
   `bpftool prog show` reports the type, and the generic path's
   `do_xdp_generic()` call disappears from the flow.
2. **XDP_DROP at rate**, with `/proc/net/dev` on `wwan0` showing packets
   received and nothing delivered upward, and CPU time in the DL tasklet
   compared against the same program under generic XDP. That difference is the
   whole justification.
3. **XDP_PASS end to end**, confirming forwarded traffic still works and that
   `bpf_xdp_adjust_head()` moving the start does not break the rejoin -
   this is where the `skb_reserve`/`skb_put` arithmetic gets tested.
4. **XDP_REDIRECT into a cpumap**, which requires 873. Forwarded traffic must
   survive; without 873 it will not, and confirming that failure first is a
   direct reproduction of W0045.
5. **A program that grows the tail**, confirming `-EINVAL` rather than
   corruption, given the allocation leaves no tail slack.

## Where this stands with upstream

Worth stating in the design rather than finding out in review. On 2026-08-14
Jakub Kicinski refused Jiayuan Chen's `net: xdp: don't assume an Ethernet header
in generic XDP` with "There is no native XDP on any non-ether device, making
generic xdp work on those is silly. Just attach the BPF in TC", and Toke
Hoiland-Jorgensen added that the "XDP is Ethernet only" assumption should be
left alone.

This design is a counter-example to the premise in Kicinski's first sentence: it
makes a non-Ethernet device a native XDP device, and it asks the core for
nothing, because the buffer discipline was already in the driver. That is a
different thing from overturning the conclusion, which was three maintainers'
stated position and stays theirs.

Alexander Lobakin, in the same thread, listed what would break on such a device:
"XDP_TX, XDP_REDIRECT won't work properly -- cpumap Rx, each .ndo_xdp_xmit()
implementation". He was right on both counts. cpumap Rx is W0045, which 873
fixes; `ndo_xdp_xmit` is the XDP_TX limitation recorded above. Neither was
discovered here first, and saying so is cheaper than having it said back.

## What this does not do

It does not give `wwan0` AF_XDP zero-copy, which needs `MEM_TYPE_XSK_BUFF_POOL`
and a real driver-owned queue. It does not change the NTB parse, the de-aggregation,
or 892's bounds checks. It does not remove the per-datagram copy - that copy is
inherent to MBIM aggregation and is what makes the buffer exclusively owned in
the first place. And it does not touch the frame engine, which has nothing to do
with this path.
