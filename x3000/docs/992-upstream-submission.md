# Sending the MBIM GRO + XDP work upstream

Plan and review prep for submitting patches 991 and 992 to netdev. Written
2026-09-11, after the hardware audit in `xdp-methods-tested.md` section 20 gave
the GRO claim a measurement instead of an argument.

Nothing here has been sent.

**Direction, settled 2026-09-12 against the 6.12.103 tree: send the driver series.
There is no core fix to send instead.** The 2026-09-11 entry here said the
opposite; it was a plan resting on an unread call path. Section 2 records what the
tree actually says and why both core shapes are dead, because the question will
come up on-list. Sections 3 onward are the series to send. Read "Before you send"
last.

## 1. The problem, stated without reference to any patch

A driver that delivers RX through `gro_cells` cannot accept an skb-mode XDP
program without silently destroying its own GRO.

`netif_elide_gro()` returns true for any `dev->xdp_prog`:

    netdevice.h:2433   if (!(dev->features & NETIF_F_GRO) || dev->xdp_prog)
                               return true;

and `gro_cells_receive()` tests it on every skb, falling back to bare
`netif_rx()` when it fires:

    gro_cells.c:23     if (!gcells->cells || skb_cloned(skb) || netif_elide_gro(dev)) {
    gro_cells.c:24             res = netif_rx(skb);

The elision is right for the case it was written for - you cannot hand a
GRO-coalesced superframe to a program that expects one packet. It is wrong for a
driver that runs XDP itself, per datagram, *before* `gro_cells_receive()`: by then
the program has already seen each datagram individually and coalescing afterwards
is harmless.

Nothing in the API lets a driver say which case it is in, so the core assumes the
first.

**Measured on an RM520N-GL, 2026-09-11**, three load-matched 12s windows at about
310 datagrams/s with a sustained downlink running, using `xdp-filter` with an
empty port list (pass-everything) so only the attach mode varies:

| attach | wwan0 datagrams | IP InReceives | aggregation |
|---|---|---|---|
| `-m native` (program on `link->xdp_prog`) | 3876 | 1782 | **2.18x** |
| `-m skb` (program on `dev->xdp_prog`) | 3754 | 3555 | **1.06x** |
| unloaded | 3658 | 1662 | **2.20x** |

In skb mode `InReceives` comes within 5% of the raw datagram count: GRO is off.
Unloading restores it. The driver, its traffic and its configuration are identical
across all three rows - the only variable is which pointer the program is stored
behind.

**Measured independently a day earlier, at a higher link rate**, and recorded in
`x3000/docs/lean-overlay.md`: the same program attached with `xdpgeneric` gave
**1.00x aggregation against 24.8x detached**. Two runs, two link rates, same
result. The 24.8x figure is the better one to quote upstream - it is
arithmetically comfortable at about 34.7 KB per delivered skb against a 65536
ceiling, and it makes the cost of the defect an order of magnitude rather than a
factor of two.

## 2. Why there is no core fix to send instead

The defect in section 1 is real. Both shapes that would fix it inside the core are
not, and reading the tree is what settled that.

**Canonical record: `xdp-methods-tested.md` section 22.** What follows is the
argument in the form you would paste into an on-list reply, so the decisive
citations are repeated here rather than only linked. Line numbers are pristine
v6.12.103; this build's `net/core/dev.c` sits exactly 5 lines lower, because one
OpenWrt hack patch adds 5 lines at `xmit_one()` and nothing else in the tree
touches that file. Every other file cited here is unpatched and matches as
written.

**Shape B - run the hook inside `gro_cells_receive()` - double-executes.**
Everything a gro_cell receives ends up in `__netif_receive_skb_core()`, which runs
`dev->xdp_prog` unconditionally:

    gro_cells.c:61      napi_gro_receive(napi, skb)   in gro_cell_poll()
    gro.c:303/618/710   gro_normal_one(napi, skb, ...)
    gro.h:514-518       gro_normal_list() -> netif_receive_skb_list_internal()
    dev.c:6000          netif_receive_skb_list_internal()
    dev.c:5914          __netif_receive_skb_list()
    dev.c:5848          __netif_receive_skb_list_core()
    dev.c:5583          __netif_receive_skb_core()
    dev.c:5612          if (static_branch_unlikely(&generic_xdp_needed_key)) {
    dev.c:5616              ret2 = do_xdp_generic(rcu_dereference(skb->dev->xdp_prog), &skb);

An skb-mode attach is what turns that static key on (`generic_xdp_install()`,
`dev.c:5958-5959`), so a hook added inside `gro_cells_receive()` would run the
program twice: once per datagram going in, once more on whatever GRO produced
coming out. The second run is the worse half. It hands the program a coalesced
superframe, which is the exact input `netif_elide_gro()` exists to prevent.

The second site cannot be suppressed. There is no per-skb "XDP already ran"
marker anywhere in the core; the only thing that makes `__netif_receive_skb_core()`
skip is `skb->dev->xdp_prog` being NULL, because that is the argument it passes
and `do_xdp_generic()` returns `XDP_PASS` immediately on NULL (`dev.c:5266`,
`5290`). Adding a marker means a new skb bit for one niche case, which is not a
patch netdev will take.

**Shape A - let the driver opt out of the elision - is worse, not smaller.** With
the program still on `dev->xdp_prog` and the elision suppressed, `gro_cells` would
coalesce first and the core would then run the program once, at `dev.c:5616`, on
the coalesced skb alone. Per-datagram filtering disappears. That inverts the
guarantee rather than preserving it.

**What works is the shape 992 already uses, and it has in-tree precedent.** Hold
the program on a driver-private pointer, run it per datagram through the core's
own helper, and leave `dev->xdp_prog` NULL so that neither `netif_elide_gro()` nor
`__netif_receive_skb_core()` can see it. `do_xdp_generic()` takes the program as an
argument for exactly that purpose, and it is exported:

    dev.c:5262   int do_xdp_generic(struct bpf_prog *xdp_prog, struct sk_buff **pskb)
    dev.c:5296   EXPORT_SYMBOL_GPL(do_xdp_generic);

`drivers/net/tun.c` does precisely this - read in 6.12.103, not assumed:

    tun.c:210    struct bpf_prog __rcu *xdp_prog;          in struct tun_struct
    tun.c:1200   rcu_assign_pointer(tun->xdp_prog, prog);  from ndo_bpf
    tun.c:1926   rcu_read_lock();
    tun.c:1929   ret = do_xdp_generic(xdp_prog, &skb);
    tun.c:2529   ret = do_xdp_generic(xdp_prog, &skb);

`tun` never assigns `dev->xdp_prog`. So 992's driver-side code is not a workaround
for a missing core feature - it is the mechanism, and the only one that keeps both
halves of the contract. None of it should be deleted or simplified away.

For scale: eight in-tree drivers deliver RX through `gro_cells` - vxlan, geneve,
bareudp, macsec, amt, pfcp, rmnet and (with 991) mhi_wwan_mbim. **None of them
implements `ndo_bpf` or mentions XDP at all.** This series would be the first
`gro_cells` driver with an XDP hook, which is why the interaction has gone
unnoticed, and why there is no existing driver to point at for precedent on this
specific pairing. `tun` supplies the call-pattern precedent but does not use
`gro_cells`.

### 2.1 The one core change still worth asking for, separately

The behaviour is correct. What is wrong is that it is invisible: `ethtool -k`
keeps reporting `generic-receive-offload: on` while GRO is elided, so the
order-of-magnitude change in section 1 has no user-visible cause. The install path
already switches off the two *visible* neighbours:

    dev.c:5960   dev_disable_lro(dev);
    dev.c:5961   dev_disable_gro_hw(dev);

Clearing `NETIF_F_GRO` through the same `wanted_features` +
`netdev_update_features()` machinery `dev_disable_lro()` uses would make the
feature bits describe reality, and would make `netif_elide_gro()`'s
`dev->xdp_prog` test redundant rather than load-bearing. Small patch, worth one
attempt, but **a separate submission**: it changes nothing for this driver, and
bundling it would give reviewers a reason to hold the series while arguing about
it.

### 2.2 Two reviewer questions, answered in advance

**"Where is your `xdp_do_flush()`?"** Not needed on this path - checked, not
assumed. Every generic-redirect target finishes its work inline: devmap ends in
`generic_xdp_tx()` (`devmap.c:721`), xskmap calls `xsk_generic_rcv()` which takes
`pool->rx_lock` and calls `xsk_flush()` itself, and cpumap's
`cpu_map_generic_redirect()` does `ptr_ring_produce()` then `wake_up_process()`.
Nothing is parked in a per-CPU bulk queue, so `xdp_do_check_flushed()` - called
from `__napi_poll()` at `dev.c:6899` under `CONFIG_DEBUG_NET` - cannot fire for
this hook.

**"You dereference an RCU pointer without `rcu_read_lock()`."** It is already
held, by upstream code, not by the patch:

    mhi_wwan_mbim.c:296   rcu_read_lock();
    mhi_wwan_mbim.c:298   link = mhi_mbim_get_link_rcu(mbim, session);
    mhi_wwan_mbim.c:306   for (n = 0; n < nframes; n++, ...)
    mhi_wwan_mbim.c:348       netif_rx(skbn);          <- the call 991 replaces
    mhi_wwan_mbim.c:351   rcu_read_unlock();

992's `rcu_dereference(link->xdp_prog)` and its `do_xdp_generic()` call both sit
inside that region, which brackets the whole datagram loop. No locking needs to be
added, and none should be claimed as added.

## 3. The series: one fix plus two patches

992 cannot go alone. It depends on 991 in two concrete ways:

* `gro_cells` must exist on the link - 992's hook runs between the datagram copy
  and `gro_cells_receive()`.
* 991 anchors `skbn->protocol` and the MAC header before delivery. 992's own
  commit message explains why the program cannot run without that: generic XDP
  computes `mac_len` as `skb->data - skb_mac_header(skb)`, and
  `netdev_alloc_skb()` leaves the MAC header at its `~0U` sentinel.

**991 also has to be split, because it bundles a bug fix.** Its newlink hunk is
unrelated to `gro_cells`:

        hlist_add_head_rcu(&link->hlnode, &mbim->link_list[LINK_HASH(if_id)]);
    -   return register_netdevice(ndev);
    +   err = register_netdevice(ndev);
    +           hlist_del_init_rcu(&link->hlnode);

Upstream hashes the link before `register_netdevice()` and leaves it hashed if
registration fails. The wwan core's `newlink` error path then calls
`free_netdev()` without going through `dellink`, so the hash entry survives
pointing at a freed netdev, and `mhi_mbim_get_link_rcu()` can still find it from
the RX callback. That is a use-after-free window, and it must not ship inside a
net-next feature patch: **a fix belongs in `net` with a `Fixes:` tag so it reaches
stable.** Bundled into 991 it would never be backported, and netdev would ask for
the split on the first review pass regardless.

**Verified end to end on 2026-09-12, because the whole split rests on it.**
`mhi_mbim_newlink()` hashes the link and then returns `register_netdevice(ndev)`
with no unwind (`mhi_wwan_mbim.c:newlink`, the `hlist_add_head_rcu()` immediately
before the `return`). The caller is `wwan_rtnl_newlink()`, whose return value
reaches `rtnl_newlink_create()`:

    rtnetlink.c   if (ops->newlink)
                          err = ops->newlink(link_net ? : net, dev, tb, data, extack);
                  else
                          err = register_netdevice(dev);
                  if (err < 0) {
                          free_netdev(dev);
                          goto out;
                  }

`free_netdev(dev)` directly - **`ops->dellink` is not called on this path**, so
`mhi_mbim_dellink()`, which is the only thing that does `hlist_del_init_rcu()`,
never runs. And `struct mhi_mbim_link` *is* the netdev private area
(`wwan_ops.priv_size = sizeof(struct mhi_mbim_link)`), so `free_netdev()` frees the
`hlnode` that is still linked into `mbim->link_list[]`. After that,
`mhi_mbim_get_link_rcu()` walks freed memory from the MHI DL callback on every
NTB - both the node and its `->next`.

Reachable from userspace with `CAP_NET_ADMIN` and no modem cooperation:
`rtnl_newlink_create()` copies the requested ifindex into `dev->ifindex` before
calling `->newlink`, so `ip link add ... type wwan linkid N index <already-taken>`
makes `register_netdevice()` fail at `dev_index_reserve()` after the link is
hashed. 991 adds one more failure mode on the same path, because
`gro_cells_init()` in `ndo_init` can return `-ENOMEM`.

The tag, confirmed from two independent upstream patches that carry it:

    Fixes: aa730a9905b7 ("net: wwan: Add MHI MBIM network driver")

So the submission is one fix plus a two-patch feature series:

    [PATCH net]        net: wwan: mhi_wwan_mbim: unhash the link if register_netdevice() fails
    [PATCH net-next 0/2] net: wwan: mhi_wwan_mbim: GRO batching and an XDP hook
    [PATCH net-next 1/2] net: wwan: mhi_wwan_mbim: deliver RX datagrams through gro_cells
    [PATCH net-next 2/2] net: wwan: mhi_wwan_mbim: XDP hook on the RX datagram path

The fix goes first and separately. 991 then drops that hunk and keeps only the
gro_cells conversion. Check that net-next is open before sending the series; it
closes during each merge window and patches sent into a closed tree are dropped
without comment.

## 4. Changes each commit message needs

Both messages are otherwise ready as written.

**Remove the out-of-tree framing.** 992 ends with *"Out-of-tree patch for the
GL-X3000 lean build; applies after 991."* That line goes. The dependency is
expressed by the series ordering, not by prose.

**Add a sign-off to both**, which `git format-patch -s` does for you:

    Signed-off-by: Ahrion Gallegos <ahrionmgallegos@gmail.com>

**Add the measurement to 992's GRO paragraph.** This is the one substantive
improvement available since the patch was written, and it turns the central
justification from reasoning into evidence. Replace the paragraph beginning
"GRO. The program is kept on link->xdp_prog" with:

    GRO. The program is kept on link->xdp_prog, not dev->xdp_prog.
    dev->xdp_prog is what netif_elide_gro() tests, and gro_cells_receive()
    tests the same predicate on every datagram (net/core/gro_cells.c),
    falling back to bare netif_rx() when it fires; attaching the same
    program in XDP_MODE_SKB therefore silently switches off the GRO that
    patch 1/2 exists to provide. Measured on an RM520N-GL over three
    load-matched 12s windows at ~310 datagrams/s, varying only the attach
    mode: 2.18x RX aggregation in driver mode, 1.06x in skb mode, 2.20x
    with nothing attached. In skb mode InReceives comes within 5% of the
    raw datagram count. Owning ndo_bpf also makes XDP_MODE_DRV the default
    attach mode for this device (dev_xdp_mode()), so `ip link set dev wwan0
    xdp ...` lands here rather than in the generic path.

**Add the same kind of evidence to 991.** Append to the Details list:

    Measured on an RM520N-GL at a sustained 3.3 Mbit/s downlink: 5114 wwan0
    datagrams against 2467 IP InReceives over 20s, i.e. 2.07x aggregation,
    with zero datagrams dropped and 2908 bytes per delivered skb. Three
    independent runs gave 2.07x, 2.09x and 2.12x. Before this change the
    ratio is 1.00x by construction - netif_rx() has no GRO to do.

State the rate alongside the figure and do not extrapolate from it. An earlier
attempt to show aggregation scaling with load produced a 60x reading at ~8700
datagrams/s, and that figure is **withdrawn**: 60 datagrams of ~1400 bytes implies
an 84 KB skb, which exceeds `gro_max_size` of 65536, so GRO cannot have produced
it. The likely cause is datagrams dropped at the `gro_cells` backlog check
(`gro_cells.c:30-34`, `dev_core_stats_rx_dropped_inc()`) - counted by the driver,
never delivered to IP, and therefore booked as aggregation by any metric that
divides the first by the second. **Any aggregation measurement here must report
`rx_dropped` and bytes-per-skb, or it cannot tell coalescing from loss.** A rate
sweep with `curl --limit-rate` did not settle the question either way: the link
would not exceed 3.3 Mbit/s, so all four points landed within a 1.4x span of each
other and aggregation held flat at 2.11-2.15x across them.

## 5. Cover letter (0/2), driver-series version

    Subject: [PATCH net-next 0/2] net: wwan: mhi_wwan_mbim: GRO batching and an XDP hook

    The MBIM RX path currently hands each de-aggregated datagram to the stack
    with netif_rx(), so a single MHI transfer carrying an NTB of up to ~21
    full-size datagrams walks the IP stack 21 times with no batching. On a
    dual Cortex-A53 router at 5G downlink rates that per-packet cost is the
    WAN bottleneck.

    Patch 1 switches delivery to gro_cells, the stock mechanism for
    callback-driven virtual drivers (ip_tunnel, vxlan, geneve). Measured
    2.09x RX aggregation on an RM520N-GL, from 1.00x.

    Patch 2 adds an XDP hook on the same path: ndo_bpf with a per-link
    rcu-protected program pointer, run through do_xdp_generic(). Three
    things make that indirection deliberate rather than lazy - the full
    verdict set including XDP_REDIRECT and therefore AF_XDP; the
    bpf_net_context that the redirect helpers dereference unchecked and
    that only core entry points establish; and GRO, which survives only
    because the program is held on link->xdp_prog where netif_elide_gro()
    cannot see it. Measured: aggregation 2.12x with a program attached
    against 2.09x without.

    The honest limit is stated in patch 2: MBIM NTB aggregation means
    datagrams share one 32KB DMA buffer and each is copied out before the
    program runs. This buys the earliest available drop point and
    driver-context filtering, not the zero-copy page-flip path XDP has on
    real NICs.

    Tested on a GL.iNet GL-X3000 (MT7981A, aarch64) with a Quectel
    RM520N-GL on mainline mhi_pci_generic + mhi_wwan_mbim, kernel 6.12.103.
    Attach, detach, XDP_PASS, XDP_DROP and AF_XDP all exercised; rx_errors
    stayed at zero throughout and no crash records appeared in pstore.

## 6. What reviewers will push back on the driver series

Worth having answers ready rather than discovering these on-list.

**The mode question, and it is the serious one.** Implementing `ndo_bpf` makes
`dev_xdp_mode()` return `XDP_MODE_DRV`, so userspace is told this is native XDP -
but the program runs via `do_xdp_generic()` on an skb that already exists, which
is generic XDP semantics. Expect some version of *"don't advertise driver mode
for a generic-mode hook."*

The patch's answer is that `dev->xdp_prog` is load-bearing for GRO and there is
no third option: hold the program where the core can see it and lose GRO, or hold
it privately and own `ndo_bpf`. The measurement makes that cost concrete rather
than hypothetical.

A reviewer may still answer *"then fix the core so skb-mode XDP does not
blanket-disable GRO"*. Section 2 is the answer to that, and it is worth having
ready in one paragraph: the elision cannot simply be narrowed, because every skb
a gro_cell receives reaches `__netif_receive_skb_core()` where the core runs
`dev->xdp_prog` again, so a second hook double-executes and the second run sees a
coalesced superframe; and suppressing the elision without moving the program makes
the program run on the coalesced skb only. `tun` resolves the same tension the same
way this patch does. What is left for the core is a visibility fix, not a
capability one, and it belongs in its own submission.

**The tun.c precedent is verified.** 992's message says *"drivers/net/tun.c makes
the same call from its own driver context for the same reason."* Checked against
6.12.103 on 2026-09-12, and it holds in all four parts: a private
`struct bpf_prog __rcu *xdp_prog` in `struct tun_struct` (`tun.c:210`), installed
from `ndo_bpf` with `rcu_assign_pointer()` (`tun.c:1200`), executed through
`do_xdp_generic(xdp_prog, &skb)` under `rcu_read_lock()` (`tun.c:1926-1929`, and
again at `tun.c:2529`), and `dev->xdp_prog` never assigned anywhere in the file.
Re-check after any rebase with:

    grep -n "do_xdp_generic\|xdp_prog" drivers/net/tun.c

**Rebase risk, and it is larger than it looked.** `mhi_mbim_rx()` - the exact
function 991 and 992 rewrite - is under active repair upstream *right now*. Looked
up 2026-09-12:

| posted | patch | what it does |
|---|---|---|
| 2026-09-07, Aamir Ahmed | `validate datagram bounds before copy` | adds `if (dgram_offset + dgram_len > skb->len) continue;`. **Withdrawn** in favour of the v2 below |
| 2026-09-11 v2 1/3, Guanglei Zhu | `guard against a cyclic NDP chain` | an NDP whose `wNextNdpIndex` points at itself or backwards loops forever; the check moved to the retrieval site on review |
| 2026-09-11 v2 2/3, Guanglei Zhu | `check skb_copy_bits() return value` | the datagram copy's return is ignored, so a failed copy delivers uninitialized memory to the stack. v2 factors the error handling into a new `mhi_mbim_rx_drop()` helper |

Both v2 patches carry `Fixes: aa730a9905b7` and `Cc: stable`, and both land in the
datagram loop. Consequences:

* **They restructure the loop 991/992 patch.** The `mhi_mbim_rx_drop()` helper
  changes the context around `skb_copy_bits(skb, dgram_offset, skbn->data,
  dgram_len)`, which is inside 992's largest hunk. Rebase, do not hand-merge.
* **Check whether they have been applied before sending.** As of 2026-09-12 they
  were a day-old v2 on-list, not merged. Sending a feature series into an active
  review thread on the same function invites "rebase on Guanglei's set" as the
  first reply.
* **They are also missing from this build**, which is a separate matter from
  submission - see the task list. 6.12.103 has all three holes: no bounds check,
  `skb_copy_bits()` unchecked at `mhi_wwan_mbim.c:324`, and no monotonicity check
  on `wNextNdpIndex` at `mhi_wwan_mbim.c:354`. The cyclic case is an endless loop
  in BH context.

Either way the series must be rebased on current `net-next` and re-tested, not
sent against 6.12.103.

**The raw-IP caveat.** The message states plainly that on an `ARPHRD_RAWIP` link
`mac_len` is 0, so Ethernet-parsing programs misparse silently. That honesty is
an asset, not a liability - leave it in. A reviewer may ask for it to be
surfaced to userspace somehow; there is no existing mechanism, which is a fine
answer.

**The oops report helps.** Documenting the `bpf_net_context` NULL dereference that
a hand-rolled hook produced is the strongest single argument for routing through
`do_xdp_generic()`. Keep the call trace.

## 7. Before you send

In order. The first step replaces guesswork about recipients entirely - do not
hand-curate that list, and do not trust any list I or anyone else writes from
memory, because maintainers change and stale addresses waste reviewer time.

    cd ~/x3000-lean            # or a fresh net-next clone, which is better

    # 1. who gets it - authoritative, reads MAINTAINERS from the tree
    scripts/get_maintainer.pl --nogit --nogit-fallback \
        drivers/net/wwan/mhi_wwan_mbim.c

    # 2. style - netdev enforces this strictly
    scripts/checkpatch.pl --strict --codespell <each patch>

    # 3. build clean with the driver as a module, W=1
    make W=1 drivers/net/wwan/mhi_wwan_mbim.o

    # 4. format the series with a cover letter and sign-off
    git format-patch -s --cover-letter -v1 -2 --subject-prefix="PATCH net-next"

    # 5. dry run first, always
    git send-email --dry-run --to=<from get_maintainer> --cc=netdev@vger.kernel.org v1/*.patch

Also before sending: confirm `net-next` is open, and re-run
`x3000/docs/verify-992a.sh` against the rebased kernel so the numbers in the
commit messages describe the code actually being submitted rather than the
6.12.103 build they were taken from.

**Use `x3000/docs/verify-992a.sh`, do not hand-roll this.** Its section 4 already
measures baseline aggregation and its section 6 measures it with a program
attached in driver mode, with `rx_errors` checked alongside in section 7. Three
separately hand-written samplers during this work produced 2.09x, 2.12x and 2.07x
- the same quantity the verifier reports, at the cost of re-deriving it each time
and of two metric bugs the verifier would not have had.

The one thing the verifier does **not** cover is the skb-mode row, which is the
whole point of section 1. That gap should be closed by adding a section to the
verifier rather than by another ad-hoc script. Until it is, the method is:

    xdp-filter load -m skb -f udp wwan0     # then measure aggregation
    xdp-filter unload wwan0

Aggregation is wwan0's pre-GRO `rx_packets` over post-GRO `InReceives`, and
**`InReceives` must be summed across `/proc/net/snmp` and `/proc/net/snmp6`** -
the wwan is `ipv4v6` and a dual-stack download goes over IPv6, where the IPv4-only
counter stays flat and produces meaningless ratios. Take all rows in one run so
the comparison is internal, and **check the datagram rates match before comparing
ratios**: the first attempt produced a 60x row and a 2.2x row that looked like an
A/B and were simply taken at different downlink speeds.

## 8. Why this is worth sending

991 is uncontroversial: it replaces `netif_rx()` with the mechanism every other
callback-driven virtual driver already uses, and the aggregation number is
measured. It stands on its own merits whatever happens to 992.

992 is the interesting one and may not land in this shape. The mode objection is
legitimate. But the problem it documents is real and, as far as this work has
found, undocumented anywhere else: **a driver that uses `gro_cells` cannot accept
an skb-mode XDP program without silently destroying its own GRO**, because
`gro_cells_receive()` tests `netif_elide_gro()` at `gro_cells.c:23` and drops to
bare `netif_rx()`. Eight in-tree drivers are in that position and none of them has
noticed, because none of them has an XDP hook yet.

The redirection a reviewer is most likely to suggest - "fix the core instead" - has
already been tried on paper and does not exist; section 2 has the call path. So
there is no better version of this change being held back, which is worth saying
plainly if it comes up.
