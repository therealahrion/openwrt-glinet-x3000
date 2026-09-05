# QoS / Latency Lab — research notes

Context: GL.iNet GL-X3000, OpenWrt 25.12, kernel **6.12.103**, QModem vendor
`pcie_mhi` modem stack, eBPF/XDP lab baked (BTF, kprobes, AF_XDP, host-clang
BPF toolchain, sqm + qosify + cake + sched kmods). Researched 2026-09.

## 1. The four layers — where every technique lives

Almost all confusion in this space comes from mixing four layers that can
only fix their own problems:

| Layer | Who runs it | Techniques |
|---|---|---|
| **Sender endpoint** | The machine *originating* traffic | BBR v1/v2/v3, TCP Prague, TSQ, socket pacing (`sk_pacing_rate`, `SO_MAX_PACING_RATE`), BPF sk-pacing, eBPF+EDT host shaping, `sch_fq` as pacer |
| **Bottleneck middlebox** | *This router* | Shaping (CAKE/HTB/TBF), AQM (CoDel/PIE/DualPI2), flow isolation (fq_codel/CAKE), classification (qosify/DSCP), autorate |
| **Link / driver / hw** | NIC + modem silicon | BQL, mq/mqprio, hardware shapers (ETF/TSN, vendor QDMA), flow offload, the modem's internal buffers |
| **Network-cooperative** | Endpoints *and* every bottleneck | ECN, **L4S** (ECT(1) + DualPI2/dual-queue + Prague/AccECN), carrier L4S |

Two iron laws follow. **A router cannot choose congestion control for
traffic it forwards** — BBR/TSQ/pacing on the X3000 affect only the router's
own connections (speedtests, its downloads), never your PC's game traffic.
And **an endpoint cannot fix a bloated bottleneck it doesn't own** — which
is why the middlebox layer (cake + autorate) is where a 5G router earns its
keep.

## 2. Term by term

### FQ (`sch_fq`) — vs fq_codel, and why they're different things
`sch_fq` is a **pacing scheduler for senders**: per-flow queues released on
socket pacing rates and EDT timestamps. It is *not* fq_codel (per-flow
AQM for forwarded traffic, OpenWrt's default qdisc — verified
`CONFIG_DEFAULT_NET_SCH="fq_codel"` in this tree). fq shines on servers;
on a router it only paces locally-originated traffic.
**Status here:** `sch_fq` ships inside the `kmod-sched` bundle → already in
the next image. fq_codel: everywhere by default. **Verdict: fq = lab piece;
fq_codel/cake do the real work.**

### CAKE / sqm / qosify / autorate
Covered in depth in earlier project notes; summary: cake is the shaping +
per-flow-fairness + AQM engine both managers use; sqm-scripts and qosify
are alternative managers (run ONE); cake-autorate retunes cake's rate to
track variable 5G capacity — the single highest-value latency tool for
this link. All baked; autorate is a bash script installed on-device
(bash + fping baked for it).

### "cake_mq" (mq + per-queue cake)
Technique: attach an `mq` root and one cake instance per hardware TX queue
so shaping scales across CPU cores — relevant for multi-gigabit wired
boxes. The X3000's WAN is a single-queue modem netdev (`rmnet_mhi0`) and
one cake instance at 5G rates is exactly what the SQM ceiling is about.
`kmod-sched-mqprio` exists in feeds if LAN-side experiments appeal.
**Verdict: not applicable to this WAN.**

### TSQ (TCP Small Queues)
In-kernel since 3.6, automatic, no knob needed: limits how many bytes each
local TCP socket may park in qdisc/driver queues, keeping the *sender's own*
stack unbloated. Endpoint-layer; already active on the router for its own
flows and on any Linux sender. **Verdict: nothing to do — already have it.**

### BBR v1 / v2 / v3
Congestion control = **endpoint** tech. v1 is mainline (`kmod-tcp-bbr` —
already in this config since vjt; enable per-router with
`sysctl net.ipv4.tcp_congestion_control=bbr`, affects router-originated TCP
only). v2 was an alpha branch, superseded. **v3 is still out-of-tree** as of
Sept 2026 — it lives in Google's `google/bbr` kernel branch; upstreaming
was announced in 2023 and has not landed (kernel's `tcp_bbr` remains v1).
**Correction (verified 2026-09):** BBRv3 does NOT require building Google's
kernel — community-maintained backport patches exist
([CachyOS kernel-patches](https://github.com/CachyOS/kernel-patches) `6.12/`,
XanMod equivalents), and the CachyOS bbr3 patch **dry-run-applies cleanly
to exactly 6.12.103 (0 failed hunks, tested)**. It replaces the in-kernel
bbr (v1) and touches core TCP files — droppable into this fork as a
`target/linux/generic` patch. **Verdict unchanged in substance: CC is
endpoint tech, so on the router it governs only router-originated TCP —
but it is genuinely backportable here, today.**

### Pacing, EDT, and "BPF sk pacing"
**Pacing** = spreading packets at a rate instead of bursting;
**EDT** (Earliest Departure Time, Google's Carousel model) = each skb
carries a departure timestamp and `sch_fq` releases it on schedule.
Knobs, all sender-side: CC sets `sk_pacing_rate` (BBR does this);
apps cap it with `SO_MAX_PACING_RATE`; and **BPF sk-pacing** = a
cgroup/sockops eBPF program calling `bpf_setsockopt(SO_MAX_PACING_RATE)`
to rate-limit services per-socket — a datacenter pattern (per-tenant
egress control). Needs `KERNEL_CGROUP_BPF` → baked.
**"BBRv3 + BPF sk pacing"** = servers pacing BBR flows under an
eBPF-imposed ceiling; composes fine, still endpoint-land.

### eBPF + EDT (Cilium-style bandwidth management)
The tc-eBPF program stamps `skb->tstamp` (`bpf_skb_set_tstamp`) and `sch_fq`
enforces the schedule — how Kubernetes/Cilium shape pod egress without HTB.
On this router you *could* reproduce it (tc-bpf + sch_fq + BTF all baked)
— a great learning lab — but for forwarded WAN traffic it amounts to
rebuilding cake's shaper minus its AQM and fairness. **Verdict: excellent
experiment, wrong tool for the 5G latency job.**

### EDT + VDQ-CSAQM
Research frontier (Nokia Bell Labs / ELTE line of work): core-stateless AQM
using **virtual dual queues** driven by eBPF+EDT at hosts — L4S-ish dual
behavior without per-bottleneck queues. Paper-stage prototypes; nothing
packaged for OpenWrt anywhere. **Verdict: watch list only.**

### DualPI2 & L4S — the one to actually watch
L4S (RFC 9330-9332) = network-cooperative ultra-low latency: endpoints mark
ECT(1) and back off per-signal (TCP Prague / AccECN semantics), bottlenecks
run a **dual-queue coupled AQM (DualPI2)** giving L4S flows ~1 ms queues
alongside classic traffic.
**Kernel status (verified 2026-09):** `dualpi2` is mainline **from 6.17**;
**AccECN landed in 6.20**; TCP Prague mainlining has started but is not
upstream. None of it is in this 6.12 kernel or the 25.12 feeds — BUT the
L4S team maintains a dedicated **`l4steam-6.12.y` branch**
([L4STeam/linux](https://github.com/L4STeam/linux), tracked by
[phoepsilonix/linux-l4s](https://github.com/phoepsilonix/linux-l4s)) with
Prague + dualpi2 + AccECN on our exact kernel series, with prebuilt
releases. Extracting that branch's diff into `target/linux/generic`
patches is a real, maintained backport path — the heaviest of the bunch
(core TCP + ECN + qdisc), but existing, not hypothetical. Notably, with
carrier L4S live, backporting the *endpoint* pieces to the router has one
legit lab use: originating true L4S flows from the router to validate the
carrier path end-to-end; and dualpi2 on the router is the forward answer
to the cake/L4S coexistence caveat above.
**Carrier status — the big one:** **T-Mobile US turned L4S on across its
5G-Advanced network in July 2025**, the first wireless deployment. If this
router's SIM is T-Mobile (or a carrier that follows), L4S-capable apps
(FaceTime, cloud gaming, etc.) can get low-latency treatment end-to-end
*in the carrier network itself*.
**The router's job in an L4S world is mostly "do no harm":** don't strip
ECN bits, and be aware of the classic-ECN coexistence caveat — when cake is
the bottleneck it CE-marks with RFC 3168 semantics, which L4S ECT(1) flows
interpret aggressively; if L4S traffic matters on this link, the pragmatic
posture is to shape (bufferbloat control) and observe, and revisit when
DualPI2 reaches an OpenWrt kernel. A 6.12 **backport of the dualpi2 qdisc
is feasible** (self-contained scheduler) if we ever want the router itself
to be an L4S bottleneck — flagged as a future project.

### AQM alternatives in the feeds
`kmod-sched-pie` and `kmod-sched-fq-pie` (RFC 8033 PIE — the DOCSIS AQM)
and `kmod-sched-red`/`drr`/`prio` exist in feeds, **not currently baked**.
Candidates if AQM A/B testing appeals; cake/fq_codel outclass them for
home use.

### Hardware-level pacing & queueing
- **ETF/TSN** (`sch_etf`, `SO_TXTIME` offload, time-aware shaping): needs
  TSN-capable NICs (Intel igc etc.) — MT7981 has none; not packaged here.
- **NIC hardware rate limiting** (mlx5/bnxt per-queue shapers): datacenter
  silicon, N/A.
- **MediaTek QDMA hardware QoS**: exists in vendor SDKs; mainline exposure
  is minimal — and the mainline MTK feature that *is* present, **hardware
  flow offload (HNAT)**, *bypasses qdiscs entirely*. Rule stands: on a
  shaped WAN, offload stays off, or cake never sees the packets.
- **BQL**: byte-limits driver rings so qdiscs keep control — active in the
  ethernet path automatically; nothing to tune.
- **The real hardware queue problem:** the RM520N's internal buffers (and
  the carrier scheduler behind it). Linux cannot AQM those — the entire
  reason autorate keeps the bottleneck *inside* cake on the router.

## 3. Verdicts, ranked for this box

1. **cake + cake-autorate** — the latency fix for variable 5G. Do first.
2. **qosify vs sqm A/B** — classification refinement; already baked.
3. **L4S awareness** — check carrier (T-Mobile: live); verify ECT(1)
   survives the path; keep ECN unmolested; revisit DualPI2 when kernel
   moves (or ask for the backport).
4. **BBR** — v1 aboard for router-local TCP; v3 belongs on endpoints;
   nothing further on the router.
5. **eBPF+EDT / BPF sk-pacing** — real tech, wrong layer for WAN latency;
   the build fully supports experimenting with both.
6. **PIE/fq-pie/mqprio/ETF/hw pacing** — available-or-N/A footnotes.

## 4. Platform-ready: bake-time verdict + the three buckets

**Bake-time conflict verdict (validated 2026-09-04):** baking support is
additive and safe. Kmods are independent `.ko` files that sit unloaded
until something modprobes them; qdiscs are code the kernel *can* attach,
not code it does attach; userspace tools are disjoint binaries. Every
"can't use X and Y together" in this doc is a **runtime** exclusivity
(the three rules below) — none of them is an install-time conflict.
Both managers baked together is specifically safe at rest: sqm ships
disabled and qosify's shipped config has no interface section, so a
freshly flashed image with both aboard starts them inert. The only
bake-time exclusivities in this whole space, all already handled:

1. **Same-binary variants** — `tc-tiny` vs `tc-bpf` vs `tc-full` (one
   `tc` binary; we bake tc-bpf), and the old uqmi/qmi-wwan vs QModem
   pair (unset long ago). Resolved.
2. **Patch-level replacements** — the BBRv3 backport *replaces*
   `tcp_bbr.c` in place; v1 and v3 cannot coexist in one kernel. The
   other source patches (DualPI2, Prague, AccECN, BORE, sched_ext flip)
   are additive, but any of them changes the kernel you ship — they're
   rebuild decisions, not package adds. None applied.
3. That's it. Nothing else conflicts at bake time.

**Bucket 1 — already baked** (in `config.common` now; in every image
built from it): the entire eBPF/XDP substrate (BTF + BTF-in-modules,
cgroup-BPF, kprobes, perf events, AF_XDP, host BPF toolchain), tc-bpf,
libbpf, bpftool-full, xdp-loader/xdpdump, xdp-sockets-diag, sched-bpf,
full kmod-sched (fq, htb, mq, …) + kmod-sched-cake + ifb, BBR v1,
sqm-scripts + luci, qosify, bash + fping (cake-autorate's deps — the
script itself is unpackaged, install per its repo). Plus the always-on
natives: fq_codel default, TSQ, BQL, ECN forwarding. Together these
already cover: FQ, CAKE, cake_mq (mq+cake, LAN-side), FQ+BBR, EDT,
eBPF+EDT, BPF sk-pacing, and every sqm/qosify/autorate workflow.

**Bucket 2 — can bake, deliberately on hold** (verified compatible with
everything in bucket 1; zero conflicts if added):

* One-line package adds: kmod-sched-pie, fq-pie, red, drr, prio,
  skbprio, mqprio (+common), ctinfo, act-police; xdp-filter /
  xdp-forward / xdp-bench / xdp-monitor; bpfcountd; ucode-mod-bpf.
  Remember the vermagic rule: decide before flashing.
* One-line kernel flip: sched_ext (`CONFIG_SCHED_CLASS_EXT`; in 6.12
  source, compiled out).
* Source backports (rebuild decisions): DualPI2 + Prague + AccECN
  (L4STeam `l4steam-6.12.y`), BORE (0 failed hunks on 6.12.103),
  BBRv3 (0 failed hunks — but a *replacement* for v1, see above).

**Bucket 3 — cannot bake:** EDT VDQ-CSAQM (paper/patent/P4 only — no
Linux implementation exists to bake; its primitives, tc-bpf+EDT+fq, are
bucket 1); ETF/TSN and NIC hardware pacing (MT7981 has no TSN-capable
NIC — hardware, not software); MTK vendor hardware QoS (vendor-SDK
only, not in mainline; the mainline HW path is flow offload, which is
runtime-exclusive with shaping); BBRv2 (obsolete, no maintained 6.12
patch); scx_cake's userspace scheduler (kernel side would be the
sched_ext flip, but the Rust loader is x86-tuned and unpackaged for
musl/aarch64 — not bakeable as-is).

## 5. Ten-minute experiment cookbook

```sh
# BTF sanity (CO-RE ready?)
bpftool btf dump file /sys/kernel/btf/vmlinux | head
# Router-local BBR (affects only the router's own TCP)
sysctl -w net.ipv4.tcp_congestion_control=bbr
# Pacing lab: put sch_fq somewhere harmless and watch it
tc qdisc replace dev br-lan root fq; tc -s qdisc show dev br-lan
# Does ECT(1) survive the carrier path? (L4S probe)
tcpdump -ni rmnet_mhi0 'ip[1] & 3 == 1'
# The managers (one at a time)
service sqm enable && service sqm start        # or:
uci set qosify.@interface[...]; service qosify restart
# cake-autorate: install per its INSTALLATION.md (bash + fping present)
```

## Appendix: CPU schedulers — scx_cake, BORE, sched_ext

These are **CPU (task) schedulers**, a different axis from packet queueing:
they decide which *process* runs next, not which packet leaves next. On a
headless router the latency-critical packet path (NAPI polling, cake in
softirq) barely interacts with the task scheduler, so their ceiling here
is inherently low. Verified status:

**sched_ext (the scx framework):** mainlined in **kernel 6.12** — this
build's exact kernel. Verified in-tree: `CONFIG_SCHED_CLASS_EXT is not
set` in `target/linux/generic/config-6.12`, i.e. present in source,
compiled out. Enabling it in this fork = one kernel-config line (+ BTF,
already baked). Caveat: the *official* sched-ext/scx scheduler suite
increasingly targets kernels newer than 6.12; per-scheduler minimums vary.

**scx_cake** ([RitzDaCat/scx_cake](https://github.com/RitzDaCat/scx_cake)):
experimental BPF CPU scheduler adapting network CAKE's DRR++ idea to CPU
scheduling, for gaming workloads. Requires kernel **6.12+** — so it clears
the version bar here — but it is explicitly tuned for modern x86
(Ryzen X3D, Intel hybrid), carries an EXPERIMENTAL warning, uses a Rust
loader (unpackaged for musl/aarch64), and optimizes a workload class
(games running locally) the router doesn't have. **Dismissed for the
router on workload/architecture/maturity — not kernel version. It's a
candidate for the 9950X3D desktop instead.**

**BORE** ([firelzrd/bore-scheduler](https://github.com/firelzrd/bore-scheduler)):
burstiness-based EEVDF tweak for desktop responsiveness. Verified: a
maintained `stable/linux-6.12-bore` patch series exists (pinned at
6.12.37 vs our 6.12.103 — would need an apply-test/minor rebase), pure
arch-agnostic kernel-sched code, so **backportable in form**. Dismissed
on merit for the router: it improves interactive-task scheduling under
desktop load, which a headless router has none of, and the packet path
lives in softirq where BORE doesn't reach. Its rightful home is a gaming
PC (CachyOS ships it by default). The companion SMT patch is moot on
Cortex-A53 (no SMT).

**What actually helps CPU-side packet latency on this box:** IRQ affinity
/ packet steering and threaded NAPI — runtime knobs that already exist,
no scheduler replacement required.

## Runtime conflict rules (govern everything below)

1. **One master per interface.** One root qdisc per netdev (cake vs HTB vs
   PIE vs fq: a per-interface choice, not a conflict). One *manager* per
   interface: sqm-scripts XOR qosify. One DSCP marker at a time.
2. **Fast paths bypass queues.** HW/SW flow offload and XDP_REDIRECT
   forwarding skip the qdisc layer — mutually exclusive with shaping the
   same path. XDP filtering/observation coexists fine.
3. **Layers compose; semantics can clash.** Endpoint pacing/CC never
   conflicts with middlebox shaping. The one semantic caveat: RFC 3168
   CE-marking (cake) vs L4S ECT(1) flows when cake is the bottleneck.

At bake time, essentially nothing conflicts (only same-binary variants
like tc-tiny/tc-bpf). All real conflicts are runtime, per the rules above.

## Validated support matrix (re-validated 2026-09-04, source-level)

Note: no image containing the eBPF/QoS-lab config has been flashed yet —
**NEXT-BUILD** = in `config.common` now, present in the next image.
Tiers: **NATIVE** (always on) · **NEXT-BUILD** · **FEEDS** (packaged,
deliberately not baked yet) · **CONFIG-FLIP** (in 6.12 source, one kernel
config line) · **BACKPORT✔** (external patch, dry-run-tested clean on
6.12.103) · **BACKPORT-BRANCH** (maintained 6.12.y branch, untested here)
· **NO-ARTIFACT** · **N/A-HW**.

| Technique | Tier | Evidence (verified) |
|---|---|---|
| TSQ | NATIVE | 29 tsq refs in `tcp_output.c` (6.12.103 source) |
| BQL | NATIVE | driver-level, automatic |
| fq_codel | NATIVE | `CONFIG_DEFAULT_NET_SCH="fq_codel"` |
| ECT(1)/ECN passthrough | NATIVE | router forwards ECN bits untouched |
| CAKE | NEXT-BUILD | `sch_cake.c` present; `kmod-sched-cake=y` |
| sqm / qosify / autorate-deps | NEXT-BUILD | 37/37 config sweep |
| FQ (`sch_fq`, EDT-aware) | NEXT-BUILD | `sch_fq.c` present, 6 tstamp refs; in `kmod-sched=y` |
| BBR v1 (+FQ+BBR combo) | NEXT-BUILD | `tcp_bbr.c` present; `kmod-tcp-bbr=y`; router-local flows only |
| EDT via eBPF | NEXT-BUILD | `bpf_skb_set_tstamp` in `filter.c` + uapi; tc-bpf + BTF baked |
| BPF sk-pacing | NEXT-BUILD | `SO_MAX_PACING_RATE` @ `filter.c:5317`; `KERNEL_CGROUP_BPF=y` |
| cake_mq (mq + cake children) | NEXT-BUILD-capable | `sch_mq.c` present + cake; WAN is single-queue → LAN-only technique; mqprio in FEEDS |
| PIE, fq-PIE, RED, DRR, prio, skbprio, mqprio, ctinfo, act-police | FEEDS | in 25.12 feeds; **not baked** (user hold, 2026-09-04); kmods must be baked pre-flash |
| xdp-filter/forward/bench/monitor, bpfcountd, ucode-mod-bpf | FEEDS | same hold |
| sched_ext | CONFIG-FLIP | `kernel/sched/ext.c` PRESENT; `# CONFIG_SCHED_CLASS_EXT is not set`; no packaged scx userspace |
| scx_cake | CONFIG-FLIP + porting | repo requires 6.12+; x86-tuned, Rust loader unpackaged for musl/aarch64 |
| BBRv3 (± BPF sk-pacing) | BACKPORT✔ | CachyOS bbr3 patch: **0 failed hunks vs 6.12.103**; would *replace* bbr v1; endpoint-only |
| BORE | BACKPORT✔ | firelzrd `linux-6.12-bore`: **0 failed hunks vs 6.12.103**; desktop-interactivity tech |
| DualPI2 | BACKPORT-BRANCH | `sch_dualpi2.c` **ABSENT** in 6.12.103; mainline 6.17; `l4steam-6.12.y` branch confirmed via ls-remote — the only backport that changes *forwarded* traffic |
| TCP Prague | BACKPORT-BRANCH | zero prague refs in `net/ipv4` (grep); `l4steam-6.12.y` |
| AccECN | BACKPORT-BRANCH | zero accecn refs (grep); mainline 6.20; same branch |
| BBRv2 | OBSOLETE | superseded by v3 (google/bbr); no maintained 6.12 patch |
| EDT VDQ-CSAQM | NO-ARTIFACT | ANRW'20 paper + Ericsson patent + P4 impls; no Linux code — primitives (tc-bpf+EDT+fq) available to prototype |
| ETF/TSN, NIC hw pacing | N/A-HW | no TSN-capable NIC on MT7981 |
| MTK hw QoS | N/A (mainline) | vendor-SDK only; the mainline HW path is flow offload → Rule 2 |

Nothing in this matrix has been applied beyond what NEXT-BUILD denotes;
backports remain documented options only.

## Sources

T-Mobile L4S launch: [T-Mobile newsroom](https://www.t-mobile.com/news/network/unlock-l4s-5g-advanced),
[Mobile World Live](https://www.mobileworldlive.com/t-mobile-us/t-mobile-us-unleashes-l4s-on-5g-advanced/),
[SDxCentral](https://www.sdxcentral.com/news/t-mobile-first-with-wireless-l4s-deployment/) ·
BBRv3: [google/bbr](https://github.com/google/bbr),
[Phoronix](https://www.phoronix.com/news/Google-BBRv3-Linux),
[bbr-dev status thread](https://groups.google.com/g/bbr-dev/c/kQzIeKgLzQ4) ·
L4S/DualPI2: [RFC 9332](https://datatracker.ietf.org/doc/rfc9332/),
[dualpi2 net-next series](https://www.mail-archive.com/linux-kselftest@vger.kernel.org/msg21452.html),
[linux-l4s patch tree](https://github.com/phoepsilonix/linux-l4s),
[DualPI2 characterization paper (2026)](https://arxiv.org/html/2603.04381) ·
[cake-autorate](https://github.com/lynxthecat/cake-autorate) ·
Tree facts (sch_fq in kmod-sched, fq_codel default, pie/fq-pie packaged,
no dualpi2/prague/etf) verified directly against this repo's 25.12 checkout.
