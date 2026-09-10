# QoS / Latency Lab — research notes

Context: GL.iNet GL-X3000, OpenWrt 25.12, kernel **6.12.103**, eBPF/XDP lab
baked (BTF, kprobes, AF_XDP, host-clang BPF toolchain, sqm + qosify + cake +
sched kmods). Researched 2026-09.

**Read this first (2026-09-10).** These notes were begun while the box ran the
QModem vendor `pcie_mhi` stack. It does not any more: the modem is on mainline
`mhi_pci_generic` + `mhi_wwan_mbim` with ModemManager, and the interface is
`wwan0`, not `rmnet_mhi0.1`. Anything below that names rmnet, quectel-CM or
`mhi_netdev_quectel.c` describes a stack this build no longer has - the
downlink MTU black-hole in field log #1 especially. Those findings have not been
re-tested on the MBIM path and should not be acted on until they are.

For the offload, XDP and flow-table material, `xdp-methods-tested.md` is the
newer and more carefully verified document; where the two disagree, that one
wins.

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
Congestion control = **endpoint** tech. `kmod-tcp-bbr` builds the kernel's
`tcp_bbr.c`; enable per-router with
`sysctl net.ipv4.tcp_congestion_control=bbr` (affects router-originated TCP
only). v2 was an alpha branch, superseded. **v3 is out-of-tree** in mainline
as of Sept 2026 — it lives in Google's `google/bbr` branch; upstreaming was
announced in 2023 and has not landed.
**Baked here (2026-09-04):** this fork now carries
`target/linux/mediatek/patches-6.12/990-tcp-bbr3.patch` — the CachyOS/ptr1337
BBRv3 backport — so `kmod-tcp-bbr` builds **v3, not v1**. Verified before
baking: applies to pristine 6.12.103 with **0 rejects** (benign 1–14 line
offsets only), and a file-level overlap sweep against OpenWrt's generic 6.12
patches found the only two shared files (`Kconfig`, `rtnetlink.h`) are
touched in unrelated regions ~240 lines from bbr3's hunks — no context
clash. v1 and v3 cannot coexist in one kernel, so this is a replacement, as
requested. **CC is still endpoint tech: on the router it governs only
router-originated TCP; the win for forwarded client/gaming traffic is set on
those endpoints, not here.** The final apply confirmation is the kernel
build (CI/WSL), which runs the full quilt series then this patch.
**Boot default (found 2026-09-05):** `kmod-tcp-bbr` ships an *active*
`/etc/sysctl.d/12-tcp-bbr.conf`, so `bbr` — now v3 — is the boot default
for router-local TCP (and was, as v1, since vjt's builds); the shipped
`30-tcp-bbr.conf` documents a commented opt-out to CUBIC.

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
4. **BBR** — v3 now baked (990 patch) for router-local TCP; the bigger
   gains for forwarded gaming traffic still belong on the endpoints.
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
   `tcp_bbr.c` in place; v1 and v3 cannot coexist in one kernel. This one
   **is applied** (`990-tcp-bbr3.patch`, 2026-09-04) — a deliberate
   replacement, not a conflict. The other source patches (DualPI2, Prague,
   AccECN, BORE, sched_ext flip) are additive, but any of them changes the
   kernel you ship — they're rebuild decisions, not package adds. Not
   applied.
3. That's it. Nothing else conflicts at bake time.

**Bucket 1 — already baked** (in `config.common` now; in every image
built from it): the entire eBPF/XDP substrate (BTF + BTF-in-modules,
cgroup-BPF, kprobes, perf events, AF_XDP, host BPF toolchain), tc-bpf,
libbpf, bpftool-full, xdp-loader/xdpdump, xdp-sockets-diag, sched-bpf,
full kmod-sched (fq, htb, mq, …) + kmod-sched-cake + ifb, **BBR v3**
(via 990 patch — replaces v1), sqm-scripts + luci, qosify, bash + fping
(cake-autorate's deps — the
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
  (L4STeam `l4steam-6.12.y`), BORE (0 failed hunks on 6.12.103).
  (BBRv3 was in this list; it is now applied — see bucket 1.)

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
# Router-local BBRv3 is the BOOT DEFAULT (kmod-tcp-bbr ships an active
# /etc/sysctl.d/12-tcp-bbr.conf). Verify:
sysctl net.ipv4.tcp_congestion_control        # expect: bbr (= v3 here)
# Opt out to CUBIC: uncomment the line in /etc/sysctl.d/30-tcp-bbr.conf
# (sorts after 12-, so it wins), then `service sysctl restart`.
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
2. **Fast paths and queues — corrected 2026-09-10.** This rule used to say
   HW *and* SW flow offload both skip the qdisc layer. Only half of that is
   true, checked against 6.12.103.
   *Hardware* offload (PPE) and XDP_REDIRECT forwarding do skip it and are
   mutually exclusive with shaping the same path — PPE-bound packets never
   reach the CPU at all.
   *Software* flow offload does **not**. Both of its transmit paths end in
   `dev_queue_xmit()`, which is where the root qdisc runs:
   `FLOW_OFFLOAD_XMIT_NEIGH` goes `neigh_xmit()` -> `neigh->output()` ->
   `dev_queue_xmit()` (`neighbour.c:1570`, `1599`, `1610`), and
   `FLOW_OFFLOAD_XMIT_DIRECT` goes through `nf_flow_queue_xmit()`
   (`nf_flow_table_ip.c:345`). So cake on egress and software flow offload
   compose fine.
   What software offload actually skips is conntrack re-lookup, the
   filter/nat/mangle chains and the routing lookup — everything after
   `nf_ingress` (`dev.c:5664`). Generic XDP (`dev.c:5616`) and tc ingress
   (`dev.c:5656`) both run earlier and are unaffected. XDP
   filtering/observation coexists fine.
3. **Layers compose; semantics can clash.** Endpoint pacing/CC never
   conflicts with middlebox shaping. The one semantic caveat: RFC 3168
   CE-marking (cake) vs L4S ECT(1) flows when cake is the bottleneck.

At bake time, essentially nothing conflicts (only same-binary variants
like tc-tiny/tc-bpf). All real conflicts are runtime, per the rules above.

## Validated support matrix (re-validated 2026-09-04, source-level)

Note (superseded 2026-09-10): **NEXT-BUILD has shipped.** Everything marked
that way below is in the running image and has been for several builds. The
tier names are kept so the evidence column still reads correctly, but read
NEXT-BUILD as "present on the box" from here on.
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
| BBR **v3** (+FQ+BBR combo) | NEXT-BUILD | `990-tcp-bbr3.patch` tracked (replaces v1); `kmod-tcp-bbr=y`; 0 rejects on 6.12.103 + no OpenWrt-generic overlap; router-local flows only |
| EDT via eBPF | NEXT-BUILD | `bpf_skb_set_tstamp` in `filter.c` + uapi; tc-bpf + BTF baked |
| BPF sk-pacing | NEXT-BUILD | `SO_MAX_PACING_RATE` @ `filter.c:5317`; `KERNEL_CGROUP_BPF=y` |
| cake_mq (mq + cake children) | NEXT-BUILD-capable | `sch_mq.c` present + cake; WAN is single-queue → LAN-only technique; mqprio in FEEDS |
| PIE, fq-PIE, RED, DRR, prio, skbprio, mqprio, ctinfo, act-police | FEEDS | in 25.12 feeds; **not baked** (user hold, 2026-09-04); kmods must be baked pre-flash |
| xdp-filter/forward/bench/monitor, bpfcountd, ucode-mod-bpf | FEEDS | same hold |
| sched_ext | CONFIG-FLIP | `kernel/sched/ext.c` PRESENT; `# CONFIG_SCHED_CLASS_EXT is not set`; no packaged scx userspace |
| scx_cake | CONFIG-FLIP + porting | repo requires 6.12+; x86-tuned, Rust loader unpackaged for musl/aarch64 |
| BBRv3 + BPF sk-pacing combo | NEXT-BUILD | v3 baked (row above); sk-pacing via `KERNEL_CGROUP_BPF=y`; compose fine — both endpoint-side |
| BORE | BACKPORT✔ | firelzrd `linux-6.12-bore`: **0 failed hunks vs 6.12.103**; desktop-interactivity tech |
| DualPI2 | BACKPORT-BRANCH | `sch_dualpi2.c` **ABSENT** in 6.12.103; mainline 6.17; `l4steam-6.12.y` branch confirmed via ls-remote — the only backport that changes *forwarded* traffic |
| TCP Prague | BACKPORT-BRANCH | zero prague refs in `net/ipv4` (grep); `l4steam-6.12.y` |
| AccECN | BACKPORT-BRANCH | zero accecn refs (grep); mainline 6.20; same branch |
| BBRv2 | OBSOLETE | superseded by v3 (google/bbr); no maintained 6.12 patch |
| EDT VDQ-CSAQM | NO-ARTIFACT | ANRW'20 paper + Ericsson patent + P4 impls; no Linux code — primitives (tc-bpf+EDT+fq) available to prototype |
| ETF/TSN, NIC hw pacing | N/A-HW | no TSN-capable NIC on MT7981 |
| MTK hw QoS | N/A (mainline) | vendor-SDK only; the mainline HW path is flow offload → Rule 2 |

Applied status, 2026-09-10: everything at NEXT-BUILD is on the box. The
backport rows (BORE, DualPI2, TCP Prague, AccECN) remain documented options
and none has been applied. FEEDS rows are still on the deliberate hold.

## Kernel-level optimization audit (2026-09-05, source-verified)

Audit of build-time kernel optimizations beyond the QoS/eBPF work, each
claim checked against the on-disk tree (`target/linux/generic/config-6.12`,
`target/linux/mediatek/filogic/config-6.12`, the composed `.config`, the
6.12.103 source, and the mediatek patches/dts). No changes applied.

**Already optimal / already aboard — verified, nothing to gain:**

* Kernel compiled **-O2**: `CONFIG_CC_OPTIMIZE_FOR_PERFORMANCE=y` (the
  "router kernels are -Os" folklore does not apply to 25.12).
* Steering fully compiled: `RPS=y, XPS=y, RFS_ACCEL=y, NET_FLOW_LIMIT=y`
  — every runtime balancing knob is backed.
* **WED** (WiFi↔eth hardware dispatch): `NET_MEDIATEK_SOC_WED=y`.
* **Native XDP** in mtk_eth_soc (LAN side; modem rmnet = generic XDP only).
* No cpufreq driver for MT7981 (`# CONFIG_CPU_FREQ is not set`, no OPP
  table in dtsi) → cores run at fixed max clock; there is no governor
  ramp-up latency to eliminate.
* No hidden accounting overhead: `PSI` and `IRQ_TIME_ACCOUNTING` both off.
* **EIP97 hardware crypto engine**: mainline mt7981b.dtsi lacks it, but
  OpenWrt's `117-complete-mt7981b-dtsi.patch` adds
  `crypto@10320000` (`inside-secure,safexcel-eip97`) with **no status
  property → enabled by default**, X3000 inherits it, and
  `kmod-crypto-hw-safexcel=y` is a filogic default already in the image.
  Accelerates AES/SHA (IPsec-class work). Does NOT cover ChaCha20
  (WireGuard). Post-flash check: `grep safexcel /proc/crypto`.

**Config-flip candidates (kernel config edit → rebuild; ON HOLD):**

* **PREEMPT_DYNAMIC** — arm64 supported (`HAVE_PREEMPT_DYNAMIC_KEY`).
  Bake once, then choose `preempt=none|voluntary|full` per boot — the
  platform-ready way to A/B scheduling latency without rebuilds.
  Currently `PREEMPT_NONE=y` (throughput-leaning).
* **PREEMPT_RT** — mainline in exactly this kernel (6.12:
  `kernel/Kconfig.preempt:70`, arm64 `select ARCH_SUPPORTS_RT`). Pure
  config flip, no patchset. Worst-case latency down, peak throughput
  down (softirq/NAPI become threads). Experimental on a router.
* **HZ 100 → 250/1000** — currently `HZ=100`. Modest: fq/cake pacing is
  hrtimer-based already; this only refines the scheduler tick.
* (Adjacent, not kernel) userspace `TARGET_OPTIMIZATION` is `-Os
  -mcpu=cortex-a53`; a global -O2 flip speeds packages, but the datapath
  is kernel-side and unaffected.

**Decision point (vermagic, not performance): WireGuard is NOT in the
image** — all four symbols unset. If WG is ever wanted it must be baked
pre-flash (`kmod-wireguard` auto-pulls the aarch64 NEON
chacha/poly1305 lib kmods, which OpenWrt does package). Post-flash
install is blocked by vermagic like any kmod.

**N/A or not recommended (verified):**

* HW LRO — `MT7981_CAPS` lacks `MTK_HWLRO` (the silicon doesn't have
  it); software GRO, already on, is the equivalent.
* NO_HZ_FULL + isolcpus — on 2 cores, starving housekeeping of CPU0
  hurts more than tick removal helps. Net negative here.
* 16K/64K pages — marginal TLB gains on A53, real ecosystem risk.
* `mitigations=off` — A53 is in-order and reports "Not affected" for
  the expensive vulnerabilities; there is ~nothing to claw back.
* arm64 AES-CE CPU modules — OpenWrt doesn't package them for aarch64
  at all; moot, and EIP97 covers AES offload anyway.

**Verdict:** the 25.12 kernel is already much closer to optimal than
router folklore suggests (-O2, steering compiled, WED, XDP, fixed max
clock, HW crypto quietly enabled). The genuinely new bake-worthy items
are PREEMPT_DYNAMIC (boot-selectable preemption) and the WireGuard
decision; everything else that moves the needle is the runtime layer
already documented above (RPS/affinity/threaded-NAPI vs offload-vs-cake).

### GitHub-ecosystem sweep (2026-09-05)

Checked the out-of-tree fork/feed ecosystem for MT7981 optimizations we
might be missing. Method: directory-diffed ImmortalWrt's
`openwrt-25.12` branch (same kernel 6.12) against this tree, patch by
patch, plus the MediaTek vendor feed.

* **ImmortalWrt 25.12 vs us, `target/linux/mediatek/patches-6.12`:**
  their entire delta is 2 SPI-NAND flash-chip patches + 1 Realtek PHY
  LED patch — zero performance patches. Generic
  hack/pending/backport-6.12 deltas: cpuinfo cosmetics, Motorcomm
  PHY/ethernet drivers (hardware we don't have), regulator infra —
  zero datapath. Meanwhile WE carry `990-tcp-bbr3.patch`, which they
  don't: this tree is *ahead* of the flagship optimization fork.
* **The one real find — fullcone NAT** (`fullconenat` /
  `fullconenat-nft` packages + a firewall4 patch in ImmortalWrt): not
  throughput, but genuinely gaming-relevant — full-cone NAT is what
  yields "Open NAT"/NAT Type A on consoles and better P2P matchmaking
  vs OpenWrt's default masquerade. Portable to this tree; includes a
  kmod → **must be baked pre-flash** (vermagic) if wanted. Tradeoff:
  full-cone deliberately relaxes per-port NAT strictness (that's the
  point); firewall rules still apply. Status: NOT added.
* **MediaTek's own feed** (github.com/mediatek/mtk-openwrt-feeds) —
  the vendor acceleration bits (hw QoS etc.) pin to OpenWrt
  21.02/kernel 5.4 and 24.10/kernel 6.6, not 25.12/6.12: structurally
  incompatible without a large port, and its hw-QoS path is
  runtime-exclusive with cake (Rule 2) anyway. Confirms the existing
  N/A verdict, now with the concrete source.
* **hanwckf-style mt798x forks**: built on MediaTek's older SDK base —
  adopting one means abandoning 6.12/BBRv3/the eBPF platform. A
  different firmware, not a patch to take.

### Deeper pass — driver internals + upstream deltas (2026-09-05)

Second-round audit of layers not previously opened: the vendor MHI
driver's own datapath, PCIe link power management, ethernet interrupt
moderation, the Wi-Fi stack, and a full scan of OpenWrt master's
kernel-6.12 patch queue vs the 25.12 release.

**Already optimal (new confirmations):**

* **PCIe ASPM**: filogic sets `CONFIG_PCIEASPM_PERFORMANCE=y` — ASPM
  effectively disabled by policy, so the RM520N's PCIe link has no
  L0s/L1 exit-latency jitter to remove. (Generic config leaves ASPM
  off entirely; the target overrides to performance.)
* **mtk_eth_soc has DIM** (dynamic interrupt moderation; `DIMLIB=y`,
  25 refs in the driver) — adaptive IRQ coalescing on the ethernet
  side is already active, no manual `ethtool -C` tuning needed.
* `HIGH_RES_TIMERS=y` (pacing/cake hrtimer precision backed).
* Wi-Fi: mac80211's fq_codel + AQL (airtime queue limits) are default
  kernel behavior; and since this build's QoS plan is cake (no HW
  flow-offload), WED won't bypass the Wi-Fi AQM path.

**Genuine findings (candidates — NOT applied):**

1. **Vendor `pcie_mhi` RX path has NO GRO.** Every QMAP-demuxed packet
   is delivered via `netif_receive_skb()` (12 call sites across
   `mhi_netdev*.c`); zero `napi_gro_receive`/`gro_cells` usage.
   **Cross-firmware verdict (verified 2026-09-05):** mainline
   `mhi_net.c` delivers via `__netif_rx()` — no GRO there either; GRO
   exists on the mainline side only when rmnet is layered on top
   (`gro_cells` in rmnet_handlers.c), which vjt's ModemManager/wwan0
   configuration does not do; and stock GL.iNet runs this same
   vendor-driver family (older revision, same RX design). So NONE of
   stock / vjt / vanilla-as-vjt-ran-it does GRO on this modem's RX
   path — the patch would make this build the *first*, not a catch-up.
   (The vendor netdev also advertises no SG/GSO/csum offloads —
   `NETIF_F_VLAN_CHALLENGED` only.) Consequence: per-packet
   stack traversal on cellular downlink — a real CPU-efficiency gap at
   high pps on 2×A53, and a nuance to the earlier vendor-vs-mainline
   "same speed" verdict (vendor wins aggregation/features; mainline
   wins GRO). Patch candidate: convert NAPI-context deliveries to
   `napi_gro_receive()` — a classic small conversion, needs testing.
   Runtime tunables the driver does expose: `poll_weight`,
   `qmap_mode` module params.
2. **mt76 is 5½ months stale on 25.12**: release pins snapshot
   2026-03-19; master is on 2026-09-01, and 25.12 carries zero local
   mt76 patches — so a `PKG_SOURCE_VERSION` bump is a clean,
   package-level candidate for accumulated Wi-Fi fixes/perf.
3. Marginal cherry-pick: master's backport-6.12 carries a safexcel
   (EIP97) authenc-ciphersuite grouping patch (v7.1) — small win for
   the crypto engine only.
4. Boot-arg tier (no rebuild): `threadirqs` (forced-threaded IRQs — a
   latency experiment shy of PREEMPT_RT; confirm effect post-boot via
   `ps | grep irq/`), `pcie_aspm.policy` already moot per above.

**Conclusive negative:** the full master-vs-25.12 diff of generic
`backport-6.12`/`pending-6.12` contains, beyond the above, only
PHY/DSA/PoE driver work for hardware the X3000 doesn't have (Motorcomm,
MaxLinear, Realtek switch/PHY, PSE); a PPPoE-GRO patch matters only on
wired PPPoE WAN; and NO mediatek `patches-6.12` extras exist anywhere
(master moved that target to 6.18). Combined with the ImmortalWrt diff
above: there is no known kernel-datapath patch for this SoC on this
kernel that this tree is missing. The two real opportunities this pass
produced are the **MHI GRO patch** and the **mt76 bump**.

## REVIEW LIST (originated 2026-09-05; STATUS updated — see also the
## reconciliation ledger above, which is authoritative)

| Item | Kind | Status |
|---|---|---|
| MHI-GRO | source patch to vendor driver | HELD — write lever-off + bench before baking |
| PREEMPT_DYNAMIC | kernel config flip | ✅ BAKED (filogic config-6.12) |
| kmod-wireguard | package bake | ✅ BAKED (+tools +luci-proto) |
| safexcel patch | cherry-pick backport | DEFERRED — marginal, IPsec-only |
| threadirqs | boot arg (cmdline) | NOT baked — boot-arg, needs cmdline edit |
| qmodem_monitor | package bake (+luci app) | ✅ BAKED |
| fullcone NAT | package + firewall4 patch (ImmortalWrt) | HELD — patch port, focused step |

Baked beyond the original list: IKCONFIG(+PROC), ply, zram (dormant),
default_qdisc=fq_codel, tcp_sack/dsack, QModem UI→next + adds, MTU
hotplug. Still on the shelf: mt76 bump (behavioral), HZ 250/1000,
PREEMPT_RT, and the QoS backport tiers (DualPI2/Prague/AccECN, sched_ext,
BORE). This config is BUILD-READY as of 2026-09-05.

## Round 3 — runtime, memory & efficiency techniques (2026-09-05)

**Already aboard (verified this round):**

* **MGLRU** (multi-generational LRU, the modern memory-reclaim engine):
  `CONFIG_LRU_GEN=y` + `LRU_GEN_ENABLED=y` — better reclaim behavior
  under memory pressure is already active, nothing to flip.

**Runtime techniques (no rebuild — post-flash cookbook):**

* **cake tuned for cellular** — the biggest practical latency lever in
  this list. On the WAN cake instance: `ack-filter` on the *egress*
  side (verified present in `sch_cake.c`) thins bursts of TCP ACKs on
  the narrow uplink — a classic asymmetric-link win that protects
  game traffic while uploads/downloads run; plus `nat` (post-NAT flow
  hashing), ingress mode on the download shaper, and conservative
  `overhead`/`mpu` for cellular framing. Pair with cake-autorate
  (deps already baked) since 5G bandwidth breathes.
* **IRQ suppression knobs** (pair with threaded NAPI + RPS):
  `/sys/class/net/<dev>/gro_flush_timeout` and `napi_defer_hard_irqs`
  — defer hard interrupts and let NAPI poll batches under load; the
  modern replacement for manual coalescing on single-queue devices
  like the modem netdev.
* **softirq budget sysctls**: `net.core.netdev_budget`,
  `netdev_budget_usecs`, `netdev_max_backlog` — how much RX work each
  softirq round may do; worth touching only if `/proc/net/softnet_stat`
  shows squeezes (column 3 non-zero).
* **UDP GRO for forwarded traffic**: `ethtool -K <dev>
  rx-udp-gro-forwarding on` — batches forwarded UDP (QUIC, some game
  traffic) for CPU efficiency; caveat: micro-batching can add tiny
  hold times, so measure with game traffic before keeping.
* Modem driver module params (`poll_weight`, `qmap_mode`) — exposed by
  the vendor driver for NAPI/aggregation experiments.

**Bake candidates (new this round):**

* **zram-swap** (`kmod-zram` + `zram-swap`; NOT in image — verified):
  compressed RAM swap. On a 512MB-class router this is headroom
  insurance under load spikes (LuCI + collectd + dial + QoS all
  resident) — prevents OOM-kill stalls that read as "lag." Kmod →
  pre-flash decision.
* Micro: userspace `TARGET_OPTIMIZATION` could add `+crc` (hw CRC32
  instructions) to `-mcpu=cortex-a53`; marginal, userspace-only.

**Round-3 negatives:** busy-polling (local-socket tech, not
forwarding), RFS (ditto), dirty-ratio/vm tuning (no meaningful disk
IO), SLUB tuning (no evidence of allocator pressure at router scale).

## Round 4 — search-driven sweep: community + kernel-doc sources (2026-09-05)

**Verified locally this round:**

* The kernel is already **hardening-lean**: `INIT_STACK_NONE=y`,
  init-on-alloc/free off, and `# CONFIG_STACKPROTECTOR is not set` —
  so the folklore "strip hardening for performance" tweaks
  (`init_on_alloc=0` etc.) have literally nothing to strip here.
* `CONFIG_RCU_NOCB_CPU` is **not compiled** — the `rcu_nocbs=` boot
  arg would be inert. RCU callback offload = config-flip tier if ever
  wanted; marginal on 2 cores.

**Community-proven runtime techniques (new; no rebuild needed):**

1. **Wi-Fi AQL tuning — the Wi-Fi analog of cake.** The canonical
   mt76/Filogic latency thread (GL-MT6000, same driver family)
   converged on lowering per-AC airtime queue limits from the default
   5000/12000 to **2500/2500** (some prefer 1500/1500):
   `echo $ac 2500 2500 > /sys/kernel/debug/ieee80211/phy0/aql_txq_limit`
   for ac 0-3, persisted via rc.local; confirmed effective **even
   with WED enabled**. Biggest known Wi-Fi-latency lever on this
   hardware family.
2. **Early-demux trio**: `net.ipv4.ip_early_demux=0`,
   `tcp_early_demux=0`, `udp_early_demux=0` — early demux is a
   per-packet local-socket lookup that is pure waste on a forwarding
   router; disabling saves CPU on every forwarded packet.
3. **Game-friendly conntrack timeouts**: modest
   `nf_conntrack_udp_timeout`(≈60s) so game flows don't rebind
   mid-match; avoid aggressive shortening.
4. **EEE (802.3az) off on gaming ports**: `ethtool --show-eee <lan>`
   post-flash; energy-efficient-ethernet adds wake latency on idle
   links — disable where active. Likewise **pause frames off**
   (`ethtool -A <lan> rx off tx off`) to avoid switch-level
   head-of-line stalls.
5. **NAPI-thread priority** (pairs with threaded NAPI + pinning):
   `chrt -f 15` the `napi/<dev>` kthreads so RX polling outranks
   housekeeping under load. RT-adjacent practice; measure.
6. **Selective/hybrid offload** (advanced): nftables flowtables are
   per-rule — offload only bulk/non-game-DSCP flows while game
   traffic stays in the cake path; partially composes offload with
   shaping (softens Rule 2's either/or).
7. **Cellular MTU sanity**: compare `ip link` MTU on rmnet vs the
   carrier PDP MTU (`AT+CGCONTRDP`); a mismatch causes fragmentation
   jitter. (MSS clamping is already on by default in firewall.)
8. Micro/lore tier: `skew_tick=1` boot arg (tick de-collision; tiny
   on 2 cores), keep logging in tmpfs (logd default — avoid adding
   flash-backed logging on the datapath box).

**Round-4 negatives (checked against this hardware):** "set governor
to schedutil" advice — N/A, no cpufreq exists here (fixed clock);
SFE/shortcut-fe — not packaged in 25.12, superseded by flowtables;
dnsmasq-full/DoH — service hygiene, not datapath latency.

## Round 5 — the wider Linux universe, domain by domain (2026-09-05)

Sweep across the ecosystems where Linux latency/throughput engineering
actually happens (datacenter, telecom/NFV, HFT, realtime, gaming
distros), mapped onto this box. Local claims verified in-tree.

**1. The deepest new track — vendor-driver modernization ladder.**
Evidence: the MHI netdev uses 11 raw `alloc_skb` calls and ZERO
`page_pool` / `build_skb` / `napi_build_skb`; features-wise it
advertises nothing (no SG/GSO/GRO). Modern NIC drivers use a standard
ladder, each step a known technique: (1) `napi_gro_receive` (the
MHI-GRO item), (2) `napi_build_skb` (build skbs around DMA buffers
instead of allocating+copying), (3) `page_pool` recycling (amortize
page alloc/DMA-map per packet), (4) advertise NETIF_F_SG/GRO. Effort
rises per step; combined payoff is the difference between a 2015-style
and a 2025-style driver datapath. Patch-track, on hold.

**2. Toolchain frontier.** Kernel **LTO** exists in 6.12
(`LTO_CLANG` in arch/Kconfig) but requires a clang-built kernel —
invasive under OpenWrt's GCC kbuild; possible, heavy. **AutoFDO +
Propeller** (profile-guided + post-link kernel optimization, ~5-10%
claimed): the MAINLINE kbuild glue landed in **6.13** (verified: zero
refs in 6.12.103) — but the technique itself predates that and the
glue backports: CachyOS shipped AutoFDO kernels on pre-6.13 bases, so
"works on 6.12" is effectively true out-of-tree. For THIS box it is
moot regardless, for two hard reasons: (a) it requires a clang-built
kernel (OpenWrt kbuild is GCC — major surgery, same blocker as LTO);
(b) quality profiles need LBR/SPE-class branch sampling hardware —
SPE is ARMv8.2, and the MT7981's Cortex-A53s are v8.0 (no SPE, no
LBR-equivalent), so a representative kernel profile cannot be
collected from the actual router workload on this CPU. Tier:
inaccessible on this silicon; x86/SPE-capable-server technique today. The old O3 Kconfig is gone from
6.12 (manual KCFLAGS only; lore-tier). `LD_DEAD_CODE_DATA_ELIMINATION`
— already `=y` (verified). BOLT: userspace/research tier.

**3. New runtime knobs (verified present in this source):**
`net.core.gro_normal_batch` (GRO→stack batch size; pairs with
threaded-NAPI/deferred-IRQ tuning); `/sys/kernel/debug/sched/
base_slice_ns` (EEVDF timeslice — shorter = snappier preemption,
measure); `net.netfilter.nf_conntrack_checksum=0` (skip conntrack
csum re-validation, per-packet micro-saving); **console quieting** —
`quiet`/`loglevel=4` on cmdline: printk to a 115200 UART is
synchronous and can stall the box for ms-scale bursts (threaded
printk is only partial in 6.12).

**4. The one real hardening tax found:** `SLAB_FREELIST_HARDENED=y` +
`SLAB_FREELIST_RANDOM=y` (small allocator-path cost). Everything else
is already lean (no lockdep/debug-preempt/PROVE_LOCKING; stack
protector off). Recommendation: KEEP for security; listed for honesty
as the only measurable flip left in this class.

**5. eBPF-native steering labs (platform already supports):** XDP
`cpumap` redirect — steer LAN RX processing to a chosen core at the
XDP layer (native XDP on mtk_eth); AF_XDP userspace fast-path
experiments. Both are what the eBPF platform was baked for.

**6. Endpoint/adjacent tech (named, out of the router's scope):**
MPTCP (bond cellular+other paths — endpoint/proxy technology);
BIG TCP (needs local termination + driver support — not a forwarding
win here); netkit/io_uring zero-copy (container/server tech).

**7. Paradigms surveyed and rejected (the outside-the-box boundary):**
DPDK/VPP userspace dataplanes — no PMD exists for mtk_eth or MHI, a
poll-mode core is unaffordable on 2×A53, and leaving the kernel
forfeits cake/the entire qdisc ecosystem; Snabb/full-userspace XDP —
same economics; RTOS/unikernel dataplane, Rust driver rewrite,
SmartNIC-style CPU offload — no fit on this silicon. Named so the
boundary of the search space is explicit.

**8. Observability = the meta-optimization (bake candidates):** BTF
is already baked, so **`ply`** (a tiny eBPF tracer, ideal for
routers) and optionally `perf` would close the loop — from here on,
real gains come from profiling the flashed device (softirq time,
alloc pressure, IRQ distribution, per-packet cost) rather than from
longer candidate lists. Neither tool is in the image today (verified).

## Field debugging log (post-flash, live hardware)

**#1 — T-Mobile downlink MTU black-hole (2026-09-05, first boot).**
Symptom: `rmnet_mhi0` up, dialed (5G SA, T-Mobile 310/260, APN
`fbb.home` from modem profile, 464XLAT: IPv4 `192.0.0.2/27`), but the
vendor driver floods `drop skb_len=5c8 (1480) larger than qmap
mtu=1472` — full-size downlink packets discarded at
`mhi_netdev_quectel.c:1474` (`skb_len > qmap_net->mtu`). Root cause:
quectel-CM-M reads the QMI runtime-settings MTU (1472) and applies it
(`change mtu 1500 -> 1472`); T-Mobile's real downlink is 1500-class
(1480 IPv4-after-CLAT), so 1472 is too low. Small traffic works, bulk
downloads black-hole (silent drop → no ICMP → PMTUD can't recover).
Fix: force `rmnet_mhi0.1` MTU to 1500 (network already proves ≥1480
by delivering it; MSS-clamp covers uplink). Persistence caveat traced
in-log: quectel-CM only re-applies MTU when current≠1472 at dial time
(2nd dial logged no change because netdev already 1472), so any
override to 1500 WILL be clobbered on the next redial that starts from
1500 → persistence must re-assert AFTER the dial. QModem has no MTU
UCI knob and only a pre_dial hook (too early). Interim: hotplug
iface (ifup/ifupdate) re-assert. Proper Phase-2 fix: patch
quectel-CM-M to honor a configured MTU (or skip lowering), baked.
Status: hotplug PROVEN persistent across redials on hardware
(re-assert logged after quectel-CM's 1472, drop grep clean) and now
BAKED at `files-common/etc/hotplug.d/iface/99-rmnet-mtu`. The deeper
quectel-CM-M honor-configured-MTU source patch stays optional.

**#2 — QModem feed full-package audit → UI swap + feature adds
(2026-09-05).** The feed ships 19 packages beyond the 5 drivers. Build
changes: `luci-app-qmodem-next` REPLACES `luci-app-qmodem` — critical
because the OLD app's Package/config menu *defined* the
driver-selection symbols, so all derived selections are now pinned
directly in config.common (`kmod-qmi_wwan_q/f/s`, `ndisc6`; `pciutils`
and `qfirehose` were already direct). ADDED: `qmodem_monitor` +
`luci-app-qmodem-monitor` (next-family watchdog — review-list item now
baked), `sms-forwarder-next` (hard dep of -next), and
`luci-app-qmodem-ttlfw4` (standalone fw4 TTL, inert until configured).
SKIPPED with reasons: `-sms`/`-mwan`/`-ttl` (hard-depend on the removed
old UI; SMS UI is native in -next), `-hc` (foreign SIM-switch
hardware), `rmnet-nss` (Qualcomm-only), legacy `sms-forwarder`
(superseded), `qmodem-seal` (telemetry — privacy).

**#3 — default_qdisc=fq baked (2026-09-05, user request).**
`files-common/etc/sysctl.d/11-default-qdisc.conf` sets
`net.core.default_qdisc=fq` — the pacing qdisc BBR pairs with. Scope:
only interfaces without an explicit qdisc; the WAN under cake/SQM
overrides it, LAN isn't the bottleneck — so it's a clean win for
router-originated (bbr) TCP with no downside on the shaped paths.

**#4 — AT MTU question CLOSED empirically (2026-09-05).** Full
`AT+QMAP=?` / `AT+QCFG=?` enumeration from the live RM520N shows NO MTU
subcommand in either set (QMAP: WWAN/DMZ/PING/DNS/GRE*/LAN/LANIP/VLAN/
MPDN_rule/IPPT_NAT/connect/auto_connect/AP_rule/SFE/domain/DHCP*DNS/
NAT_timeout/port_mapping; QCFG: incl. data_interface, pcie/mode,
clat, gatewayset, netmaskset — but no mtu). Definitive: this firmware
has no settable modem-side MTU. Host-side hotplug (#1) is the correct
and only mechanism, matching GL.iNet's own approach. Notable extras
seen (not acted on): `AT+QMAP="SFE"` (modem-internal shortcut-forward
engine) and `AT+QCFG="clat"` (464XLAT tuning) — left at firmware
defaults; the connection works.

**BBRv3 runtime-verification note:** on OpenWrt, `modinfo` (busybox
applet) does not print the `version` field and static functions are
absent from `/proc/kallsyms` (no KALLSYMS_ALL), so both earlier checks
came back empty — NOT evidence against v3. The `.modinfo` section is
never stripped (vermagic lives there), so `strings tcp_bbr.ko | grep
version=` reveals the MODULE_VERSION the patch sets (`version=3`). The
canonical proof remains build-time: tcp_bbr.c = 2407 lines +
`fast_ack_mode` in tcp.h, and the flashed .ko was compiled from that
tree.

## Platform-ready batch (2026-09-05) — baked, dormant unless noted

Implemented (all dormant / behavior-unchanged at boot):

* **default_qdisc reverted to fq_codel** (`11-default-qdisc.conf`) — the
  earlier `fq` experiment reversed; fq_codel is the kernel default and
  the better AQM for a forwarding router (cake still owns the WAN).
* **IKCONFIG + IKCONFIG_PROC** (filogic `config-6.12`) — the verification
  backbone: `zcat /proc/config.gz | grep …` now answers "is X really in
  the kernel?" on the live box, permanently. Not OpenWrt-menu-exposed,
  so set directly in the kernel fragment.
* **PREEMPT_DYNAMIC** (filogic `config-6.12`) — boots `preempt=none` as
  today; adds the `preempt=voluntary|full` boot-arg lever with no
  rebuild. arm64 has `HAVE_PREEMPT_DYNAMIC_KEY`. VERIFY it took via
  `zcat /proc/config.gz | grep PREEMPT_DYNAMIC` post-flash (fragment
  flips can be reconciled away by oldconfig; IKCONFIG makes it checkable).
* **WireGuard platform-ready** — `kmod-wireguard` (+NEON crypto auto),
  `wireguard-tools`, `luci-proto-wireguard`; inert until a tunnel is
  configured. Vermagic-locked, hence bake-now-or-never.
* **ply** — eBPF/BTF dynamic tracer; dormant CLI tool, the measurement
  companion to the baked BTF.
* **zram** — `kmod-zram` + `zram-swap`, shipped DISABLED via
  `uci-defaults/99-zram-disabled` (package auto-enables otherwise).
  Enable: `/etc/init.d/zram enable && service zram start`.
* **TCP SACK/DSACK explicit pin** (`20-tcp-tuning.conf`) — both are
  kernel defaults (SACK is core TCP, not a build option, so it was never
  missing); pinned explicitly for the router's own TCP on the lossy 5G
  uplink. Endpoint-only, like BBR. `tcp_fack` deliberately omitted
  (removed from modern kernels; RACK-TLP is the default successor).

**Reconciliation ledger (2026-09-05) — status of everything discussed:**
BAKED: QModem UI→next + feature adds, MTU hotplug, IKCONFIG(+PROC),
PREEMPT_DYNAMIC, WireGuard, ply, zram(dormant), default_qdisc=fq_codel,
tcp_sack/dsack, qmodem_monitor, BBRv3, full eBPF/XDP/QoS platform.
HELD (deliberate, need a focused/tested pass): mt76 bump (behavioral),
fullcone NAT (firewall4 patch port). MHI-GRO left this list on 2026-09-08 —
see below. DEFERRED-marginal: safexcel authenc grouping
(IPsec-only micro-opt on the already-present EIP97 engine). RUNTIME/
boot-arg, by-design not baked (apply + measure post-baseline): the whole
cookbook — cake+autorate, cake ack-filter, Wi-Fi AQL, RPS/threaded-NAPI/
IRQ-affinity, early-demux, EEE/pause-frame off, gro_flush_timeout, and
the boot-args threadirqs/skew_tick/console-quiet (cmdline-only on this
device; PREEMPT_DYNAMIC by contrast has a runtime debugfs toggle).

Held for a deliberate/tested pass (NOT in this batch, with reasons):

* **mt76 bump** — swaps the Wi-Fi driver to a newer snapshot; behavioral
  (not dormant), so it deserves its own build to isolate any regression.
  Needs a `PKG_SOURCE_VERSION`/`MIRROR_HASH` change.

  Assessed 2026-09-10 against the pin (`39c960c3ada5`, 2026-03-19). Diffing
  the eleven files that matter for this board - `mt7915/{soc,mmio,mac,init,main}.c`,
  `mac80211.c`, `dma.c`, `wed.c`, `tx.c`, `agg-rx.c`, `mt76.h` - gives about
  400 changed lines, and the content is mostly **fixes**, which raises the
  value of the bump:

  - `wed.c`: WED v2 uses `MT_RXQ_MAIN` for every band on the pin; upstream now
    selects `MT_RXQ_BAND1` when `wed->version == 2 && dev->phy.band_idx`.
    MT7981 is WED v2 **and** DBDC, so enabling WED on the current pin would
    misconfigure band 1. This gates #99: bump before testing WED, or the test
    measures a known-buggy configuration.
  - `dma.c`: clamps an out-of-range DMA index, because "a hung bus (e.g. after
    a PCIe AER error) reads 0xffffffff from every register" and would otherwise
    corrupt `q->head`/`q->tail`. The Wi-Fi is SoC-internal here rather than
    PCIe, so this specific trigger does not apply, but it is real hardening.
  - `mt7915/mac.c`: RSSI chain 3 read `GENMASK(31, 14)` where it should be
    `GENMASK(31, 24)`; `tx_retries = count - 1` underflowed to 0xFFFFFFFF when
    count was zero; new PLE hardware-hang detection
    (`MT_SWDEF_PLE1_MDP_RIOC_HANG_ERR`); reset path now uses
    `test_and_clear_bit` and wakes queues.
  - `mac80211.c`: `ieee80211_is_first_frag()` was passed `hdr->frame_control`
    where `hdr->seq_ctrl` was intended; wcid publish is now guarded against a
    double-publish with `WARN_ON_ONCE`.
  - Behaviour change to isolate: `MT_DRV_HW_PS_BUFFERING` plus new power-save
    buffering in `tx.c` and a UAPSD EOSP fix - this alters handling for
    power-saving clients.

  Caveats on that assessment: it covers eleven files, not the whole tree, and
  it was taken against `master`, which moves. An actual bump means choosing a
  specific commit, and some of these changes are recent enough not to be
  battle-tested.
* **MHI-GRO — DONE, and this entry was stale.** It is patch 991,
  `991-net-wwan-mhi_wwan_mbim-gro-cells-rx.patch`: written, built, flashed and
  running, with 992 (native XDP via `do_xdp_generic`) and 993 (the MHI doorbell
  fix) stacked on top of it. It did not stay lever-off/ethtool-gated as planned;
  it is unconditional. Two later findings matter for anyone reading this row:
  cpumap redirect bypasses gro_cells entirely and so discards what 991 buys,
  while RPS runs *after* gro_cells and keeps it. Both are written up in
  `xdp-methods-tested.md` section 14.
* **fullcone NAT** — requires porting ImmortalWrt's firewall4 patch +
  `fullconenat-nft`; a firewall-behavior change worth doing as a focused
  step. Console/P2P "Open NAT" value.

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

## Branch state (2026-09-06): lean tree

`openwrt-25.12` was reset to **vjt's latest tree + the lean optimization
overlay** — see `x3000/docs/lean-overlay.md` for the exact contents and
verification. QModem, qosify, sqm, zram, the modem-stack toggle and the
rmnet MTU hotplug from the sections above are gone from this branch;
they remain in git history (`ec64d13e08` and earlier). The research and
field findings above stay valid as reference — the QModem-specific fixes
(#1 MTU, #2 driver audit, #4 AT-MTU) do not apply to the ModemManager/
MBIM data path this tree now builds.
