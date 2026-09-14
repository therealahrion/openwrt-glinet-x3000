// SPDX-License-Identifier: GPL-2.0
/*
 * Flowtable-driven XDP fast path for the modem interface.
 *
 * Two programs. Attach the probe first: it answers the question this tree has
 * asked since section 16.5 and never tested, which is whether
 * bpf_xdp_flow_lookup() actually hits on wwan0. Only once it does is the
 * fastpath worth loading.
 *
 *   xdp_ft_probe     lookup, count, XDP_PASS. Changes nothing.
 *   xdp_ft_fastpath  lookup, NAT rewrite, build L2, XDP_REDIRECT.
 *
 * Why this can work here at all, each point read from v6.12.103:
 *
 *   - The kfunc exists. nf_flow_table_bpf.o is gated on DEBUG_INFO_BTF_MODULES
 *     (net/netfilter/Makefile) and this build sets it.
 *   - The device is in the XDP hashtable. nf_flow_table_offload_setup() takes
 *     the nf_flow_offload_xdp_setup() branch only while hardware offload is
 *     OFF (nf_flow_table_offload.c:1258), so keep the firewall dropdown on
 *     software flow offloading. Hardware offload makes every lookup -ENOENT.
 *   - wwan0 reaches the flowtable at all only because of this tree's firewall4
 *     patch 001-flowtable-fall-back-to-l3-device. Stock fw4 builds the device
 *     list from ifc.device, and a proto modemmanager interface has only
 *     l3_device.
 *   - The lookup resolves the device from xdp->rxq->dev. On wwan0 that is the
 *     real netdev: patch 992 runs the program through do_xdp_generic(), whose
 *     rxq comes from netif_get_rxqueue(skb) (dev.c:5079). On the wired ports it
 *     would be eth->dummy_dev and every lookup would miss - which is why this
 *     program is for wwan0 and nowhere else.
 *   - The redirect target must advertise NETDEV_XDP_ACT_NDO_XMIT
 *     (devmap.c:488). The mtk netdevs do; wwan0 and the AP netdevs do not.
 *     So eth1 and eth0 are legal targets and each other's peers are not.
 *
 * The packet has no Ethernet header. wwan0 is ARPHRD_RAWIP with hard_header_len
 * 0, and 991 anchors mac_header at skb->data, so do_xdp_generic() computes
 * mac_len 0 and the IP header sits at ctx->data. A program written against
 * ethhdr - including the in-tree selftest this is modelled on - reads the first
 * two octets of the source address as an EtherType here.
 *
 * NAT semantics are taken from nf_flow_snat_ip() / nf_flow_dnat_ip() in
 * net/netfilter/nf_flow_table_ip.c, not from reasoning about conntrack.
 *
 * IPv4 only, deliberately: the rewrite for v6 is a different function and
 * getting one right is worth more than getting two nearly right.
 *
 * That decision was sound and, on this link, it picked the wrong family.
 * Measured 2026-09-14: this WAN is 464XLAT with the CLAT inside the modem, the
 * carrier resolvers do DNS64, and every dual-stack client therefore chooses
 * IPv6. Over a 30-second speedtest IPv4 was 44 of 5373 IP-layer receives -
 * 0.8%. So this program, working perfectly, would accelerate under one percent
 * of what crosses the link.
 *
 * The v6 version is also the easier one, which is the part that makes this
 * worth fixing rather than regretting. bpf_xdp_flow_lookup() already has a
 * case AF_INET6 arm filling src_v6/dst_v6, so the lookup needs no change; and
 * native IPv6 has no NAT, so the whole address and port rewrite below - and
 * every checksum it has to repair - simply does not exist. Decrement
 * hop_limit, build L2, redirect. The one failure mode that can silently break
 * a user's connections is absent from it.
 *
 * See xdp-methods-tested.md section 23.11.
 */

#define BPF_NO_KFUNC_PROTOTYPES
#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>

#define ETH_P_IP	0x0800
#define ETH_ALEN	6
#define IP_MF		0x2000
#define IP_OFFSET	0x1fff
#define AF_INET		2
#define IPPROTO_TCP	6
#define IPPROTO_UDP	17

#define FLOW_OFFLOAD_DIR_ORIGINAL	0
#define FLOW_OFFLOAD_DIR_REPLY		1
#define FLOW_OFFLOAD_XMIT_DIRECT	3

/* enum nf_flow_flags bit positions, include/net/netfilter/nf_flow_table.h */
#define NF_FLOW_SNAT	0
#define NF_FLOW_DNAT	1
#define NF_FLOW_TEARDOWN 2

struct ethhdr_ {
	__u8	h_dest[ETH_ALEN];
	__u8	h_source[ETH_ALEN];
	__be16	h_proto;
} __attribute__((packed));

struct iphdr_ {
	__u8	ihl_version;
	__u8	tos;
	__be16	tot_len;
	__be16	id;
	__be16	frag_off;
	__u8	ttl;
	__u8	protocol;
	__sum16	check;
	__be32	saddr;
	__be32	daddr;
} __attribute__((packed));

struct ports_ {
	__be16	source;
	__be16	dest;
} __attribute__((packed));

struct tcpflags_ {
	__be32	seq_ack[4];	/* seq, ack_seq, then the flags word */
} __attribute__((packed));

/* Kernel types, matched by name for CO-RE. Only the fields this program reads
 * are declared; preserve_access_index makes libbpf relocate every offset from
 * the running kernel's BTF, so a layout change upstream is a load failure and
 * not silent corruption.
 */
struct in_addr___local { __be32 s_addr; };
struct in6_addr___local { __u8 s6_addr[16]; };

/* Mirrors struct flow_offload_tuple field for field, including the anonymous
 * unions and the bitfield word, because CO-RE relocates by name and a name that
 * sits in the wrong container does not resolve.
 */
struct flow_offload_tuple___local {
	union {
		struct in_addr___local	src_v4;
		struct in6_addr___local	src_v6;
	};
	union {
		struct in_addr___local	dst_v4;
		struct in6_addr___local	dst_v6;
	};
	struct {
		__be16		src_port;
		__be16		dst_port;
	};
	int			iifidx;
	__u8			l3proto;
	__u8			l4proto;
	struct {
		__u16		id;
		__be16		proto;
	} encap[2];
	struct { }		__hash;
	__u8			dir:2,
				xmit_type:3,
				encap_num:2,
				in_vlan_ingress:2;
	__u16			mtu;
	union {
		struct {
			void	*dst_cache;
			__u32	dst_cookie;
		};
		struct {
			__u32	ifidx;
			__u32	hw_ifidx;
			__u8	h_source[ETH_ALEN];
			__u8	h_dest[ETH_ALEN];
		} out;
		struct {
			__u32	iifidx;
		} tc;
	};
} __attribute__((preserve_access_index));

struct rhash_head___local {
	void *next;
};

struct flow_offload_tuple_rhash___local {
	struct rhash_head___local		node;
	struct flow_offload_tuple___local	tuple;
} __attribute__((preserve_access_index));

struct flow_offload___local {
	struct flow_offload_tuple_rhash___local tuplehash[2];
	void		*ct;
	unsigned long	flags;
	__u16		type;
	__u32		timeout;
} __attribute__((preserve_access_index));

struct bpf_flowtable_opts___local {
	__s32 error;
};

struct flow_offload_tuple_rhash___local *
bpf_xdp_flow_lookup(struct xdp_md *, struct bpf_fib_lookup *,
		    struct bpf_flowtable_opts___local *, __u32) __ksym;

/* Every exit the decision path can take gets its own slot, so a dry run
 * accounts for all of seen rather than leaving a remainder to guess at.
 *
 * The parse failures are split rather than pooled, and that is not cosmetic: a
 * run where the traffic turned out to be IPv6 showed 145880 of 146062 in a
 * single parse_skip slot and took a whole cycle to diagnose, when a not_ipv4
 * counter would have said so on sight.
 */
enum stat_slot {
	ST_SEEN = 0,
	ST_NOT_IPV4,
	ST_FRAG_OR_OPTS,
	ST_NOT_TCP_UDP,
	ST_SHORT,
	ST_LOW_TTL,
	ST_TCP_TEARDOWN,
	ST_MISS,
	ST_HIT,
	ST_BAD_DIR,
	ST_TORN_DOWN,
	ST_NOT_DIRECT,
	ST_NO_OUT_IFIDX,
	ST_READ_ERR,
	ST_WOULD_REDIRECT,
	ST_NO_HEADROOM,
	ST_REDIRECT,
	ST__MAX,
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, ST__MAX);
} xdp_ft_stats SEC(".maps");

static __always_inline void bump(__u32 slot)
{
	__u64 *v = bpf_map_lookup_elem(&xdp_ft_stats, &slot);

	if (v)
		*v += 1;
}

/* One's-complement helpers. Applied consistently to network-order 16-bit
 * words, so no endian conversion is needed or wanted.
 */
static __always_inline __u16 csum_fold(__u32 sum)
{
	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);
	return (__u16)~sum;
}

static __always_inline __u16 csum_replace4(__u16 old_csum, __be32 from, __be32 to)
{
	__u32 sum = (__u32)(__u16)~old_csum;

	sum += (__u16)~(__u16)(from >> 16);
	sum += (__u16)~(__u16)(from & 0xffff);
	sum += (__u16)(to >> 16);
	sum += (__u16)(to & 0xffff);
	return csum_fold(sum);
}

static __always_inline __u16 csum_replace2(__u16 old_csum, __be16 from, __be16 to)
{
	__u32 sum = (__u32)(__u16)~old_csum;

	sum += (__u16)~from;
	sum += (__u16)to;
	return csum_fold(sum);
}

struct parsed {
	struct iphdr_	*iph;
	struct ports_	*ports;
	void		*data_end;
};

/* Parse a raw-IP packet at ctx->data. Returns 0 on "worth looking up". */
/* Returns 0, or the counter slot naming which check rejected the packet. The
 * caller bumps it, so every rejection is attributable rather than pooled.
 */
static __always_inline int parse_rawip(struct xdp_md *ctx, struct parsed *p)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct iphdr_ *iph = data;
	struct ports_ *ports;

	if ((void *)(iph + 1) > data_end)
		return ST_SHORT;

	/* Raw IP: the version nibble is the only thing identifying the family.
	 * This is the counter that says a window measured IPv6 and nothing else.
	 */
	if ((iph->ihl_version >> 4) != 4)
		return ST_NOT_IPV4;

	/* Options change the L4 offset; the flowtable declines these too. */
	if ((iph->ihl_version & 0x0f) != 5)
		return ST_FRAG_OR_OPTS;

	if (iph->frag_off & bpf_htons(IP_MF | IP_OFFSET))
		return ST_FRAG_OR_OPTS;

	/* Forwarding decrements; 1 would have to become 0. */
	if (iph->ttl <= 1)
		return ST_LOW_TTL;

	if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP)
		return ST_NOT_TCP_UDP;

	ports = (struct ports_ *)(iph + 1);
	if ((void *)(ports + 1) > data_end)
		return ST_SHORT;

	p->iph = iph;
	p->ports = ports;
	p->data_end = data_end;
	return 0;
}

static __always_inline struct flow_offload_tuple_rhash___local *
do_lookup(struct xdp_md *ctx, struct parsed *p)
{
	struct bpf_flowtable_opts___local opts = {};
	struct bpf_fib_lookup tuple = {
		.ifindex	= ctx->ingress_ifindex,
		.family		= AF_INET,
	};

	tuple.tos		= p->iph->tos;
	tuple.l4_protocol	= p->iph->protocol;
	tuple.tot_len		= bpf_ntohs(p->iph->tot_len);
	tuple.ipv4_src		= p->iph->saddr;
	tuple.ipv4_dst		= p->iph->daddr;
	tuple.sport		= p->ports->source;
	tuple.dport		= p->ports->dest;

	return bpf_xdp_flow_lookup(ctx, &tuple, &opts, sizeof(opts));
}

/* Everything the commit stage needs, gathered while the packet is still
 * untouched.
 */
struct decision {
	struct flow_offload_tuple_rhash___local *other;
	unsigned long	flags;
	__u32		out_ifidx;
	__u8		h_dest[ETH_ALEN];
	__u8		h_source[ETH_ALEN];
	__be32		snat_addr, dnat_addr;
	__be16		snat_port, dnat_port;
	__u8		dir;
};

/* Rewrite one address and port pair and repair both checksums.
 *
 * The L4 checksum covers the pseudo-header address as well as the port, so
 * both deltas apply to it. A UDP checksum of zero means "not computed" and has
 * to stay zero; TCP has no such case.
 */
static __always_inline void xlate(struct parsed *p, __be32 *addr_field,
				  __be16 *port_field, __be32 new_addr,
				  __be16 new_port)
{
	__be32 old_addr = *addr_field;
	__be16 old_port = *port_field;
	__u16 *l4c;

	*addr_field = new_addr;
	*port_field = new_port;
	p->iph->check = csum_replace4(p->iph->check, old_addr, new_addr);

	l4c = (p->iph->protocol == IPPROTO_TCP)
	    ? (__u16 *)((__u8 *)p->ports + 16)
	    : (__u16 *)((__u8 *)p->ports + 6);

	if ((void *)(l4c + 1) <= p->data_end &&
	    (p->iph->protocol == IPPROTO_TCP || *l4c)) {
		__u16 c = csum_replace4(*l4c, old_addr, new_addr);

		*l4c = csum_replace2(c, old_port, new_port);
	}
}

/* Decide whether this packet can be accelerated, and read everything needed to
 * do it. Returns 0 when it can.
 *
 * Nothing here writes to the packet, and that is the point: every read through
 * the flow is a probe read of a computed address and can fail. A failure after
 * the rewrite had begun would put a half-translated packet on the stack, which
 * is worse than not accelerating the flow at all. So the whole decision is made
 * and every value gathered first, and the commit stage that follows cannot
 * fail.
 *
 * Every exit is counted here rather than in the callers, so the dry run and the
 * real path are guaranteed to be counting the same thing.
 */
static __always_inline int decide(struct xdp_md *ctx, struct parsed *p,
				  struct decision *d)
{
	struct flow_offload_tuple_rhash___local *th, *other;
	struct flow_offload___local *flow;
	__u8 xmit;
	__u32 hsz;
	int rc;

	rc = parse_rawip(ctx, p);
	if (rc) {
		bump(rc);
		return -1;
	}

	/* TCP teardown must reach conntrack, so hand FIN and RST to the stack.
	 * nf_flow_state_check() does the same and additionally tears the flow
	 * down; this program cannot, so the stack's copy of the check is what
	 * retires it.
	 */
	if (p->iph->protocol == IPPROTO_TCP) {
		__u8 *flagsb = (__u8 *)p->ports + 13;

		if ((void *)(flagsb + 1) > p->data_end) {
			bump(ST_SHORT);
			return -1;
		}
		if (*flagsb & 0x05) {		/* FIN | RST */
			bump(ST_TCP_TEARDOWN);
			return -1;
		}
	}

	th = do_lookup(ctx, p);
	if (!th) {
		bump(ST_MISS);
		return -1;
	}
	bump(ST_HIT);

	d->dir = BPF_CORE_READ_BITFIELD_PROBED(&th->tuple, dir);
	if (d->dir > FLOW_OFFLOAD_DIR_REPLY) {
		bump(ST_BAD_DIR);
		return -1;
	}

	/* tuplehash[] is the first member of struct flow_offload, so the flow is
	 * the matched hash minus dir entries. container_of, by hand.
	 *
	 * There is deliberately no bpf_rdonly_cast() here. The cast existed to
	 * make this computed pointer trusted enough to dereference, but nothing
	 * below dereferences it: every read goes through bpf_core_read(), which
	 * is bpf_probe_read_kernel() and takes an arbitrary kernel address.
	 * probe_read_kernel is reachable from XDP under CAP_PERFMON
	 * (kernel/bpf/helpers.c, bpf_base_func_proto), which root has.
	 *
	 * The cast needed bpf_core_type_id_kernel(), and that TYPE_ID_TARGET
	 * relocation was the single relocation libbpf could not resolve here:
	 *
	 *   libbpf: relo #7: relocation decision ambiguity: success 90056 != success 90242
	 *
	 * struct flow_offload is defined in four loaded BTFs on this box -
	 * nf_flow_table, nf_flow_table_inet, nf_tables and nft_flow_offload.
	 * The definitions agree on field offsets, so every FIELD_* relocation
	 * resolves and libbpf's bit_offset check (relo_core.c:1361) passes; but
	 * a type id is an index into one particular BTF, so the candidates can
	 * never agree and relo_core.c:1369 rejects the object.
	 *
	 * Written as a branch on dir with constant offsets, rather than as
	 * arithmetic on dir, because the verifier cannot carry a bound through a
	 * multiply by a negative constant. `dir * -hsz` on a register it knows
	 * to hold 0..3 comes back with smin at S64_MIN, and
	 * check_reg_sane_offset() rejects pointer math against an unbounded
	 * minimum:
	 *
	 *   173: (27) r1 *= -88
	 *   175: (0f) r3 += r1
	 *   math between ptr_ pointer and register with unbounded min value is not allowed
	 *
	 * The same function explicitly permits a known constant offset, negative
	 * included, so each arm of the branch passes. The dir <= 1 test above
	 * does not help on its own: llvm applies it to a copy of the register,
	 * and the masking in between breaks the link back to the original.
	 *
	 * hsz is relocated rather than taken from sizeof(). The local mirrors
	 * are only as right as the header they were copied from, and a wrong
	 * size here would walk to the wrong address silently. A TYPE_SIZE
	 * relocation is safe where the type-id one was not, for the same reason
	 * the field relocations are: its value comes from the layout, which
	 * every candidate agrees on, not from an index into one BTF. Measured on
	 * this kernel it is 88, which is what the local mirror computes - so the
	 * old sizeof() was right, and is now checked rather than assumed.
	 */
	hsz = bpf_core_type_size(struct flow_offload_tuple_rhash___local);
	if (!hsz) {
		bump(ST_READ_ERR);
		return -1;
	}

	if (d->dir == FLOW_OFFLOAD_DIR_ORIGINAL) {
		/* th is tuplehash[0], so it already sits at the flow's base and
		 * the peer is the slot after it.
		 */
		flow  = (struct flow_offload___local *)th;
		other = (struct flow_offload_tuple_rhash___local *)
			((char *)th + hsz);
	} else {
		/* th is tuplehash[1]; base and peer are both one slot back. */
		flow  = (struct flow_offload___local *)((char *)th - hsz);
		other = (struct flow_offload_tuple_rhash___local *)
			((char *)th - hsz);
	}
	d->other = other;

	if (bpf_core_read(&d->flags, sizeof(d->flags), &flow->flags)) {
		bump(ST_READ_ERR);
		return -1;
	}
	if (d->flags & (1UL << NF_FLOW_TEARDOWN)) {
		bump(ST_TORN_DOWN);
		return -1;
	}

	/* Egress. Only the direct form carries the addresses required; NEIGH
	 * would need a neighbour lookup this program cannot do, so those flows
	 * stay on the stack's fast path where dst_cache handles them.
	 */
	xmit = BPF_CORE_READ_BITFIELD_PROBED(&th->tuple, xmit_type);
	if (xmit != FLOW_OFFLOAD_XMIT_DIRECT) {
		bump(ST_NOT_DIRECT);
		return -1;
	}

	if (bpf_core_read(&d->out_ifidx, sizeof(d->out_ifidx),
			  &th->tuple.out.ifidx) ||
	    bpf_core_read(&d->h_dest, sizeof(d->h_dest),
			  &th->tuple.out.h_dest) ||
	    bpf_core_read(&d->h_source, sizeof(d->h_source),
			  &th->tuple.out.h_source)) {
		bump(ST_READ_ERR);
		return -1;
	}
	if (!d->out_ifidx) {
		bump(ST_NO_OUT_IFIDX);
		return -1;
	}

	/* The translated address and port for whichever directions apply, taken
	 * from the peer tuple exactly as nf_flow_snat_ip() and nf_flow_dnat_ip()
	 * do it.
	 */
	if (d->flags & (1UL << NF_FLOW_SNAT)) {
		if (d->dir == FLOW_OFFLOAD_DIR_ORIGINAL) {
			if (bpf_core_read(&d->snat_addr, sizeof(d->snat_addr),
					  &other->tuple.dst_v4.s_addr) ||
			    bpf_core_read(&d->snat_port, sizeof(d->snat_port),
					  &other->tuple.dst_port)) {
				bump(ST_READ_ERR);
				return -1;
			}
		} else {
			if (bpf_core_read(&d->snat_addr, sizeof(d->snat_addr),
					  &other->tuple.src_v4.s_addr) ||
			    bpf_core_read(&d->snat_port, sizeof(d->snat_port),
					  &other->tuple.src_port)) {
				bump(ST_READ_ERR);
				return -1;
			}
		}
	}

	if (d->flags & (1UL << NF_FLOW_DNAT)) {
		if (d->dir == FLOW_OFFLOAD_DIR_ORIGINAL) {
			if (bpf_core_read(&d->dnat_addr, sizeof(d->dnat_addr),
					  &other->tuple.src_v4.s_addr) ||
			    bpf_core_read(&d->dnat_port, sizeof(d->dnat_port),
					  &other->tuple.src_port)) {
				bump(ST_READ_ERR);
				return -1;
			}
		} else {
			if (bpf_core_read(&d->dnat_addr, sizeof(d->dnat_addr),
					  &other->tuple.dst_v4.s_addr) ||
			    bpf_core_read(&d->dnat_port, sizeof(d->dnat_port),
					  &other->tuple.dst_port)) {
				bump(ST_READ_ERR);
				return -1;
			}
		}
	}

	return 0;
}

/* Apply the translation and decrement the TTL. Nothing here can fail, because
 * every value it uses was read by decide() before the packet was touched.
 */
static __always_inline void commit(struct parsed *p, struct decision *d)
{
	if (d->flags & (1UL << NF_FLOW_SNAT)) {
		if (d->dir == FLOW_OFFLOAD_DIR_ORIGINAL)
			xlate(p, &p->iph->saddr, &p->ports->source,
			      d->snat_addr, d->snat_port);
		else
			xlate(p, &p->iph->daddr, &p->ports->dest,
			      d->snat_addr, d->snat_port);
	}

	if (d->flags & (1UL << NF_FLOW_DNAT)) {
		if (d->dir == FLOW_OFFLOAD_DIR_ORIGINAL)
			xlate(p, &p->iph->daddr, &p->ports->dest,
			      d->dnat_addr, d->dnat_port);
		else
			xlate(p, &p->iph->saddr, &p->ports->source,
			      d->dnat_addr, d->dnat_port);
	}

	/* TTL, per ip_decrease_ttl(): decrement and repair the header checksum. */
	{
		__be16 old_ttl_proto = *(__be16 *)&p->iph->ttl;

		p->iph->ttl -= 1;
		p->iph->check = csum_replace2(p->iph->check, old_ttl_proto,
					      *(__be16 *)&p->iph->ttl);
	}
}

SEC("xdp.frags")
int xdp_ft_probe(struct xdp_md *ctx)
{
	struct flow_offload_tuple_rhash___local *th;
	struct parsed p;
	int rc;

	bump(ST_SEEN);

	rc = parse_rawip(ctx, &p);
	if (rc) {
		bump(rc);
		return XDP_PASS;
	}

	th = do_lookup(ctx, &p);
	bump(th ? ST_HIT : ST_MISS);

	return XDP_PASS;
}

/* Everything the fastpath does, up to but not including the first byte
 * written. Attaching this answers the only question that decides whether the
 * rewrite is worth running at all - what share of the traffic is a flow this
 * program could actually carry - and it cannot break a connection, because it
 * never touches a packet.
 */
SEC("xdp.frags")
int xdp_ft_dryrun(struct xdp_md *ctx)
{
	struct decision d = {};
	struct parsed p;

	bump(ST_SEEN);

	if (decide(ctx, &p, &d))
		return XDP_PASS;

	bump(ST_WOULD_REDIRECT);
	return XDP_PASS;
}

SEC("xdp.frags")
int xdp_ft_fastpath(struct xdp_md *ctx)
{
	struct decision d = {};
	struct ethhdr_ *eth;
	struct parsed p;
	void *data_end;

	bump(ST_SEEN);

	if (decide(ctx, &p, &d))
		return XDP_PASS;

	commit(&p, &d);

	/* Grow an Ethernet header in front. XDP_PACKET_HEADROOM is 256 and
	 * do_xdp_generic() guarantees it before running the program, so this
	 * should not fail - but a failure here would send a headerless frame out
	 * a wired port, so it is checked rather than assumed.
	 */
	if (bpf_xdp_adjust_head(ctx, -(int)sizeof(struct ethhdr_))) {
		bump(ST_NO_HEADROOM);
		return XDP_PASS;
	}

	data_end = (void *)(long)ctx->data_end;
	eth = (void *)(long)ctx->data;
	if ((void *)(eth + 1) > data_end)
		return XDP_DROP;	/* cannot PASS: the header is half-built */

	__builtin_memcpy(eth->h_dest, d.h_dest, ETH_ALEN);
	__builtin_memcpy(eth->h_source, d.h_source, ETH_ALEN);
	eth->h_proto = bpf_htons(ETH_P_IP);

	bump(ST_REDIRECT);
	return bpf_redirect(d.out_ifidx, 0);
}

char _license[] SEC("license") = "GPL";
