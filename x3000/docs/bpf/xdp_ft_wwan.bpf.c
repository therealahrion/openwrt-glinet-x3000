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

/* kernel/bpf/helpers.c - turns a computed address back into something the
 * verifier will let us read. Needed because container_of() on the returned
 * tuplehash produces a pointer the verifier no longer trusts.
 */
extern void *bpf_rdonly_cast(const void *obj, __u32 btf_id) __ksym;

enum stat_slot {
	ST_SEEN = 0,
	ST_PARSE_SKIP,
	ST_MISS,
	ST_HIT,
	ST_NOT_DIRECT,
	ST_TORN_DOWN,
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
static __always_inline int parse_rawip(struct xdp_md *ctx, struct parsed *p)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct iphdr_ *iph = data;
	struct ports_ *ports;

	if ((void *)(iph + 1) > data_end)
		return -1;

	/* Raw IP: the version nibble is the only thing identifying the family. */
	if ((iph->ihl_version >> 4) != 4)
		return -1;

	/* Options change the L4 offset; the flowtable declines these too. */
	if ((iph->ihl_version & 0x0f) != 5)
		return -1;

	if (iph->frag_off & bpf_htons(IP_MF | IP_OFFSET))
		return -1;

	/* Forwarding decrements; 1 would have to become 0. */
	if (iph->ttl <= 1)
		return -1;

	if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP)
		return -1;

	ports = (struct ports_ *)(iph + 1);
	if ((void *)(ports + 1) > data_end)
		return -1;

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

SEC("xdp.frags")
int xdp_ft_probe(struct xdp_md *ctx)
{
	struct flow_offload_tuple_rhash___local *th;
	struct parsed p;

	bump(ST_SEEN);

	if (parse_rawip(ctx, &p)) {
		bump(ST_PARSE_SKIP);
		return XDP_PASS;
	}

	th = do_lookup(ctx, &p);
	bump(th ? ST_HIT : ST_MISS);

	return XDP_PASS;
}

SEC("xdp.frags")
int xdp_ft_fastpath(struct xdp_md *ctx)
{
	struct flow_offload_tuple_rhash___local *th, *other;
	struct flow_offload___local *flow;
	__be32 old_addr, new_addr;
	__be16 old_port, new_port;
	__u8 h_dest[ETH_ALEN], h_source[ETH_ALEN];
	struct ethhdr_ *eth;
	unsigned long flags;
	struct parsed p;
	__u32 out_ifidx;
	__u8 dir, xmit;
	void *data_end;

	bump(ST_SEEN);

	if (parse_rawip(ctx, &p)) {
		bump(ST_PARSE_SKIP);
		return XDP_PASS;
	}

	/* TCP teardown must reach conntrack, so hand FIN and RST to the stack.
	 * nf_flow_state_check() does the same and additionally tears the flow
	 * down; we cannot, so the stack's copy of this check is what retires it.
	 */
	if (p.iph->protocol == IPPROTO_TCP) {
		__u8 *flagsb = (__u8 *)p.ports + 13;

		if ((void *)(flagsb + 1) > p.data_end)
			return XDP_PASS;
		if (*flagsb & 0x05) {	/* FIN | RST */
			bump(ST_PARSE_SKIP);
			return XDP_PASS;
		}
	}

	th = do_lookup(ctx, &p);
	if (!th) {
		bump(ST_MISS);
		return XDP_PASS;
	}
	bump(ST_HIT);

	dir = BPF_CORE_READ_BITFIELD_PROBED(&th->tuple, dir);
	if (dir > FLOW_OFFLOAD_DIR_REPLY)
		return XDP_PASS;

	/* tuplehash[] is the first member of struct flow_offload, so the flow is
	 * the matched hash minus dir entries. container_of, by hand.
	 */
	flow = (struct flow_offload___local *)
		((char *)th - (__u64)dir * sizeof(struct flow_offload_tuple_rhash___local));
	flow = bpf_rdonly_cast(flow, bpf_core_type_id_kernel(struct flow_offload___local));
	if (!flow)
		return XDP_PASS;

	flags = BPF_CORE_READ(flow, flags);
	if (flags & (1UL << NF_FLOW_TEARDOWN)) {
		bump(ST_TORN_DOWN);
		return XDP_PASS;
	}

	other = &flow->tuplehash[dir ? FLOW_OFFLOAD_DIR_ORIGINAL
				    : FLOW_OFFLOAD_DIR_REPLY];

	/* Egress. Only the direct form carries the addresses we need; NEIGH
	 * would require a neighbour lookup this program cannot do, so those
	 * flows stay on the stack's fast path where dst_cache handles them.
	 */
	xmit = BPF_CORE_READ_BITFIELD_PROBED(&th->tuple, xmit_type);
	if (xmit != FLOW_OFFLOAD_XMIT_DIRECT) {
		bump(ST_NOT_DIRECT);
		return XDP_PASS;
	}
	out_ifidx = BPF_CORE_READ(th, tuple.out.ifidx);
	if (!out_ifidx)
		return XDP_PASS;
	BPF_CORE_READ_INTO(&h_dest, th, tuple.out.h_dest);
	BPF_CORE_READ_INTO(&h_source, th, tuple.out.h_source);

	/* SNAT, per nf_flow_snat_ip()/nf_flow_snat_port(). */
	if (flags & (1UL << NF_FLOW_SNAT)) {
		if (dir == FLOW_OFFLOAD_DIR_ORIGINAL) {
			old_addr = p.iph->saddr;
			new_addr = BPF_CORE_READ(other, tuple.dst_v4.s_addr);
			old_port = p.ports->source;
			new_port = BPF_CORE_READ(other, tuple.dst_port);
			p.iph->saddr = new_addr;
			p.ports->source = new_port;
		} else {
			old_addr = p.iph->daddr;
			new_addr = BPF_CORE_READ(other, tuple.src_v4.s_addr);
			old_port = p.ports->dest;
			new_port = BPF_CORE_READ(other, tuple.src_port);
			p.iph->daddr = new_addr;
			p.ports->dest = new_port;
		}
		p.iph->check = csum_replace4(p.iph->check, old_addr, new_addr);
		/* L4 checksum covers both the pseudo-header address and the
		 * port, so both deltas apply to it.
		 */
		{
			__u16 *l4c = (p.iph->protocol == IPPROTO_TCP)
				   ? (__u16 *)((__u8 *)p.ports + 16)
				   : (__u16 *)((__u8 *)p.ports + 6);

			if ((void *)(l4c + 1) <= p.data_end &&
			    (p.iph->protocol == IPPROTO_TCP || *l4c)) {
				__u16 c = csum_replace4(*l4c, old_addr, new_addr);

				*l4c = csum_replace2(c, old_port, new_port);
			}
		}
	}

	/* DNAT, per nf_flow_dnat_ip()/nf_flow_dnat_port(). */
	if (flags & (1UL << NF_FLOW_DNAT)) {
		if (dir == FLOW_OFFLOAD_DIR_ORIGINAL) {
			old_addr = p.iph->daddr;
			new_addr = BPF_CORE_READ(other, tuple.src_v4.s_addr);
			old_port = p.ports->dest;
			new_port = BPF_CORE_READ(other, tuple.src_port);
			p.iph->daddr = new_addr;
			p.ports->dest = new_port;
		} else {
			old_addr = p.iph->saddr;
			new_addr = BPF_CORE_READ(other, tuple.dst_v4.s_addr);
			old_port = p.ports->source;
			new_port = BPF_CORE_READ(other, tuple.dst_port);
			p.iph->saddr = new_addr;
			p.ports->source = new_port;
		}
		p.iph->check = csum_replace4(p.iph->check, old_addr, new_addr);
		{
			__u16 *l4c = (p.iph->protocol == IPPROTO_TCP)
				   ? (__u16 *)((__u8 *)p.ports + 16)
				   : (__u16 *)((__u8 *)p.ports + 6);

			if ((void *)(l4c + 1) <= p.data_end &&
			    (p.iph->protocol == IPPROTO_TCP || *l4c)) {
				__u16 c = csum_replace4(*l4c, old_addr, new_addr);

				*l4c = csum_replace2(c, old_port, new_port);
			}
		}
	}

	/* TTL, per ip_decrease_ttl(): decrement and fix the header checksum. */
	{
		__be16 old_ttl_proto = *(__be16 *)&p.iph->ttl;

		p.iph->ttl -= 1;
		p.iph->check = csum_replace2(p.iph->check, old_ttl_proto,
					     *(__be16 *)&p.iph->ttl);
	}

	/* Grow an Ethernet header in front. XDP_PACKET_HEADROOM is 256 and
	 * do_xdp_generic() guarantees it before running us, so this should not
	 * fail - but a failure here would send a headerless frame out a wired
	 * port, so it is checked rather than assumed.
	 */
	if (bpf_xdp_adjust_head(ctx, -(int)sizeof(struct ethhdr_))) {
		bump(ST_NO_HEADROOM);
		return XDP_PASS;
	}

	data_end = (void *)(long)ctx->data_end;
	eth = (void *)(long)ctx->data;
	if ((void *)(eth + 1) > data_end)
		return XDP_DROP;	/* cannot PASS: the header is half-built */

	__builtin_memcpy(eth->h_dest, h_dest, ETH_ALEN);
	__builtin_memcpy(eth->h_source, h_source, ETH_ALEN);
	eth->h_proto = bpf_htons(ETH_P_IP);

	bump(ST_REDIRECT);
	return bpf_redirect(out_ifidx, 0);
}

char _license[] SEC("license") = "GPL";
