// SPDX-License-Identifier: GPL-2.0
/*
 * Does bpf_xdp_flow_lookup() hit on wwan0?
 *
 * Counts and passes. Attaches nothing else, rewrites nothing, drops nothing.
 * Both address families, which on this link is the difference between a
 * measurement and a flat line: the WAN is 464XLAT with DNS64 upstream and IPv4
 * was 0.8% of a measured 30-second window.
 *
 * Deliberately kept apart from the fastpath object, and the reason has changed.
 * It was that the fastpath's CO-RE relocations could not resolve against this
 * kernel's BTF and bpftool loadall fails a whole object when one program fails,
 * which took this program down with it. That is fixed - the fastpath object
 * carries no TYPE_ID relocation any more and loads. What is still true, and is
 * now the reason, is that this program reads nothing out of struct
 * flow_offload_tuple and so has no relocations at all. It is the canary: if a
 * kernel bump breaks the mirrors in xdp_ft_wwan.bpf.c, this one still answers
 * whether the kfunc itself works.
 *
 * The packet has no Ethernet header: wwan0 is ARPHRD_RAWIP (519) with
 * hard_header_len 0, and 991 anchors mac_header at skb->data, so
 * do_xdp_generic() computes mac_len 0 and the IP header sits at ctx->data. The
 * selftest this is modelled on parses ethhdr and would read the first two
 * octets of the source address as an EtherType. With no EtherType on the wire
 * the version nibble is the only thing naming the family.
 */

#define BPF_NO_KFUNC_PROTOTYPES
#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define IP_MF		0x2000
#define IP_OFFSET	0x1fff
#define AF_INET		2
#define AF_INET6	10
#define IPPROTO_TCP	6
#define IPPROTO_UDP	17

/* IPv6 extension headers. The flowtable does not walk them either - see
 * nf_flow_tuple_ipv6() at nf_flow_table_ip.c:593 - so a packet carrying one is
 * not a flow this lookup could ever find. Counted apart from ICMPv6 so that
 * "not TCP or UDP" does not hide "TCP behind a hop-by-hop option".
 */
#define IPPROTO_HOPOPTS		0
#define IPPROTO_ROUTING		43
#define IPPROTO_FRAGMENT	44
#define IPPROTO_ESP		50
#define IPPROTO_AH		51
#define IPPROTO_DSTOPTS		60
#define IPPROTO_MH		135

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

struct ipv6hdr_ {
	__u8	priority_version;
	__u8	flow_lbl[3];
	__be16	payload_len;
	__u8	nexthdr;
	__u8	hop_limit;
	__u8	saddr[16];
	__u8	daddr[16];
} __attribute__((packed));

struct ports_ {
	__be16	source;
	__be16	dest;
} __attribute__((packed));

/* Opaque on purpose - see the header comment. */
struct flow_offload_tuple_rhash___local { };

struct bpf_flowtable_opts___local {
	__s32 error;
};

struct flow_offload_tuple_rhash___local *
bpf_xdp_flow_lookup(struct xdp_md *, struct bpf_fib_lookup *,
		    struct bpf_flowtable_opts___local *, __u32) __ksym;

/* v4 and v6 are observations, not exits: they say what the window contained,
 * and they do not sum with the rest.
 */
enum stat_slot {
	ST_SEEN = 0,
	ST_NOT_IP,
	ST_V4,
	ST_V6,
	ST_FRAG_OR_OPTS,
	ST_NOT_TCP_UDP,
	ST_SHORT,
	ST_MISS,
	ST_HIT,
	ST_LOOKUP_ERR,
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

SEC("xdp.frags")
int xdp_ft_probe(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct flow_offload_tuple_rhash___local *th;
	struct bpf_flowtable_opts___local opts = {};
	struct bpf_fib_lookup tuple = {};
	struct ipv6hdr_ *ip6h;
	struct iphdr_ *iph;
	struct ports_ *ports;
	__u8 *v = data;

	bump(ST_SEEN);

	if ((void *)(v + 1) > data_end) {
		bump(ST_SHORT);
		return XDP_PASS;
	}

	/* The ports are read into scalars inside each arm rather than after
	 * the branch. Two packet pointers at different constant offsets merge
	 * into a range the verifier will not carry, and the scalars cost
	 * nothing.
	 */
	if ((*v >> 4) == 4) {
		iph = data;
		if ((void *)(iph + 1) > data_end) {
			bump(ST_SHORT);
			return XDP_PASS;
		}
		bump(ST_V4);

		/* Options move the L4 offset; fragments have no ports. The
		 * flowtable declines both, so counting them separately says
		 * whether a low hit rate is the lookup failing or the traffic
		 * being ineligible.
		 */
		if ((iph->ihl_version & 0x0f) != 5 ||
		    (iph->frag_off & bpf_htons(IP_MF | IP_OFFSET))) {
			bump(ST_FRAG_OR_OPTS);
			return XDP_PASS;
		}
		if (iph->protocol != IPPROTO_TCP &&
		    iph->protocol != IPPROTO_UDP) {
			bump(ST_NOT_TCP_UDP);
			return XDP_PASS;
		}

		ports = (struct ports_ *)(iph + 1);
		if ((void *)(ports + 1) > data_end) {
			bump(ST_SHORT);
			return XDP_PASS;
		}

		tuple.family		= AF_INET;
		tuple.tos		= iph->tos;
		tuple.l4_protocol	= iph->protocol;
		tuple.tot_len		= bpf_ntohs(iph->tot_len);
		tuple.ipv4_src		= iph->saddr;
		tuple.ipv4_dst		= iph->daddr;
		tuple.sport		= ports->source;
		tuple.dport		= ports->dest;
	} else if ((*v >> 4) == 6) {
		ip6h = data;
		if ((void *)(ip6h + 1) > data_end) {
			bump(ST_SHORT);
			return XDP_PASS;
		}
		bump(ST_V6);

		switch (ip6h->nexthdr) {
		case IPPROTO_TCP:
		case IPPROTO_UDP:
			break;
		case IPPROTO_HOPOPTS:
		case IPPROTO_ROUTING:
		case IPPROTO_FRAGMENT:
		case IPPROTO_ESP:
		case IPPROTO_AH:
		case IPPROTO_DSTOPTS:
		case IPPROTO_MH:
			bump(ST_FRAG_OR_OPTS);
			return XDP_PASS;
		default:
			bump(ST_NOT_TCP_UDP);
			return XDP_PASS;
		}

		ports = (struct ports_ *)(ip6h + 1);
		if ((void *)(ports + 1) > data_end) {
			bump(ST_SHORT);
			return XDP_PASS;
		}

		/* tos and tot_len are left unset. bpf_xdp_flow_lookup() builds
		 * its flow_offload_tuple from ifindex, family, l4_protocol, the
		 * ports and the addresses (nf_flow_table_bpf.c:63-92) and never
		 * reads either field; this struct is a carrier, not a FIB
		 * request.
		 */
		tuple.family		= AF_INET6;
		tuple.l4_protocol	= ip6h->nexthdr;
		__builtin_memcpy(tuple.ipv6_src, ip6h->saddr, 16);
		__builtin_memcpy(tuple.ipv6_dst, ip6h->daddr, 16);
		tuple.sport		= ports->source;
		tuple.dport		= ports->dest;
	} else {
		bump(ST_NOT_IP);
		return XDP_PASS;
	}

	tuple.ifindex = ctx->ingress_ifindex;

	th = bpf_xdp_flow_lookup(ctx, &tuple, &opts, sizeof(opts));
	if (!th) {
		/* opts.error distinguishes "no such flow" from the kfunc
		 * refusing the request, which is the difference between the
		 * flowtable not knowing this flow and the lookup being
		 * structurally unusable here. In practice an ordinary miss sets
		 * it too - flow_offload_lookup() returning NULL becomes
		 * ERR_PTR(-ENOENT) at nf_flow_table_bpf.c:49 - so the miss slot
		 * stays at zero and lookup_err carries both.
		 */
		if (opts.error)
			bump(ST_LOOKUP_ERR);
		else
			bump(ST_MISS);
		return XDP_PASS;
	}

	bump(ST_HIT);
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
