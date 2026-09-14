// SPDX-License-Identifier: GPL-2.0
/*
 * Does bpf_xdp_flow_lookup() hit on wwan0?
 *
 * Counts and passes. Attaches nothing else, rewrites nothing, drops nothing.
 *
 * Deliberately kept apart from the fastpath object. The fastpath reads fields
 * out of struct flow_offload_tuple, and doing that needs CO-RE relocations that
 * the running kernel's BTF resolves ambiguously - two candidate types, two
 * different offsets, and libbpf refuses to guess. Since bpftool loadall fails
 * the whole object when any one program fails to relocate, that took this
 * program down with it.
 *
 * So this one declares the kfunc's return type opaque, exactly as the in-tree
 * selftest tools/testing/selftests/bpf/progs/xdp_flowtable.c does. Nothing is
 * read out of it, only tested for NULL, so there is nothing to relocate and
 * nothing to be ambiguous about.
 *
 * The packet has no Ethernet header: wwan0 is ARPHRD_RAWIP (519) with
 * hard_header_len 0, and 991 anchors mac_header at skb->data, so
 * do_xdp_generic() computes mac_len 0 and the IP header sits at ctx->data. The
 * selftest this is modelled on parses ethhdr and would read the first two
 * octets of the source address as an EtherType.
 */

#define BPF_NO_KFUNC_PROTOTYPES
#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define IP_MF		0x2000
#define IP_OFFSET	0x1fff
#define AF_INET		2
#define IPPROTO_TCP	6
#define IPPROTO_UDP	17

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

/* Opaque on purpose - see the header comment. */
struct flow_offload_tuple_rhash___local { };

struct bpf_flowtable_opts___local {
	__s32 error;
};

struct flow_offload_tuple_rhash___local *
bpf_xdp_flow_lookup(struct xdp_md *, struct bpf_fib_lookup *,
		    struct bpf_flowtable_opts___local *, __u32) __ksym;

enum stat_slot {
	ST_SEEN = 0,
	ST_NOT_IPV4,
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
	struct iphdr_ *iph = data;
	struct bpf_fib_lookup tuple = {};
	struct ports_ *ports;

	bump(ST_SEEN);

	if ((void *)(iph + 1) > data_end) {
		bump(ST_SHORT);
		return XDP_PASS;
	}

	/* Raw IP: the version nibble is all there is to go on. */
	if ((iph->ihl_version >> 4) != 4) {
		bump(ST_NOT_IPV4);
		return XDP_PASS;
	}

	/* Options move the L4 offset; fragments have no ports. The flowtable
	 * declines both, so counting them separately says whether a low hit
	 * rate is the lookup failing or the traffic being ineligible.
	 */
	if ((iph->ihl_version & 0x0f) != 5 ||
	    (iph->frag_off & bpf_htons(IP_MF | IP_OFFSET))) {
		bump(ST_FRAG_OR_OPTS);
		return XDP_PASS;
	}

	if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP) {
		bump(ST_NOT_TCP_UDP);
		return XDP_PASS;
	}

	ports = (struct ports_ *)(iph + 1);
	if ((void *)(ports + 1) > data_end) {
		bump(ST_SHORT);
		return XDP_PASS;
	}

	tuple.ifindex		= ctx->ingress_ifindex;
	tuple.family		= AF_INET;
	tuple.tos		= iph->tos;
	tuple.l4_protocol	= iph->protocol;
	tuple.tot_len		= bpf_ntohs(iph->tot_len);
	tuple.ipv4_src		= iph->saddr;
	tuple.ipv4_dst		= iph->daddr;
	tuple.sport		= ports->source;
	tuple.dport		= ports->dest;

	th = bpf_xdp_flow_lookup(ctx, &tuple, &opts, sizeof(opts));
	if (!th) {
		/* opts.error distinguishes "no such flow" from the kfunc
		 * refusing the request, which is the difference between the
		 * flowtable not knowing this flow and the lookup being
		 * structurally unusable here.
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
