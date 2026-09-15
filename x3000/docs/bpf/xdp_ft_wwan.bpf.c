// SPDX-License-Identifier: GPL-2.0
/*
 * Flowtable-driven XDP fast path for the modem interface.
 *
 * Three programs, meant to be attached in this order:
 *
 *   xdp_ft_probe     lookup, count, XDP_PASS. Changes nothing.
 *   xdp_ft_dryrun    every decision the fastpath makes, no byte written.
 *   xdp_ft_fastpath  lookup, NAT rewrite, build L2, XDP_REDIRECT.
 *
 * Both address families. The first revision was IPv4 only, on the reasoning
 * that one family done right beats two done nearly right. That was sound and
 * it picked the wrong family: measured 2026-09-14, this WAN is 464XLAT with
 * the CLAT inside the modem and the carrier resolvers doing DNS64, so every
 * dual-stack client chooses IPv6. Over a 30-second speedtest IPv4 was 44 of
 * 5373 IP-layer receives - 0.8%. An IPv4-only program here, working perfectly,
 * accelerates under one percent of the link and leaves every counter in the
 * dry run reading as a flat line. See xdp-methods-tested.md section 23.11.
 *
 * Why this can work here at all, each point read from v6.12.103:
 *
 *   - The kfunc exists. nf_flow_table_bpf.o is gated on DEBUG_INFO_BTF_MODULES
 *     (net/netfilter/Makefile) and this build sets it.
 *   - It already speaks both families. bpf_xdp_flow_lookup() has a case
 *     AF_INET6 arm filling src_v6/dst_v6 from fib_tuple->ipv6_src/ipv6_dst
 *     (nf_flow_table_bpf.c:84), so the v6 lookup needs no kernel change.
 *   - The device is in the XDP hashtable. nf_flow_table_offload_setup() takes
 *     the nf_flow_offload_xdp_setup() branch only while hardware offload is
 *     OFF (nf_flow_table_offload.c:1258), so keep the firewall dropdown on
 *     software flow offloading. Hardware offload makes every lookup -ENOENT.
 *   - wwan0 reaches the flowtable at all only because of this tree's firewall4
 *     patch 900-flowtable-fall-back-to-l3-device. Stock fw4 builds the device
 *     list from ifc.device, and a proto modemmanager interface has only
 *     l3_device.
 *   - The lookup resolves the device from xdp->rxq->dev. On wwan0 that is the
 *     real netdev: patch 891 runs the program through do_xdp_generic(), whose
 *     rxq comes from netif_get_rxqueue(skb) (dev.c:5079). On the wired ports it
 *     would be eth->dummy_dev and every lookup would miss - which is why this
 *     program is for wwan0 and nowhere else.
 *   - The redirect target must advertise NETDEV_XDP_ACT_NDO_XMIT
 *     (devmap.c:488). The mtk netdevs do; wwan0 and the AP netdevs do not.
 *     So eth1 and eth0 are legal targets and each other's peers are not.
 *
 * The packet has no Ethernet header. wwan0 is ARPHRD_RAWIP with hard_header_len
 * 0, and 890 anchors mac_header at skb->data, so do_xdp_generic() computes
 * mac_len 0 and the IP header sits at ctx->data. A program written against
 * ethhdr - including the in-tree selftest this is modelled on - reads the first
 * two octets of the source address as an EtherType here. With no EtherType on
 * the wire the version nibble is the only thing naming the family, which is why
 * parse_rawip() switches on it rather than on ctx->protocol.
 *
 * Two corrections to what the first revision of this file asserted, both found
 * by reading nf_flow_table_ip.c rather than reasoning about it:
 *
 *   - It said native IPv6 has no NAT, so the v6 rewrite "simply does not
 *     exist". Wrong. The flowtable implements NAT66 for v6 exactly as it does
 *     for v4 - nf_flow_snat_ipv6() at :516, nf_flow_dnat_ipv6() at :539 - and a
 *     program that ignored NF_FLOW_SNAT on a v6 flow would forward it
 *     untranslated. What is true is the narrower claim: v6 needs no *header*
 *     checksum repair, because IPv6 has none and hop_limit is not covered by
 *     the L4 pseudo-header. The kernel decrements it bare at :682. So the v6
 *     rewrite is the simpler one, not the absent one, and it is implemented
 *     below.
 *   - The v4 rewrite was missing the UDP zero-checksum guard. A UDP checksum
 *     that lands on 0x0000 after a rewrite reads as "no checksum" on the wire,
 *     so nf_flow_nat_ip_udp() writes CSUM_MANGLED_0 (0xffff) instead. This file
 *     did not, which is a one-in-65536 corruption per rewritten datagram and
 *     was never going to show up in a test. Both arms now do it.
 *
 * NAT semantics are taken from nf_flow_snat_ip() / nf_flow_dnat_ip() and their
 * v6 counterparts in net/netfilter/nf_flow_table_ip.c, not from reasoning about
 * conntrack.
 */

#define BPF_NO_KFUNC_PROTOTYPES
#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>

#define ETH_P_IP	0x0800
#define ETH_P_IPV6	0x86dd
#define ETH_ALEN	6
#define IP_MF		0x2000
#define IP_OFFSET	0x1fff
#define AF_INET		2
#define AF_INET6	10
#define IPPROTO_TCP	6
#define IPPROTO_UDP	17

/* IPv6 extension headers, so "TCP behind a hop-by-hop option" is counted apart
 * from "ICMPv6". Both are unacceleratable, but only one of them is traffic
 * anybody expected to go fast.
 */
#define IPPROTO_HOPOPTS		0
#define IPPROTO_ROUTING		43
#define IPPROTO_FRAGMENT	44
#define IPPROTO_ESP		50
#define IPPROTO_AH		51
#define IPPROTO_DSTOPTS		60
#define IPPROTO_MH		135

/* A UDP checksum of zero means "not computed", so a rewrite that lands there
 * has to be written as the equivalent 0xffff instead. net/netfilter has the
 * same constant as CSUM_MANGLED_0.
 */
#define CSUM_MANGLED_0	0xffff

#define V4_HLEN		20
#define V6_HLEN		40

#define FLOW_OFFLOAD_DIR_ORIGINAL	0
#define FLOW_OFFLOAD_DIR_REPLY		1
#define FLOW_OFFLOAD_XMIT_NEIGH		1
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

/* The version lives in the high nibble of the first octet on the wire in both
 * families, so priority_version is read the same way as iphdr_.ihl_version and
 * the kernel's endian-conditional bitfield does not have to be mirrored.
 */
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

/* Kernel types, matched by name for CO-RE. Only the fields this program reads
 * are declared; preserve_access_index makes libbpf relocate every offset from
 * the running kernel's BTF, so a layout change upstream is a load failure and
 * not silent corruption.
 */
struct in_addr___local { __be32 s_addr; };

/* Not a mirror of struct in6_addr, and deliberately so. The kernel's s6_addr
 * is a macro over in6_u.u6_addr8 (include/uapi/linux/in6.h), so there is no BTF
 * field of that name to relocate against and an access written as
 * tuple.src_v6.s6_addr would fail to load. Nothing below names a field inside
 * this type: the v6 reads take the address of src_v6 / dst_v6 and pull 16
 * bytes, which needs only the enclosing tuple's field offsets. All this
 * declaration has to get right is the size.
 */
struct in6_addr___local { __u8 __addr8[16]; };

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
 * Three slots are observations rather than exits - v4, v6 and nat66 - and are
 * marked as such in the harness legend. They do not sum with the rest.
 *
 * The parse failures are split rather than pooled, and that is not cosmetic: a
 * run where the traffic turned out to be IPv6 showed 145880 of 146062 in a
 * single parse_skip slot and took a whole cycle to diagnose. That is also why
 * v4 and v6 are counted at all: the family split is a property of the window,
 * it changes hour to hour on this link, and reading it from the same dump as
 * the result removes an entire class of misreading.
 */
enum stat_slot {
	ST_SEEN = 0,
	ST_NOT_IP,		/* version nibble is neither 4 nor 6 */
	ST_V4,			/* observation */
	ST_V6,			/* observation */
	ST_FRAG_OR_OPTS,
	ST_NOT_TCP_UDP,
	ST_SHORT,
	ST_LOW_TTL,		/* TTL or hop limit at 1 */
	ST_TCP_TEARDOWN,
	ST_MISS,
	ST_HIT,
	ST_BAD_DIR,		/* dir outside 0..1 - impossible, see below */
	ST_TORN_DOWN,
	ST_NOT_DIRECT,
	ST_NO_OUT_IFIDX,
	ST_READ_ERR,
	ST_NAT44,		/* observation: a v4 flow carrying SNAT or DNAT */
	ST_NAT66,		/* observation: a v6 flow carrying SNAT or DNAT */
	ST_WOULD_REDIRECT,
	ST_NO_HEADROOM,
	ST_REDIRECT,

	/* Two invariants on the tuple that came back, kept permanently rather
	 * than as a diagnostic. Both fields are part of the lookup key, so a
	 * tuplehash disagreeing with either is not the one that was asked for,
	 * and everything read through it would be void. They cost two probe
	 * reads and they are the reason 23.14 could rule out a bad pointer in
	 * one window instead of arguing about it.
	 */
	ST_L3_OK,
	ST_L3_BAD,
	ST_IIF_OK,
	ST_IIF_BAD,
	ST__MAX,
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, ST__MAX);
} xdp_ft_stats SEC(".maps");

/* The relocation constants libbpf actually patched in, reported rather than
 * inferred.
 *
 * 23.14 established that the pointer is right and the two-bit dir extraction
 * beside it is wrong in a fixed way, and then stopped, because every mechanism
 * I could construct from the local mirror's layout predicted something the
 * data denied. The local mirror is the wrong thing to reason from: CO-RE
 * patches these values from the running kernel's BTF at load time, and what
 * they become is the only thing that matters. So the program reports them.
 *
 * l3proto and iifidx are in here as a control. Their reads are known good -
 * 444040 agreements, no disagreements - so their offsets say what a correct
 * relocation looks like on this kernel, and the dir window can be checked
 * against them rather than against my mirror.
 *
 * A plain array, not per-CPU: these are constants, and a per-CPU array would
 * report each one multiplied by however many CPUs ran the program.
 */
enum relo_slot {
	RL_DIR_OFF = 0,		/* byte offset of dir's containing unit, from th */
	RL_DIR_SZ,		/* how many bytes the macro reads */
	RL_DIR_LSHIFT,
	RL_DIR_RSHIFT,
	RL_XMIT_OFF,
	RL_XMIT_SZ,
	RL_XMIT_LSHIFT,
	RL_XMIT_RSHIFT,
	RL_L3_OFF,		/* control: known-good plain field */
	RL_IIF_OFF,		/* control: known-good plain field */
	RL_TUPLE_OFF,		/* control: offset of tuple within the rhash */
	RL_RHASH_SZ,		/* control: TYPE_SIZE, measured at 88 */
	RL_RAW_LO,		/* the 8 bytes the dir read returns, last seen */
	RL_RAW_HI,
	RL__MAX,
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, RL__MAX);
} xdp_ft_relo SEC(".maps");

/* Every distinct value of the byte the dir bits are supposed to live in. One
 * value dominating says the extraction is reading a real field and taking the
 * wrong bits out of it; a spread says it is not reading that field at all.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 256);
} xdp_ft_dirbyte SEC(".maps");

static __always_inline void relo_set(__u32 slot, __u64 v)
{
	__u64 *p = bpf_map_lookup_elem(&xdp_ft_relo, &slot);

	if (p)
		*p = v;
}

static __always_inline void bump_byte(__u32 b)
{
	__u64 *v;

	b &= 0xff;
	v = bpf_map_lookup_elem(&xdp_ft_dirbyte, &b);
	if (v)
		*v += 1;
}

/* dir and xmit_type, read together out of the single byte that holds them.
 *
 * Deliberately not BPF_CORE_READ_BITFIELD_PROBED. That macro produced 197509
 * impossible dir values and 156892 phantom XMIT_DIRECT verdicts in one window
 * whose byte at this exact address was 5 - dir 1, xmit NEIGH - on every one of
 * 354468 lookups. It split a constant input 56/44, which deterministic
 * arithmetic cannot do, so its result depends on something that varies between
 * packets. Measured and recorded in xdp-methods-tested.md 23.16.
 *
 * This does the same arithmetic with the same relocated shift amounts. The one
 * deliberate difference is that the value shifted has provably zero upper
 * bits: the macro reads BYTE_SIZE bytes into a u64 and relies on the rest of
 * that word still holding the zero it was initialised with, and BYTE_SIZE is
 * patched from 8 down to 1 at load time, so seven eighths of that word is
 * whatever the last packet left on the stack. Masking to the low byte cannot
 * be wrong in the same way.
 *
 * Why exactly that goes wrong when the shift should discard those bits anyway
 * is not established, and is not guessed at here. What is established is that
 * this version agrees with the byte, with l3proto, with iifidx and with the
 * kernel's own structural claim in every window run so far, and the macro
 * agrees with none of them.
 */
struct bitfields {
	__u32 dir;
	__u32 xmit;
};

static __always_inline int read_bits(struct flow_offload_tuple_rhash___local *th,
				     struct bitfields *b)
{
	__u32 doff = bpf_core_field_offset(th->tuple.dir);
	__u32 xoff = bpf_core_field_offset(th->tuple.xmit_type);
	__u32 dl = __builtin_preserve_field_info(th->tuple.dir,
						 BPF_FIELD_LSHIFT_U64) & 63;
	__u32 dr = __builtin_preserve_field_info(th->tuple.dir,
						 BPF_FIELD_RSHIFT_U64) & 63;
	__u32 xl = __builtin_preserve_field_info(th->tuple.xmit_type,
						 BPF_FIELD_LSHIFT_U64) & 63;
	__u32 xr = __builtin_preserve_field_info(th->tuple.xmit_type,
						 BPF_FIELD_RSHIFT_U64) & 63;
	__u64 raw = 0, v8;

	if (bpf_core_read(&raw, sizeof(raw), (char *)th + doff))
		return -1;
	v8 = raw & 0xff;
	b->dir = (__u32)((v8 << dl) >> dr);

	/* The two share a byte in every kernel that has had this struct, but
	 * that is a property of the layout rather than a guarantee, so it is
	 * checked rather than assumed. A second read costs one probe read on a
	 * kernel where it is ever false, and nothing at all on this one.
	 */
	if (xoff != doff) {
		raw = 0;
		if (bpf_core_read(&raw, sizeof(raw), (char *)th + xoff))
			return -1;
		v8 = raw & 0xff;
	}
	b->xmit = (__u32)((v8 << xl) >> xr);

	relo_set(RL_DIR_OFF, doff);
	relo_set(RL_DIR_SZ, bpf_core_field_size(th->tuple.dir));
	relo_set(RL_DIR_LSHIFT, dl);
	relo_set(RL_DIR_RSHIFT, dr);
	relo_set(RL_XMIT_OFF, xoff);
	relo_set(RL_XMIT_SZ, bpf_core_field_size(th->tuple.xmit_type));
	relo_set(RL_XMIT_LSHIFT, xl);
	relo_set(RL_XMIT_RSHIFT, xr);
	relo_set(RL_L3_OFF, bpf_core_field_offset(th->tuple.l3proto));
	relo_set(RL_IIF_OFF, bpf_core_field_offset(th->tuple.iifidx));
	relo_set(RL_TUPLE_OFF, bpf_core_field_offset(th->tuple));
	relo_set(RL_RHASH_SZ,
		 bpf_core_type_size(struct flow_offload_tuple_rhash___local));
	relo_set(RL_RAW_LO, raw & 0xffffffff);
	relo_set(RL_RAW_HI, raw >> 32);
	bump_byte((__u32)v8);
	return 0;
}

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

/* Only scalars survive the v4/v6 branch.
 *
 * An earlier shape of this struct held a typed header pointer, which does not
 * verify once there are two families: the two arms would spill different
 * pointer types into one stack slot, the merge marks the slot scalar, and the
 * next dereference is rejected outright. So parsed carries data, data_end and
 * three bytes of description, and each use site re-derives its header with its
 * own bounds check. That costs two compares and makes every access locally
 * provable.
 */
struct parsed {
	void	*data;
	void	*data_end;
	__u8	family;		/* AF_INET or AF_INET6 */
	__u8	l4proto;	/* already narrowed to TCP or UDP */
};

static __always_inline struct iphdr_ *v4hdr(struct parsed *p)
{
	struct iphdr_ *iph = p->data;

	if ((void *)(iph + 1) > p->data_end)
		return 0;
	return iph;
}

static __always_inline struct ipv6hdr_ *v6hdr(struct parsed *p)
{
	struct ipv6hdr_ *ip6h = p->data;

	if ((void *)(ip6h + 1) > p->data_end)
		return 0;
	return ip6h;
}

/* Both arms yield the same pointer type at a constant offset, so the merge is
 * a plain packet pointer and the bounds check below covers either.
 */
static __always_inline struct ports_ *l4ports(struct parsed *p)
{
	struct ports_ *ports;

	if (p->family == AF_INET6)
		ports = (struct ports_ *)((__u8 *)p->data + V6_HLEN);
	else
		ports = (struct ports_ *)((__u8 *)p->data + V4_HLEN);

	if ((void *)(ports + 1) > p->data_end)
		return 0;
	return ports;
}

/* Where the L4 checksum sits, measured from the start of the port pair.
 * TCP: seq 4, ack 4, offset and flags 2, window 2, so +16.
 * UDP: length 2, so +6.
 */
static __always_inline __u16 *l4csum(struct parsed *p, struct ports_ *ports)
{
	__u16 *c = (p->l4proto == IPPROTO_TCP)
		 ? (__u16 *)((__u8 *)ports + 16)
		 : (__u16 *)((__u8 *)ports + 6);

	if ((void *)(c + 1) > p->data_end)
		return 0;
	return c;
}

/* Parse a raw-IP packet at ctx->data. Returns 0 on "worth looking up", or the
 * counter slot naming which check rejected it. The caller bumps it, so every
 * rejection is attributable rather than pooled.
 *
 * The order of the protocol and TTL checks matches nf_flow_tuple_ipv6()
 * (:593 then :610) in both arms, so a packet the flowtable would have declined
 * is declined here for the same stated reason. The previous revision tested
 * the v4 TTL first, which booked a hop-limit-1 ICMP packet as low_ttl rather
 * than not_tcp_udp; the counters are comparable across the change for every
 * packet except that one combination.
 */
static __always_inline int parse_rawip(struct xdp_md *ctx, struct parsed *p)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ipv6hdr_ *ip6h;
	struct iphdr_ *iph;
	__u8 *v = data;

	if ((void *)(v + 1) > data_end)
		return ST_SHORT;

	p->data = data;
	p->data_end = data_end;

	if ((*v >> 4) == 4) {
		p->family = AF_INET;
		iph = v4hdr(p);
		if (!iph)
			return ST_SHORT;
		bump(ST_V4);

		/* Options change the L4 offset; the flowtable declines these
		 * too, in ip_has_options() at nf_flow_table_ip.c:136.
		 */
		if ((iph->ihl_version & 0x0f) != 5)
			return ST_FRAG_OR_OPTS;
		if (iph->frag_off & bpf_htons(IP_MF | IP_OFFSET))
			return ST_FRAG_OR_OPTS;
		if (iph->protocol != IPPROTO_TCP &&
		    iph->protocol != IPPROTO_UDP)
			return ST_NOT_TCP_UDP;
		/* Forwarding decrements; 1 would have to become 0. */
		if (iph->ttl <= 1)
			return ST_LOW_TTL;
		p->l4proto = iph->protocol;
	} else if ((*v >> 4) == 6) {
		p->family = AF_INET6;
		ip6h = v6hdr(p);
		if (!ip6h)
			return ST_SHORT;
		bump(ST_V6);

		/* No extension-header walk, because the flowtable does not do
		 * one either: nf_flow_tuple_ipv6() switches on nexthdr and
		 * returns -1 on anything that is not TCP, UDP or GRE
		 * (:593-608). A packet carrying a hop-by-hop or fragment
		 * header is therefore not in the flowtable at all, and looking
		 * past it would only produce a lookup that cannot hit.
		 */
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
			return ST_FRAG_OR_OPTS;
		default:
			return ST_NOT_TCP_UDP;
		}
		if (ip6h->hop_limit <= 1)
			return ST_LOW_TTL;
		p->l4proto = ip6h->nexthdr;
	} else {
		return ST_NOT_IP;
	}

	if (!l4ports(p))
		return ST_SHORT;
	return 0;
}

static __always_inline struct flow_offload_tuple_rhash___local *
do_lookup(struct xdp_md *ctx, struct parsed *p)
{
	struct bpf_flowtable_opts___local opts = {};
	struct bpf_fib_lookup tuple = {
		.ifindex	= ctx->ingress_ifindex,
	};
	struct ports_ *ports = l4ports(p);

	if (!ports)
		return 0;

	tuple.l4_protocol	= p->l4proto;
	tuple.sport		= ports->source;
	tuple.dport		= ports->dest;

	/* tos and tot_len are filled for v4 only, and only because they are
	 * free: bpf_xdp_flow_lookup() builds its flow_offload_tuple from
	 * ifindex, family, l4_protocol, the ports and the addresses
	 * (nf_flow_table_bpf.c:63-92) and never reads either field. This
	 * struct is a carrier here, not a FIB request.
	 */
	if (p->family == AF_INET6) {
		struct ipv6hdr_ *ip6h = v6hdr(p);

		if (!ip6h)
			return 0;
		tuple.family = AF_INET6;
		__builtin_memcpy(tuple.ipv6_src, ip6h->saddr, 16);
		__builtin_memcpy(tuple.ipv6_dst, ip6h->daddr, 16);
	} else {
		struct iphdr_ *iph = v4hdr(p);

		if (!iph)
			return 0;
		tuple.family	= AF_INET;
		tuple.tos	= iph->tos;
		tuple.tot_len	= bpf_ntohs(iph->tot_len);
		tuple.ipv4_src	= iph->saddr;
		tuple.ipv4_dst	= iph->daddr;
	}

	return bpf_xdp_flow_lookup(ctx, &tuple, &opts, sizeof(opts));
}

/* Everything the commit stage needs, gathered while the packet is still
 * untouched. The address pair is 16 bytes wide for both families; a v4
 * translation uses element 0 and leaves the rest zero.
 */
struct decision {
	struct flow_offload_tuple_rhash___local *other;
	unsigned long	flags;
	__u32		out_ifidx;
	__u8		h_dest[ETH_ALEN];
	__u8		h_source[ETH_ALEN];
	__be32		snat_addr[4], dnat_addr[4];
	__be16		snat_port, dnat_port;
	__u8		dir;
};

/* Fold a repaired L4 checksum back into the packet.
 *
 * The zero case is the whole reason this is a function. A UDP checksum that
 * computes to 0x0000 has to be written as 0xffff, which is numerically
 * equivalent in one's complement but does not read as "no checksum present".
 * nf_flow_nat_ip_udp() and nf_flow_nat_ipv6_udp() both do this; the first
 * revision of this file did not, and that is a silent one-in-65536 corruption
 * per rewritten datagram. TCP has no such case: 0x0000 is a legal TCP checksum
 * and must be written as it stands.
 */
static __always_inline void put_l4csum(struct parsed *p, __u16 *l4c, __u16 c)
{
	if (p->l4proto == IPPROTO_UDP && c == 0)
		c = CSUM_MANGLED_0;
	*l4c = c;
}

/* True when the L4 checksum is one this program may touch. A UDP checksum of
 * zero means "not computed" and stays that way; TCP always has one.
 */
static __always_inline int l4csum_live(struct parsed *p, __u16 *l4c)
{
	return p->l4proto == IPPROTO_TCP || *l4c != 0;
}

/* Which end of the packet a translation rewrites.
 *
 * Named rather than passed as a pointer to the field, because the header
 * mirrors are packed and taking the address of a member of a packed struct is
 * both a warning and a genuine unaligned-pointer hazard on any target that
 * cares. Selecting the field inside the function keeps every access a direct
 * member reference, which the compiler is free to split into byte loads.
 */
#define XF_SRC	0
#define XF_DST	1

/* IPv4: rewrite one address and port pair and repair both checksums.
 *
 * The L4 checksum covers the pseudo-header address as well as the port, so
 * both deltas apply to it, and the IPv4 header checksum covers the address.
 */
static __always_inline void xlate4(struct parsed *p, struct iphdr_ *iph,
				   struct ports_ *ports, __u16 *l4c,
				   int which, __be32 new_addr, __be16 new_port)
{
	__be32 old_addr;
	__be16 old_port;

	if (which == XF_SRC) {
		old_addr = iph->saddr;
		old_port = ports->source;
		iph->saddr = new_addr;
		ports->source = new_port;
	} else {
		old_addr = iph->daddr;
		old_port = ports->dest;
		iph->daddr = new_addr;
		ports->dest = new_port;
	}

	iph->check = csum_replace4(iph->check, old_addr, new_addr);

	if (l4csum_live(p, l4c)) {
		__u16 c = csum_replace4(*l4c, old_addr, new_addr);

		put_l4csum(p, l4c, csum_replace2(c, old_port, new_port));
	}
}

/* IPv6: rewrite one address and port pair and repair the L4 checksum.
 *
 * Shorter than the v4 case by exactly one checksum. IPv6 has no header
 * checksum, so the only repair is the L4 one, and a 128-bit address is four
 * applications of the same 32-bit delta - which is all
 * inet_proto_csum_replace16() does (net/core/utils.c).
 */
static __always_inline void xlate6(struct parsed *p, struct ipv6hdr_ *ip6h,
				   struct ports_ *ports, __u16 *l4c,
				   int which, const __be32 *new_addr,
				   __be16 new_port)
{
	__be32 old_addr[4];
	__be16 old_port;
	int i;

	if (which == XF_SRC) {
		__builtin_memcpy(old_addr, ip6h->saddr, 16);
		__builtin_memcpy(ip6h->saddr, new_addr, 16);
		old_port = ports->source;
		ports->source = new_port;
	} else {
		__builtin_memcpy(old_addr, ip6h->daddr, 16);
		__builtin_memcpy(ip6h->daddr, new_addr, 16);
		old_port = ports->dest;
		ports->dest = new_port;
	}

	if (l4csum_live(p, l4c)) {
		__u16 c = *l4c;

		for (i = 0; i < 4; i++)
			c = csum_replace4(c, old_addr[i], new_addr[i]);
		put_l4csum(p, l4c, csum_replace2(c, old_port, new_port));
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
	struct bitfields bits = {};
	struct ports_ *ports;
	__u32 hsz;
	int rc;

	rc = parse_rawip(ctx, p);
	if (rc) {
		bump(rc);
		return -1;
	}

	ports = l4ports(p);
	if (!ports) {
		bump(ST_SHORT);
		return -1;
	}

	/* TCP teardown must reach conntrack, so hand FIN and RST to the stack.
	 * nf_flow_state_check() does the same and additionally tears the flow
	 * down; this program cannot, so the stack's copy of the check is what
	 * retires it.
	 */
	if (p->l4proto == IPPROTO_TCP) {
		__u8 *flagsb = (__u8 *)ports + 13;

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

	/* Two invariants the matched tuple must satisfy, read as plain scalars
	 * rather than bitfields. See the diagnostic block in enum stat_slot.
	 * The lookup key carries both values, so a tuplehash that came back
	 * disagreeing with either is not the one that was asked for.
	 */
	{
		__u32 iif = 0;
		__u8 l3 = 0;

		if (bpf_core_read(&l3, sizeof(l3), &th->tuple.l3proto))
			bump(ST_L3_BAD);
		else
			bump(l3 == p->family ? ST_L3_OK : ST_L3_BAD);

		if (bpf_core_read(&iif, sizeof(iif), &th->tuple.iifidx))
			bump(ST_IIF_BAD);
		else
			bump(iif == ctx->ingress_ifindex ? ST_IIF_OK : ST_IIF_BAD);
	}

	if (read_bits(th, &bits)) {
		bump(ST_READ_ERR);
		return -1;
	}
	d->dir = bits.dir;
	if (d->dir > FLOW_OFFLOAD_DIR_REPLY) {
		/* Now a genuine impossibility rather than an instrument fault:
		 * the kernel writes dir once (nf_flow_table_core.c:27) and then
		 * uses it as a container_of index, so a 2 or a 3 here would
		 * have faulted the kernel before this program was reached.
		 */
		bump(ST_BAD_DIR);
		return -1;
	}

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
	if (bits.xmit != FLOW_OFFLOAD_XMIT_DIRECT) {
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

	/* NAT66 is not hypothetical - the flowtable implements it - but on a
	 * plain routed IPv6 prefix it should never fire. Counted so that "it
	 * never fires here" is a measurement rather than an assumption.
	 */
	/* Counted per family, and the asymmetry is worth naming. There is no
	 * NAT64 counter because no NAT64 state exists in this kernel to count:
	 * on a 464XLAT link the CLAT that turns IPv4 into IPv6 is in the modem
	 * and the NAT64 that turns it back is in the carrier's network, so
	 * neither translation is ever a flow in this flowtable. What does exist
	 * here is ordinary NAT44 on the v4 path - the LAN prefix translated to
	 * the 192.0.0.2 CLAT address - and NAT66, which a routed v6 prefix
	 * should never produce. Both are counted so that "it never fires" is a
	 * measurement rather than an assumption.
	 */
	if (d->flags & ((1UL << NF_FLOW_SNAT) | (1UL << NF_FLOW_DNAT)))
		bump(p->family == AF_INET6 ? ST_NAT66 : ST_NAT44);

	/* The translated address and port for whichever directions apply, taken
	 * from the peer tuple exactly as nf_flow_snat_ip() and nf_flow_dnat_ip()
	 * do it, and their v6 counterparts at :516 and :539, which read the same
	 * peer fields.
	 *
	 * The v6 reads take the address of src_v6 / dst_v6 and pull 16 bytes
	 * rather than naming a field inside struct in6_addr, because s6_addr is
	 * a macro and not a BTF field name. See in6_addr___local above.
	 */
	if (d->flags & (1UL << NF_FLOW_SNAT)) {
		int err;

		if (d->dir == FLOW_OFFLOAD_DIR_ORIGINAL) {
			err = (p->family == AF_INET6)
			    ? bpf_core_read(d->snat_addr, 16,
					    &other->tuple.dst_v6)
			    : bpf_core_read(d->snat_addr, sizeof(__be32),
					    &other->tuple.dst_v4.s_addr);
			err |= bpf_core_read(&d->snat_port, sizeof(d->snat_port),
					     &other->tuple.dst_port);
		} else {
			err = (p->family == AF_INET6)
			    ? bpf_core_read(d->snat_addr, 16,
					    &other->tuple.src_v6)
			    : bpf_core_read(d->snat_addr, sizeof(__be32),
					    &other->tuple.src_v4.s_addr);
			err |= bpf_core_read(&d->snat_port, sizeof(d->snat_port),
					     &other->tuple.src_port);
		}
		if (err) {
			bump(ST_READ_ERR);
			return -1;
		}
	}

	if (d->flags & (1UL << NF_FLOW_DNAT)) {
		int err;

		if (d->dir == FLOW_OFFLOAD_DIR_ORIGINAL) {
			err = (p->family == AF_INET6)
			    ? bpf_core_read(d->dnat_addr, 16,
					    &other->tuple.src_v6)
			    : bpf_core_read(d->dnat_addr, sizeof(__be32),
					    &other->tuple.src_v4.s_addr);
			err |= bpf_core_read(&d->dnat_port, sizeof(d->dnat_port),
					     &other->tuple.src_port);
		} else {
			err = (p->family == AF_INET6)
			    ? bpf_core_read(d->dnat_addr, 16,
					    &other->tuple.dst_v6)
			    : bpf_core_read(d->dnat_addr, sizeof(__be32),
					    &other->tuple.dst_v4.s_addr);
			err |= bpf_core_read(&d->dnat_port, sizeof(d->dnat_port),
					     &other->tuple.dst_port);
		}
		if (err) {
			bump(ST_READ_ERR);
			return -1;
		}
	}

	return 0;
}

/* Apply the translation and decrement the TTL or hop limit.
 *
 * Every header pointer is re-derived and checked here, before the first byte is
 * written, so that a failure can still return without having touched the
 * packet. Once past the guard clause nothing can fail: the values all came from
 * decide(), and the bounds all came from these three checks.
 */
static __always_inline int commit4(struct parsed *p, struct decision *d)
{
	struct iphdr_ *iph = v4hdr(p);
	struct ports_ *ports = l4ports(p);
	__u16 *l4c;

	if (!iph || !ports)
		return -1;
	l4c = l4csum(p, ports);
	if (!l4c)
		return -1;

	/* Which end moves depends on the direction, and the pairing is not
	 * symmetric: SNAT rewrites the source on an ORIGINAL packet and the
	 * destination on a REPLY, DNAT the other way about. Straight out of
	 * nf_flow_snat_ip() and nf_flow_dnat_ip().
	 */
	if (d->flags & (1UL << NF_FLOW_SNAT))
		xlate4(p, iph, ports, l4c,
		       d->dir == FLOW_OFFLOAD_DIR_ORIGINAL ? XF_SRC : XF_DST,
		       d->snat_addr[0], d->snat_port);

	if (d->flags & (1UL << NF_FLOW_DNAT))
		xlate4(p, iph, ports, l4c,
		       d->dir == FLOW_OFFLOAD_DIR_ORIGINAL ? XF_DST : XF_SRC,
		       d->dnat_addr[0], d->dnat_port);

	/* TTL, per ip_decrease_ttl(): decrement and repair the header
	 * checksum, which covers the TTL and protocol octets as one word.
	 */
	{
		__be16 old_ttl_proto = *(__be16 *)&iph->ttl;

		iph->ttl -= 1;
		iph->check = csum_replace2(iph->check, old_ttl_proto,
					   *(__be16 *)&iph->ttl);
	}
	return 0;
}

static __always_inline int commit6(struct parsed *p, struct decision *d)
{
	struct ipv6hdr_ *ip6h = v6hdr(p);
	struct ports_ *ports = l4ports(p);
	__u16 *l4c;

	if (!ip6h || !ports)
		return -1;
	l4c = l4csum(p, ports);
	if (!l4c)
		return -1;

	/* Same pairing as the v4 arm, from nf_flow_snat_ipv6() at :516 and
	 * nf_flow_dnat_ipv6() at :539.
	 */
	if (d->flags & (1UL << NF_FLOW_SNAT))
		xlate6(p, ip6h, ports, l4c,
		       d->dir == FLOW_OFFLOAD_DIR_ORIGINAL ? XF_SRC : XF_DST,
		       d->snat_addr, d->snat_port);

	if (d->flags & (1UL << NF_FLOW_DNAT))
		xlate6(p, ip6h, ports, l4c,
		       d->dir == FLOW_OFFLOAD_DIR_ORIGINAL ? XF_DST : XF_SRC,
		       d->dnat_addr, d->dnat_port);

	/* No checksum repair, and this is the one place the v6 path is
	 * genuinely simpler rather than merely different: IPv6 has no header
	 * checksum, and the hop limit is not part of the L4 pseudo-header. The
	 * kernel decrements it bare at nf_flow_table_ip.c:682.
	 */
	ip6h->hop_limit -= 1;
	return 0;
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
	int rc;

	bump(ST_SEEN);

	if (decide(ctx, &p, &d))
		return XDP_PASS;

	rc = (p.family == AF_INET6) ? commit6(&p, &d) : commit4(&p, &d);
	if (rc) {
		/* Cannot happen: decide() established every one of these
		 * bounds. Counted and passed rather than asserted, because the
		 * alternative to being wrong about that is a dropped packet.
		 */
		bump(ST_SHORT);
		return XDP_PASS;
	}

	/* Grow an Ethernet header in front. XDP_PACKET_HEADROOM is 256 and
	 * do_xdp_generic() guarantees it before running the program, so this
	 * should not fail - but a failure here would send a headerless frame out
	 * a wired port, so it is checked rather than assumed.
	 */
	if (bpf_xdp_adjust_head(ctx, -(int)sizeof(struct ethhdr_))) {
		bump(ST_NO_HEADROOM);
		return XDP_PASS;
	}

	/* p.data and p.data_end are stale from here on - adjust_head moved the
	 * start of the packet - so only the scalar p.family is read below.
	 */
	data_end = (void *)(long)ctx->data_end;
	eth = (void *)(long)ctx->data;
	if ((void *)(eth + 1) > data_end)
		return XDP_DROP;	/* cannot PASS: the header is half-built */

	__builtin_memcpy(eth->h_dest, d.h_dest, ETH_ALEN);
	__builtin_memcpy(eth->h_source, d.h_source, ETH_ALEN);
	eth->h_proto = bpf_htons(p.family == AF_INET6 ? ETH_P_IPV6 : ETH_P_IP);

	bump(ST_REDIRECT);
	return bpf_redirect(d.out_ifidx, 0);
}

char _license[] SEC("license") = "GPL";
