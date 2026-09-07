// SPDX-License-Identifier: GPL-2.0
/* tc_cake_mark — egress tc-bpf DSCP classifier feeding cake's tins.
 *
 * This is the CAKE-COOPERATIVE L3/L4 fast path: unlike XDP_REDIRECT
 * forwarding (which bypasses the qdisc), a clsact egress filter runs
 * BEFORE the packet is enqueued into cake, so cake still shapes every
 * byte — we only set the DSCP so cake's diffserv mode sorts it into the
 * right tin. Attach on WAN egress (wwan0) where upload prioritisation
 * decides bufferbloat under load.
 *
 * Classification (dest port, host order, from port_dscp; else proto
 * defaults; else leave DSCP untouched):
 *   - DNS/NTP/QUIC-handshake, ICMP  -> low latency
 *   - everything else               -> unchanged
 * Fill port_dscp from userspace to tune (e.g. game server port -> EF).
 *
 * DSCP is written into the IPv4 ToS / IPv6 Traffic-Class field with
 * proper checksum fixup (v4). Marking correctness is a RUNTIME concern
 * the verifier cannot check — bench before trusting (see README).
 */
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char _license[] SEC("license") = "GPL";

/* ifindex -> L3 offset: 0 = raw IP (wwan0), 14 = ethernet. Absent =>
 * program does nothing (fail safe). Loader sets this. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u32);
	__type(value, __u32);
} l3off_map SEC(".maps");

/* dest port (host order) -> DSCP value (0..63). */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u16);
	__type(value, __u8);
} port_dscp SEC(".maps");

#define DSCP_EF 46   /* expedited forwarding — cake's lowest-latency tin */

static __always_inline __u8 classify(__u8 proto, __u16 dport)
{
	__u8 *d = bpf_map_lookup_elem(&port_dscp, &dport);

	if (d)
		return *d;
	if (proto == IPPROTO_ICMP || proto == IPPROTO_ICMPV6)
		return DSCP_EF;
	if (proto == IPPROTO_UDP && (dport == 53 || dport == 123))
		return DSCP_EF;
	return 0xff; /* sentinel: leave DSCP unchanged */
}

static __always_inline __u16 dport_at(struct __sk_buff *skb, __u32 l4off,
				      __u8 proto)
{
	__be16 dport;

	if (proto != IPPROTO_TCP && proto != IPPROTO_UDP)
		return 0;
	/* dest port is the 2nd 16-bit field of both TCP and UDP headers */
	if (bpf_skb_load_bytes(skb, l4off + 2, &dport, sizeof(dport)) < 0)
		return 0;
	return bpf_ntohs(dport);
}

static __always_inline int mark_v4(struct __sk_buff *skb, __u32 l3off)
{
	struct iphdr iph;
	__u16 dport;
	__u8 dscp, tos_new, tos_old;

	if (bpf_skb_load_bytes(skb, l3off, &iph, sizeof(iph)) < 0)
		return TC_ACT_OK;
	if (iph.ihl < 5)
		return TC_ACT_OK;

	dport = dport_at(skb, l3off + iph.ihl * 4, iph.protocol);
	dscp = classify(iph.protocol, dport);
	if (dscp == 0xff)
		return TC_ACT_OK;

	tos_old = iph.tos;
	tos_new = (tos_old & 0x03) | (dscp << 2);
	if (tos_new == tos_old)
		return TC_ACT_OK;

	/* checksum fixup: ToS is one byte; pass old/new as 16-bit words
	 * (high byte 0 — the unchanged ver/ihl byte cancels in the delta). */
	bpf_l3_csum_replace(skb, l3off + offsetof(struct iphdr, check),
			    bpf_htons(tos_old), bpf_htons(tos_new), 2);
	bpf_skb_store_bytes(skb, l3off + offsetof(struct iphdr, tos),
			    &tos_new, sizeof(tos_new), 0);
	return TC_ACT_OK;
}

static __always_inline int mark_v6(struct __sk_buff *skb, __u32 l3off)
{
	struct ipv6hdr ip6;
	__u16 dport;
	__u8 dscp;
	__u8 b0_old, b1_old, b0_new, b1_new;

	if (bpf_skb_load_bytes(skb, l3off, &ip6, sizeof(ip6)) < 0)
		return TC_ACT_OK;

	dport = dport_at(skb, l3off + sizeof(ip6), ip6.nexthdr);
	dscp = classify(ip6.nexthdr, dport);
	if (dscp == 0xff)
		return TC_ACT_OK;

	/* IPv6 words: byte0 = [version(4) | TC-high(4)],
	 *             byte1 = [TC-low(4) | flow-high(4)].
	 * TC = DSCP(6) | ECN(2). Rebuild bytes 0 and 1, no L3 checksum. */
	if (bpf_skb_load_bytes(skb, l3off, &b0_old, 1) < 0)
		return TC_ACT_OK;
	if (bpf_skb_load_bytes(skb, l3off + 1, &b1_old, 1) < 0)
		return TC_ACT_OK;

	{
		__u8 ecn = (b0_old & 0x0f) & 0x03;      /* low 2 of TC = ECN */
		__u8 tc  = (dscp << 2) | ecn;
		b0_new = (b0_old & 0xf0) | (tc >> 4);
		b1_new = (b1_old & 0x0f) | ((tc & 0x0f) << 4);
	}
	if (b0_new != b0_old)
		bpf_skb_store_bytes(skb, l3off, &b0_new, 1, 0);
	if (b1_new != b1_old)
		bpf_skb_store_bytes(skb, l3off + 1, &b1_new, 1, 0);
	return TC_ACT_OK;
}

SEC("tc")
int tc_cake_mark(struct __sk_buff *skb)
{
	__u32 ifindex = skb->ifindex;
	__u32 *l3off = bpf_map_lookup_elem(&l3off_map, &ifindex);
	__u8 ver;

	if (!l3off)
		return TC_ACT_OK;      /* interface not configured: no-op */

	if (bpf_skb_load_bytes(skb, *l3off, &ver, 1) < 0)
		return TC_ACT_OK;

	if ((ver & 0xf0) == 0x40)
		return mark_v4(skb, *l3off);
	if ((ver & 0xf0) == 0x60)
		return mark_v6(skb, *l3off);
	return TC_ACT_OK;
}
