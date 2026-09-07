// SPDX-License-Identifier: GPL-2.0
/* xdp_filter — one XDP program for every attach point on the GL-X3000.
 *
 * Load ONCE (pinned via bpftool), attach the pinned program to any mix
 * of interfaces; all attachments share the maps below. Per-interface
 * L2 framing is looked up in mode_map by ifindex (0 = Ethernet frame,
 * 1 = raw IP, i.e. wwan0/MBIM) — populated by load-xdp.sh, never
 * guessed from packet bytes.
 *
 * L2/L3/L4: parses Ethernet or raw-IP, then IPv4/IPv6, then TCP/UDP.
 *   - per-CPU pass/drop packet+byte counters (stats_map)
 *   - drop by SOURCE address     (block4 / block6)
 *   - drop by DESTINATION L4 port (portblock, host-order key)
 * Everything else is XDP_PASS. Deliberately small and verifier-obvious;
 * extend from here.
 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char _license[] SEC("license") = "GPL";

enum stat_idx {
	ST_PASS_PKTS,
	ST_PASS_BYTES,
	ST_DROP_PKTS,
	ST_DROP_BYTES,
	ST_MAX,
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, ST_MAX);
	__type(key, __u32);
	__type(value, __u64);
} stats_map SEC(".maps");

/* ifindex -> l2 mode. 0/absent = ethernet, 1 = raw IP (wwan). */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u32);
	__type(value, __u32);
} mode_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __be32);
	__type(value, __u8);
} block4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct in6_addr);
	__type(value, __u8);
} block6 SEC(".maps");

/* destination L4 port (host byte order) -> drop */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u16);
	__type(value, __u8);
} portblock SEC(".maps");

static __always_inline void count(__u32 base, __u64 bytes)
{
	__u32 k = base;
	__u64 *v = bpf_map_lookup_elem(&stats_map, &k);
	if (v)
		__sync_fetch_and_add(v, 1);
	k = base + 1;
	v = bpf_map_lookup_elem(&stats_map, &k);
	if (v)
		__sync_fetch_and_add(v, bytes);
}

/* Returns dest port (host order) if l4 is TCP/UDP and in-bounds, else 0. */
static __always_inline __u16 l4_dport(void *l4, void *data_end, __u8 proto)
{
	if (proto == IPPROTO_TCP) {
		struct tcphdr *th = l4;

		if ((void *)(th + 1) > data_end)
			return 0;
		return bpf_ntohs(th->dest);
	}
	if (proto == IPPROTO_UDP) {
		struct udphdr *uh = l4;

		if ((void *)(uh + 1) > data_end)
			return 0;
		return bpf_ntohs(uh->dest);
	}
	return 0;
}

static __always_inline int port_blocked(__u16 dport)
{
	if (!dport)
		return 0;
	return bpf_map_lookup_elem(&portblock, &dport) != NULL;
}

static __always_inline int verdict_v4(void *l3, void *data_end, __u64 len)
{
	struct iphdr *iph = l3;
	__u16 dport;

	if ((void *)(iph + 1) > data_end)
		return XDP_PASS;

	if (bpf_map_lookup_elem(&block4, &iph->saddr))
		goto drop;

	/* L4: IPv4 IHL is variable; bound it before reaching in. */
	if (iph->ihl >= 5 && iph->ihl <= 15) {
		void *l4 = (void *)iph + iph->ihl * 4;

		dport = l4_dport(l4, data_end, iph->protocol);
		if (port_blocked(dport))
			goto drop;
	}

	count(ST_PASS_PKTS, len);
	return XDP_PASS;
drop:
	count(ST_DROP_PKTS, len);
	return XDP_DROP;
}

static __always_inline int verdict_v6(void *l3, void *data_end, __u64 len)
{
	struct ipv6hdr *ip6 = l3;
	__u16 dport;

	if ((void *)(ip6 + 1) > data_end)
		return XDP_PASS;

	if (bpf_map_lookup_elem(&block6, &ip6->saddr))
		goto drop;

	/* L4 only for the common no-extension-header case. */
	dport = l4_dport(ip6 + 1, data_end, ip6->nexthdr);
	if (port_blocked(dport))
		goto drop;

	count(ST_PASS_PKTS, len);
	return XDP_PASS;
drop:
	count(ST_DROP_PKTS, len);
	return XDP_DROP;
}

SEC("xdp")
int xdp_filter(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	__u64 len = data_end - data;
	__u32 ifindex = ctx->ingress_ifindex;
	__u32 *mode = bpf_map_lookup_elem(&mode_map, &ifindex);

	if (mode && *mode == 1) {
		/* raw IP (wwan0): version nibble picks the family */
		__u8 *b = data;

		if (data + 1 > data_end)
			return XDP_PASS;
		if ((*b & 0xf0) == 0x40)
			return verdict_v4(data, data_end, len);
		if ((*b & 0xf0) == 0x60)
			return verdict_v6(data, data_end, len);
		count(ST_PASS_PKTS, len);
		return XDP_PASS;
	}

	/* Ethernet framing (eth0/eth1/wlan) */
	{
		struct ethhdr *eth = data;

		if ((void *)(eth + 1) > data_end)
			return XDP_PASS;
		if (eth->h_proto == bpf_htons(ETH_P_IP))
			return verdict_v4(eth + 1, data_end, len);
		if (eth->h_proto == bpf_htons(ETH_P_IPV6))
			return verdict_v6(eth + 1, data_end, len);
		count(ST_PASS_PKTS, len);
		return XDP_PASS;
	}
}
