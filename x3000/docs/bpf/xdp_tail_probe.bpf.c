// Minimal discriminator: does bpf_xdp_adjust_tail() have room to grow?
//
// 999 allocates XDP_PACKET_HEADROOM + datagram + SKB_DATA_ALIGN(sizeof
// (struct skb_shared_info)) and nothing else, so xdp_data_hard_end() lands
// at the end of the datagram and growing the tail must fail with -EINVAL.
// The generic path runs the program over an skb whose allocation kmalloc
// rounded up, so the same call normally succeeds. Both attach through the
// same ndo_bpf and are indistinguishable from userspace otherwise.
//
// tailprobe[0] packets seen   r[1] grow refused   r[2] last return value

#define SEC(N) __attribute__((section(N), used))
#define __uint(n, v) int (*n)[v]
#define __type(n, v) typeof(v) *n

typedef unsigned int __u32;
typedef unsigned long long __u64;

struct xdp_md { __u32 data, data_end, data_meta, ingress_ifindex,
                rx_queue_index, egress_ifindex; };

static void *(*lookup)(void *, const void *) = (void *)1;
static long (*adjust_tail)(struct xdp_md *, int) = (void *)65;

struct {
    __uint(type, 2);          /* BPF_MAP_TYPE_ARRAY */
    __uint(max_entries, 3);
    __type(key, __u32);
    __type(value, __u64);
} tailprobe SEC(".maps");

SEC("xdp")
int xdp_tail_probe(struct xdp_md *ctx)
{
    __u32 k;
    __u64 *v;
    long ret;

    k = 0;
    v = lookup(&tailprobe, &k);
    if (v)
        __sync_fetch_and_add(v, 1);

    ret = adjust_tail(ctx, 64);

    k = 2;
    v = lookup(&tailprobe, &k);
    if (v)
        *v = (__u64)(long long)ret;

    if (ret == 0) {
        /* It grew. Put it back - this runs on live traffic. */
        adjust_tail(ctx, -64);
    } else {
        k = 1;
        v = lookup(&tailprobe, &k);
        if (v)
            __sync_fetch_and_add(v, 1);
    }

    return 2;                 /* XDP_PASS */
}

char _license[] SEC("license") = "GPL";
