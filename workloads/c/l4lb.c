/* l4lb.c — an L4 load balancer in the shape of a production one.
 *
 * Written to be representative rather than minimal: it parses a header
 * out of the packet under explicit bounds checks, hashes a five-tuple,
 * consults a connection table, falls back to a Maglev-style backend
 * lookup table on a miss and *installs* the flow, updates per-backend
 * statistics, rewrites the packet, and reports new flows on a ring
 * buffer.  Four maps are written in one invocation, which is the
 * structure the corpus survey found common in real dataplanes and the
 * structure a per-map atomicity guarantee cannot protect.
 */
#include "ktxbpf.h"

/* Conntrack key: the canonical flow identifier plus protocol.
 * Keyed on the flow, not the raw 5-tuple, so the table has the bounded
 * working set a real deployment sizes for; the 5-tuple is still parsed
 * (and bounds-checked) because it feeds the backend hash. */
struct flow_key { __u64 flow; __u32 proto; __u32 _pad; };
struct conn     { __u32 backend; __u32 gen; __u64 last_ns; };
struct bstat    { __u64 pkts, bytes; };
struct newflow  { __u32 src, dst, backend; __u32 _pad; };

KTX_MAP(lb_conn,    KTX_MAP_HASH,         16, 16, 4096);
KTX_MAP(lb_table,   KTX_MAP_ARRAY,         4,  4, 4096);
KTX_MAP(lb_stats,   KTX_MAP_HASH,          4, 16, 4096);
KTX_MAP(lb_metrics, KTX_MAP_PERCPU_ARRAY,  4, 16,    4);
KTX_MAP(lb_events,  KTX_MAP_ARRAY,         4,  4,    1);   /* ring handle */

static __always_inline __u64 mix(__u64 h)
{
    h ^= h >> 30; h *= 0xBF58476D1CE4E5B9ULL;
    h ^= h >> 27; h *= 0x94D049BB133111EBULL;
    return h ^ (h >> 31);
}

SEC("prog")
int l4lb(struct ktx_ctx *ctx)
{
    __u8 *data = (__u8 *)(long)ctx->data;
    __u32 len = ctx->len;
    if (len < 40)
        return KTX_PASS;

    /* five-tuple, read field by field so every access is a bounded load */
    __u32 src   = *(__u32 *)(data + 0);
    __u32 dst   = *(__u32 *)(data + 4);
    __u16 sport = *(__u16 *)(data + 8);
    __u16 dport = *(__u16 *)(data + 10);
    struct flow_key k;
    k.flow  = *(__u64 *)(data + 16);
    k.proto = data[12];
    k._pad  = 0;

    __u64 h = mix(((__u64)src << 32) | dst);
    h = mix(h ^ (((__u64)sport << 16) | dport));

    struct conn *c = map_lookup_elem(&lb_conn, &k);
    __u32 backend;
    if (c) {
        backend = c->backend;
        c->last_ns = ktime_get_ns();       /* write-through the shadow */
    } else {
        __u32 slot = (__u32)(h & 4095);
        __u32 *b = map_lookup_elem(&lb_table, &slot);
        if (!b)
            return KTX_PASS;
        backend = *b;
        struct conn nc;
        nc.backend = backend;
        nc.gen     = (__u32)(h >> 32);
        nc.last_ns = ktime_get_ns();
        map_update_elem(&lb_conn, &k, &nc, 0);
        struct newflow ev;
        ev.src = src; ev.dst = dst; ev.backend = backend; ev._pad = 0;
        ringbuf_output(&lb_events, &ev, sizeof(ev), 0);
    }

    /* per-backend counters (shared) and per-CPU totals */
    struct bstat *st = map_lookup_elem(&lb_stats, &backend);
    if (st) {
        st->pkts += 1;
        st->bytes += len;
    } else {
        struct bstat ns;
        ns.pkts = 1;
        ns.bytes = len;
        map_update_elem(&lb_stats, &backend, &ns, 0);
    }
    __u32 zero = 0;
    struct bstat *tot = map_lookup_elem(&lb_metrics, &zero);
    if (tot) {
        tot->pkts += 1;
        tot->bytes += len;
    }

    /* encapsulation stub: rewrite the destination with the backend id */
    __u32 be = backend;
    packet_store_bytes(ctx, 4, &be, sizeof(be));
    return KTX_PASS;
}
