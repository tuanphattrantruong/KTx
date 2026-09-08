/* policy.c — a container-network policy path in the shape of Cilium's.
 *
 * Identity-based policy lookup, connection tracking with a new/established
 * distinction, a metrics counter, and a verdict that is the policy
 * decision.  Three maps are written in one invocation and the verdict
 * depends on all three, which makes it the natural exhibit for both the
 * cross-map invariant (\S ct/policy agreement) and the abort-policy
 * question (an abort that returns the default verdict is a policy event).
 */
#include "ktxbpf.h"

/* Keyed on the canonical flow identifier: a conntrack table has a
 * bounded working set, and keying on a per-packet-random 5-tuple would
 * simply exhaust it. */
struct ct_key   { __u64 flow; __u32 identity; __u32 _pad; };
struct ct_entry { __u32 verdict; __u32 gen; __u64 last_ns; };
struct pol_key  { __u32 identity; __u32 dport; };

KTX_MAP(pol_ct,      KTX_MAP_HASH,         16, 16, 4096);
KTX_MAP(pol_rules,   KTX_MAP_HASH,          8,  8, 4096);
KTX_MAP(pol_metrics, KTX_MAP_PERCPU_ARRAY,  4, 16,    8);

SEC("prog")
int policy(struct ktx_ctx *ctx)
{
    __u8 *data = (__u8 *)(long)ctx->data;
    __u32 len = ctx->len;
    if (len < 40)
        return KTX_PASS;

    __u32 src   = *(__u32 *)(data + 0);
    __u16 dport = *(__u16 *)(data + 10);
    struct ct_key k;
    k.flow     = *(__u64 *)(data + 16);
    k.identity = src & 0x3ff;
    k._pad     = 0;

    __u32 verdict;
    struct ct_entry *c = map_lookup_elem(&pol_ct, &k);
    if (c) {
        verdict = c->verdict;               /* established: reuse decision */
        c->last_ns = ktime_get_ns();
    } else {
        struct pol_key pk;
        pk.identity = k.identity;
        pk.dport    = dport & 7;
        __u64 *rule = map_lookup_elem(&pol_rules, &pk);
        verdict = rule ? (__u32)*rule : KTX_PASS;
        struct ct_entry nc;
        nc.verdict = verdict;
        nc.gen     = src;
        nc.last_ns = ktime_get_ns();
        /* The invariant a per-map guarantee cannot protect: an entry in
         * pol_ct must carry the verdict pol_rules would have produced. */
        map_update_elem(&pol_ct, &k, &nc, 0);
    }

    __u32 slot = verdict & 7;
    struct { __u64 n, bytes; } *m = map_lookup_elem(&pol_metrics, &slot);
    if (m) {
        m->n += 1;
        m->bytes += len;
    }
    return verdict;
}
