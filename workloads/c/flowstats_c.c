/* flowstats_c.c — the hand-written flowstats workload, in C.
 *
 * Kept semantically identical to workloads/flowstats.S so the two can be
 * compared directly: the same map, the same key, the same write-through
 * update.  Its purpose in the evaluation is to price the difference
 * between our assembler's output and a compiler's for one program whose
 * behaviour is otherwise fixed.
 */
#include "ktxbpf.h"

struct stat { __u64 pkts, bytes; };

KTX_MAP(flows, KTX_MAP_HASH, 8, 16, 4096);

SEC("prog")
int flowstats_c(struct ktx_ctx *ctx)
{
    __u8 *data = (__u8 *)(long)ctx->data;
    __u32 len = ctx->len;
    if (len < 24)
        return KTX_PASS;
    __u64 key = *(__u64 *)(data + 16);
    struct stat *s = map_lookup_elem(&flows, &key);
    if (s) {
        s->pkts += 1;
        s->bytes += len;
    } else {
        struct stat ns;
        ns.pkts = 1;
        ns.bytes = len;
        map_update_elem(&flows, &key, &ns, 0);
    }
    return KTX_PASS;
}
