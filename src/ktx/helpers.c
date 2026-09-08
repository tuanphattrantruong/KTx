/* helpers.c — helper dispatch (DESIGN §3.5), both direct and tx paths,
 * plus time, per-thread PRNG use, and the env ring buffer.
 */
#include <mach/mach_time.h>
#include <string.h>

#include "ktx_internal.h"

/* ---------------- time ---------------- */

uint64_t ktx_time_ns(struct ktx_env *e) {
    return mach_absolute_time() * e->tb_num / e->tb_denom;
}

/* ---------------- ring buffer ---------------- */

static inline void ring_acquire(struct ktx_env *e) {
    uint32_t exp = 0;
    while (!atomic_compare_exchange_weak_explicit(&e->ring_lock, &exp, 1,
                                                  memory_order_acquire,
                                                  memory_order_relaxed))
        exp = 0;
}
static inline void ring_release(struct ktx_env *e) {
    atomic_store_explicit(&e->ring_lock, 0, memory_order_release);
}

void ktx_ringbuf_append(struct ktx_env *e, const void *msg, uint32_t len) {
    ring_acquire(e);
    uint32_t needed = 4 + len;
    if (e->ring_used + needed > KTX_RING_BYTES)
        e->ring_used = 0;                /* wrap: overwrite oldest */
    memcpy(e->ring + e->ring_used, &len, 4);
    memcpy(e->ring + e->ring_used + 4, msg, len);
    e->ring_used += (needed + 7u) & ~7u;
    ring_release(e);
    atomic_fetch_add_explicit(&e->ring_count, 1, memory_order_relaxed);
}

uint64_t ktx_ringbuf_count(ktx_env *e) {
    return e ? atomic_load_explicit(&e->ring_count, memory_order_acquire) : 0;
}

void ktx_ringbuf_reset(ktx_env *e) {
    if (!e) return;
    ring_acquire(e);
    e->ring_used = 0;
    atomic_store_explicit(&e->ring_count, 0, memory_order_release);
    ring_release(e);
}

/* ---------------- helper dispatch ---------------- */

static struct ktx_map *handle_to_map(ktx_exec *ex, uint64_t h,
                                     uint32_t *pidx) {
    if ((h & KTX_MAP_HANDLE_TAG_MASK) != KTX_MAP_HANDLE_TAG) return NULL;
    uint32_t idx = (uint32_t)h;
    if (idx >= ex->prog->n_maps) return NULL;
    *pidx = idx;
    return ex->env->maps[ex->prog->map_env_id[idx]];
}

#define HELPER_ABORT(st_) do { ex->status = (st_); return 0; } while (0)

/* Readable-region check for a helper pointer argument (sfi/tx modes;
 * vanilla trusts, as the verifier would have proven it). */
static inline int arg_readable(ktx_exec *ex, uint64_t p, uint32_t size) {
    if (!ex->check_args) return 1;
    return ktx_guard_ok(ex, p, size, /*write=*/0);
}

uint64_t ktx_helper_call(ktx_exec *ex, uint64_t *r, int32_t imm) {
    switch (imm) {

    case KTX_HELPER_MAP_LOOKUP: {
        uint32_t pidx;
        struct ktx_map *m = handle_to_map(ex, r[1], &pidx);
        if (!m) HELPER_ABORT(KTX_ABORT_HELPER);
        if (!arg_readable(ex, r[2], m->key_size))
            HELPER_ABORT(KTX_ABORT_HELPER);
        const void *key = (const void *)(uintptr_t)r[2];

        if (ex->twopl) {                 /* 2PL: lock the stripe, keep it */
            ktx_status ls = ktx_2pl_acquire(ex, m, key);
            if (ls != KTX_OK) HELPER_ABORT(ls);
        }
        if (!ex->tx) {                   /* vanilla / sfi / 2pl: shared ptr */
            void *v = ktx_map_direct_lookup(m, key, ex->th->idx);
            if (v && ex->check_args &&
                ktx_region_add(ex, (uint64_t)(uintptr_t)v,
                               (uint64_t)(uintptr_t)v + m->value_size,
                               /*rw=*/1) != 0)
                HELPER_ABORT(KTX_ABORT_HELPER);
            return (uint64_t)(uintptr_t)v;
        }

        int ro = ex->ro_elide && ex->prog->map_ro[pidx];
        void *val = NULL;
        int shared = 0;
        ktx_status st = ktx_tx_lookup(ex->th, m, key, ro, &val, &shared);
        if (st != KTX_OK) HELPER_ABORT(st);
        if (val &&
            ktx_region_add(ex, (uint64_t)(uintptr_t)val,
                           (uint64_t)(uintptr_t)val + m->value_size,
                           /*rw=*/shared ? 0 : 1) != 0)
            HELPER_ABORT(KTX_ABORT_HELPER);
        return (uint64_t)(uintptr_t)val;
    }

    case KTX_HELPER_MAP_UPDATE: {
        uint32_t pidx;
        struct ktx_map *m = handle_to_map(ex, r[1], &pidx);
        if (!m) HELPER_ABORT(KTX_ABORT_HELPER);
        if (r[4] != 0) HELPER_ABORT(KTX_ABORT_HELPER);  /* flags: ANY only */
        if (ex->audit) {
            ex->th->stats.elide_audited++;
            if (ex->prog->map_ro[pidx]) ex->th->stats.elide_faults++;
        }
        if (!arg_readable(ex, r[2], m->key_size) ||
            !arg_readable(ex, r[3], m->value_size))
            HELPER_ABORT(KTX_ABORT_HELPER);
        const void *key = (const void *)(uintptr_t)r[2];
        const void *val = (const void *)(uintptr_t)r[3];

        if (ex->twopl) {
            ktx_status ls = ktx_2pl_acquire(ex, m, key);
            if (ls != KTX_OK) HELPER_ABORT(ls);
            return (uint64_t)(int64_t)ktx_2pl_update(m, key, val,
                                                     ex->th->idx);
        }
        if (!ex->tx)
            return (uint64_t)(int64_t)ktx_map_direct_update(m, key, val,
                                                            ex->th->idx);

        if (m->type == KTX_MAP_ARRAY || m->type == KTX_MAP_PERCPU_ARRAY) {
            uint32_t idx;
            memcpy(&idx, key, 4);
            if (idx >= m->max_entries) return (uint64_t)(int64_t)-1;
        }
        ktx_status st = ktx_tx_update(ex->th, m, key, val);
        if (st != KTX_OK) HELPER_ABORT(st);
        return 0;
    }

    case KTX_HELPER_MAP_DELETE: {
        uint32_t pidx;
        struct ktx_map *m = handle_to_map(ex, r[1], &pidx);
        if (!m) HELPER_ABORT(KTX_ABORT_HELPER);
        if (!arg_readable(ex, r[2], m->key_size))
            HELPER_ABORT(KTX_ABORT_HELPER);
        const void *key = (const void *)(uintptr_t)r[2];

        if (ex->audit) {
            ex->th->stats.elide_audited++;
            if (ex->prog->map_ro[pidx]) ex->th->stats.elide_faults++;
        }
        if (ex->twopl) {
            ktx_status ls = ktx_2pl_acquire(ex, m, key);
            if (ls != KTX_OK) HELPER_ABORT(ls);
            return (uint64_t)(int64_t)ktx_2pl_delete(m, key);
        }
        if (!ex->tx)
            return (uint64_t)(int64_t)ktx_map_direct_delete(m, key);

        if (m->type != KTX_MAP_HASH) return (uint64_t)(int64_t)-2;
        int present = 0;
        ktx_status st = ktx_tx_delete(ex->th, m, key, &present);
        if (st != KTX_OK) HELPER_ABORT(st);
        return present ? 0 : (uint64_t)(int64_t)-2;
    }

    case KTX_HELPER_KTIME_GET_NS:
        return ktx_time_ns(ex->env);

    case KTX_HELPER_GET_PRANDOM_U32:
        return ktx_prandom_u32(ex->th);

    case KTX_HELPER_PKT_STORE_BYTES: {
        /* packet_store_bytes(ctx, off, ptr, len): r1 ctx (trusted),
         * r2 off, r3 src ptr, r4 len.  Out-of-bounds returns -1, NOT
         * an abort (DESIGN §3.3). */
        uint64_t off = r[2], src = r[3], len = r[4];
        if (len > ex->pkt_len || off > ex->pkt_len - len)
            return (uint64_t)(int64_t)-1;
        if (len == 0) return 0;
        if (!arg_readable(ex, src, (uint32_t)len))
            HELPER_ABORT(KTX_ABORT_HELPER);
        const void *p = (const void *)(uintptr_t)src;
        if (ex->tx) {
            ktx_status st = ktx_tx_pktwrite(ex->th, (uint32_t)off, p,
                                            (uint32_t)len);
            if (st != KTX_OK) HELPER_ABORT(st);
        } else {
            memcpy(ex->pkt + off, p, len);
        }
        return 0;
    }

    case KTX_HELPER_RINGBUF_OUTPUT: {
        /* ringbuf_output(0, ptr, size, 0): size > 512 returns -1. */
        uint64_t src = r[2], len = r[3];
        if (len == 0 || len > KTX_RING_MAX_MSG)
            return (uint64_t)(int64_t)-1;
        if (!arg_readable(ex, src, (uint32_t)len))
            HELPER_ABORT(KTX_ABORT_HELPER);
        const void *p = (const void *)(uintptr_t)src;
        if (ex->tx) {
            ktx_status st = ktx_tx_ringbuf(ex->th, p, (uint32_t)len);
            if (st != KTX_OK) HELPER_ABORT(st);
        } else {
            ktx_ringbuf_append(ex->env, p, (uint32_t)len);
        }
        return 0;
    }

    default:
        /* decode validates helper ids; defensive */
        HELPER_ABORT(KTX_ABORT_HELPER);
    }
}
