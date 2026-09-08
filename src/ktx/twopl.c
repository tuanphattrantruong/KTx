/* twopl.c — the pessimistic strawman: "extend bpf_spin_lock across maps".
 *
 * This is the incremental alternative to KTx that a reviewer would
 * naturally propose: keep eBPF's immediate-effect helper semantics, but
 * let one invocation hold stripe locks across several maps, taking each
 * lock on first touch and holding it to program exit (strict two-phase
 * locking).  It is implemented here so the comparison can be *measured*
 * rather than argued.
 *
 * Two properties fall out of the design and are what the evaluation
 * reports:
 *   1. Locks are acquired in *program* order, not a global order, so
 *      cycles are possible.  There is no rollback to break them with, so
 *      the only escape is a bounded spin followed by an abort — and that
 *      abort leaves the effects already applied in place.
 *   2. Because effects are direct, any mid-invocation stop (fuel
 *      exhaustion, guard trap) tears exactly the state KTx rolls back.
 */
#include <string.h>

#include "ktx_internal.h"

static uint32_t key_stripe(struct ktx_map *m, const void *key) {
    if (m->type == KTX_MAP_ARRAY) {
        uint32_t idx;
        memcpy(&idx, key, 4);
        return ktx_array_stripe(idx);
    }
    return ktx_hash_stripe(m, ktx_hash64(key, m->key_size));
}

ktx_status ktx_2pl_acquire(struct ktx_exec *ex, struct ktx_map *m,
                           const void *key) {
    if (m->type == KTX_MAP_PERCPU_ARRAY) return KTX_OK;  /* thread-private */
    uint32_t s = key_stripe(m, key);
    for (uint32_t i = 0; i < ex->nheld; i++)
        if (ex->held[i].map_id == m->id && ex->held[i].stripe == s)
            return KTX_OK;                               /* already held */
    if (ex->nheld >= KTX_MAX_HELD) return KTX_ABORT_HELPER;

    _Atomic uint64_t *vp = &m->ver[s];
    int attempts = 0;
    for (;;) {
        uint64_t v = atomic_load_explicit(vp, memory_order_relaxed);
        if (!(v & 1) &&
            atomic_compare_exchange_weak_explicit(vp, &v, v + 1,
                                                  memory_order_acquire,
                                                  memory_order_relaxed)) {
            ex->held[ex->nheld].map_id = (uint16_t)m->id;
            ex->held[ex->nheld].stripe = (uint16_t)s;
            ex->held[ex->nheld].prelock = v;
            ex->nheld++;
            return KTX_OK;
        }
        /* No global lock order and nothing to roll back: a cycle can only
         * be broken by giving up, and giving up does not undo. */
        if (++attempts >= KTX_LOCK_SPIN) return KTX_ABORT_DEADLOCK;
    }
}

void ktx_2pl_release_all(struct ktx_exec *ex) {
    for (uint32_t i = 0; i < ex->nheld; i++) {
        struct ktx_map *m = ex->env->maps[ex->held[i].map_id];
        /* Publish a version bump: an invocation that held a stripe may
         * have stored through a value pointer without calling a helper. */
        atomic_store_explicit(&m->ver[ex->held[i].stripe],
                              ex->held[i].prelock + 2, memory_order_release);
    }
    ex->nheld = 0;
}

void ktx_p2pl_acquire_all(struct ktx_exec *ex) {
    ex->nheld_maps = 0;
    /* Program map ids can be declared in arbitrary order and may alias an
     * environment map.  Select unique ids in ascending order. */
    for (uint32_t id = 0; id < ex->env->nmaps; id++) {
        int used = 0;
        for (uint32_t p = 0; p < ex->prog->n_maps; p++)
            if (ex->prog->map_env_id[p] == id) { used = 1; break; }
        if (!used || ex->env->maps[id]->type == KTX_MAP_PERCPU_ARRAY) continue;
        _Atomic uint32_t *lp = &ex->env->maps[id]->invoke_lock;
        for (;;) {
            uint32_t expected = 0;
            if (atomic_compare_exchange_weak_explicit(
                    lp, &expected, 1, memory_order_acquire,
                    memory_order_relaxed))
                break;
        }
        ex->held_maps[ex->nheld_maps++] = (uint16_t)id;
    }
}

void ktx_p2pl_release_all(struct ktx_exec *ex) {
    /* Reverse order is conventional and makes nested extensions composable. */
    while (ex->nheld_maps > 0) {
        uint32_t id = ex->held_maps[--ex->nheld_maps];
        atomic_store_explicit(&ex->env->maps[id]->invoke_lock, 0,
                              memory_order_release);
    }
}

int ktx_2pl_update(struct ktx_map *m, const void *key, const void *val,
                   int thread_idx) {
    if (m->type == KTX_MAP_ARRAY) {
        uint32_t idx;
        memcpy(&idx, key, 4);
        if (idx >= m->max_entries) return -1;
        memcpy(m->values + (size_t)idx * m->value_size, val, m->value_size);
        return 0;
    }
    if (m->type == KTX_MAP_PERCPU_ARRAY) {
        uint32_t idx;
        memcpy(&idx, key, 4);
        if (idx >= m->max_entries) return -1;
        memcpy(m->values +
                   ((size_t)thread_idx * m->max_entries + idx) * m->value_size,
               val, m->value_size);
        return 0;
    }
    uint64_t hash = ktx_hash64(key, m->key_size);
    if (!ktx_map_locked_present(m, hash, key)) {
        int32_t prev = atomic_fetch_sub_explicit(&m->free_count, 1,
                                                 memory_order_relaxed);
        if (prev <= 0) {
            atomic_fetch_add_explicit(&m->free_count, 1, memory_order_relaxed);
            return -1;                    /* map full */
        }
    }
    ktx_map_locked_upsert(m, hash, key, val);
    return 0;
}

int ktx_2pl_delete(struct ktx_map *m, const void *key) {
    if (m->type != KTX_MAP_HASH) return -2;
    uint64_t hash = ktx_hash64(key, m->key_size);
    uint32_t freed = ktx_map_locked_delete(m, hash, key);
    if (!freed) return -2;
    ktx_pool_push(m, freed);
    return 0;
}
