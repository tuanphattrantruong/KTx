/* commit.c — OCC commit protocol, exactly DESIGN §3.4:
 * 1 read-only fast path, 2 collect+sort write stripes, 3 bounded lock,
 * 4 validate read set, 5 capacity reservation, 6 abort-free apply in log
 * order, 7 unlock + push freed nodes.
 */
#include <string.h>

#include "ktx_internal.h"

struct wstripe { uint16_t map_id; uint16_t stripe; uint64_t prelock; };

/* Binary search in the sorted write-stripe set; -1 if absent. */
static int ws_find(const struct wstripe *ws, int n, uint16_t map_id,
                   uint16_t stripe) {
    int lo = 0, hi = n - 1;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        uint32_t a = ((uint32_t)ws[mid].map_id << 16) | ws[mid].stripe;
        uint32_t b = ((uint32_t)map_id << 16) | stripe;
        if (a == b) return mid;
        if (a < b) lo = mid + 1; else hi = mid - 1;
    }
    return -1;
}

/* Insert unique (map_id, stripe), keeping ascending order. */
static int ws_insert(struct wstripe *ws, int n, uint16_t map_id,
                     uint16_t stripe) {
    uint32_t b = ((uint32_t)map_id << 16) | stripe;
    int i = n;
    while (i > 0) {
        uint32_t a = ((uint32_t)ws[i - 1].map_id << 16) | ws[i - 1].stripe;
        if (a == b) return n;            /* already present */
        if (a < b) break;
        i--;
    }
    /* check the slot below the insertion point too (loop exits early) */
    if (i > 0) {
        uint32_t a = ((uint32_t)ws[i - 1].map_id << 16) | ws[i - 1].stripe;
        if (a == b) return n;
    }
    memmove(&ws[i + 1], &ws[i], (size_t)(n - i) * sizeof(*ws));
    ws[i].map_id = map_id;
    ws[i].stripe = stripe;
    return n + 1;
}

/* Stripe of a record's key on map m (shared maps only). */
static uint32_t rec_stripe(const struct ktx_thread *t,
                           const struct ktx_map *m,
                           const struct eff_rec *r, uint64_t *hash_out) {
    if (m->type == KTX_MAP_ARRAY) {
        uint32_t idx;
        memcpy(&idx, t->arena + r->key_off, 4);
        *hash_out = 0;
        return ktx_array_stripe(idx);
    }
    uint64_t h = ktx_hash64(t->arena + r->key_off, m->key_size);
    *hash_out = h;
    return ktx_hash_stripe(m, h);
}

static void ws_unlock_all(struct ktx_env *e, struct wstripe *ws, int n,
                          int restore) {
    /* restore: store the pre-lock value (nothing changed);
     * else: pre-lock + 2 (stripe content changed). */
    for (int j = 0; j < n; j++) {
        struct ktx_map *m = e->maps[ws[j].map_id];
        atomic_store_explicit(&m->ver[ws[j].stripe],
                              restore ? ws[j].prelock : ws[j].prelock + 2,
                              memory_order_release);
    }
}

/* An EFF_SHADOW record is dirty when the program changed the value it was
 * handed.  Clean shadows are pure reads: they are neither locked, nor
 * capacity-reserved, nor written back — only validated (their read-set
 * entry was recorded at lookup time).  This is the commit-time
 * alternative to an eager dirty bit in the store path; see DESIGN.
 * With KTX_OPT_SHADOW_DIFF off, every shadow is treated as dirty, which
 * reproduces the naive redo log. */
int ktx_shadow_dirty(const struct ktx_thread *t, const struct eff_rec *r) {
    const struct ktx_map *m = t->env->maps[r->map_id];
    return memcmp(t->arena + r->val_off, t->arena + r->orig_off,
                  m->value_size) != 0;
}

ktx_status ktx_tx_commit(struct ktx_thread *t, uint8_t *pkt,
                         uint32_t pkt_len) {
    struct ktx_env *e = t->env;

    /* -------- 0. classify records: which will actually mutate? -------- */
    uint8_t apply_rec[KTX_MAX_RECORDS];
    uint32_t napply = 0;
    const int diff = e->opt_shadow_diff;
    for (uint32_t i = 0; i < t->nrecs; i++) {
        const struct eff_rec *r = &t->recs[i];
        uint8_t ap = 1;
        if (r->kind == EFF_SHADOW && diff && !ktx_shadow_dirty(t, r)) ap = 0;
        apply_rec[i] = ap;
        napply += ap;
    }

    /* -------- 1. read-only fast path: nothing to apply, no locks ----- */
    if (napply == 0) {
        for (uint32_t i = 0; i < t->nreads; i++) {
            const struct read_ent *re = &t->readset[i];
            struct ktx_map *m = e->maps[re->map_id];
            uint64_t v = atomic_load_explicit(&m->ver[re->stripe],
                                              memory_order_acquire);
            if ((v & 1) || v != re->ver) return KTX_ABORT_CONFLICT;
        }
        if (e->opt_seq_trace)
            t->last_commit_seq = atomic_fetch_add_explicit(
                &e->commit_seq, 1, memory_order_acq_rel);
        return KTX_OK;
    }

    /* -------- 2. collect the unique write-stripe set, sorted -------- */
    struct wstripe ws[KTX_MAX_RECORDS];
    int nws = 0;
    for (uint32_t i = 0; i < t->nrecs; i++) {
        const struct eff_rec *r = &t->recs[i];
        if (!apply_rec[i]) continue;
        if (r->kind != EFF_UPDATE && r->kind != EFF_DELETE &&
            r->kind != EFF_SHADOW) continue;
        struct ktx_map *m = e->maps[r->map_id];
        if (m->type == KTX_MAP_PERCPU_ARRAY) continue;
        uint64_t h;
        uint32_t s = rec_stripe(t, m, r, &h);
        nws = ws_insert(ws, nws, r->map_id, (uint16_t)s);
    }

    /* -------- 3. lock phase: CAS even->odd, bounded spin -------- */
    for (int j = 0; j < nws; j++) {
        struct ktx_map *m = e->maps[ws[j].map_id];
        _Atomic uint64_t *vp = &m->ver[ws[j].stripe];
        int attempts = 0;
        for (;;) {
            uint64_t v = atomic_load_explicit(vp, memory_order_relaxed);
            if (!(v & 1) &&
                atomic_compare_exchange_weak_explicit(
                    vp, &v, v + 1, memory_order_acquire,
                    memory_order_relaxed)) {
                ws[j].prelock = v;
                break;
            }
            if (++attempts >= KTX_LOCK_SPIN) {
                ws_unlock_all(e, ws, j, /*restore=*/1);
                return KTX_ABORT_CONFLICT;
            }
        }
    }

    /* -------- 4. validate phase -------- */
    for (uint32_t i = 0; i < t->nreads; i++) {
        const struct read_ent *re = &t->readset[i];
        int j = ws_find(ws, nws, re->map_id, re->stripe);
        int ok;
        if (j >= 0) {
            ok = (re->ver == ws[j].prelock);
        } else {
            struct ktx_map *m = e->maps[re->map_id];
            uint64_t v = atomic_load_explicit(&m->ver[re->stripe],
                                              memory_order_acquire);
            ok = !(v & 1) && v == re->ver;
        }
        if (!ok) {
            ws_unlock_all(e, ws, nws, /*restore=*/1);
            return KTX_ABORT_CONFLICT;
        }
    }

    /* -------- 5. capacity reservation (hash-map inserts) -------- */
    int32_t need[KTX_MAX_MAPS];
    memset(need, 0, sizeof(need));
    for (uint32_t i = 0; i < t->nrecs; i++) {
        const struct eff_rec *r = &t->recs[i];
        if (!apply_rec[i]) continue;
        if (r->kind != EFF_UPDATE && r->kind != EFF_SHADOW) continue;
        struct ktx_map *m = e->maps[r->map_id];
        if (m->type != KTX_MAP_HASH) continue;
        uint64_t h = ktx_hash64(t->arena + r->key_off, m->key_size);
        if (!ktx_map_locked_present(m, h, t->arena + r->key_off))
            need[r->map_id]++;           /* per-record: >= true need */
    }
    for (uint32_t mi = 0; mi < e->nmaps; mi++) {
        if (!need[mi]) continue;
        struct ktx_map *m = e->maps[mi];
        int32_t prev = atomic_fetch_sub_explicit(&m->free_count, need[mi],
                                                 memory_order_relaxed);
        if (prev < need[mi]) {           /* went negative: full */
            atomic_fetch_add_explicit(&m->free_count, need[mi],
                                      memory_order_relaxed);
            for (uint32_t k = 0; k < mi; k++)
                if (need[k])
                    atomic_fetch_add_explicit(&e->maps[k]->free_count,
                                              need[k], memory_order_relaxed);
            ws_unlock_all(e, ws, nws, /*restore=*/1);
            return KTX_ABORT_CAPACITY;
        }
    }

    /* -------- 6. apply phase: log order; cannot fail -------- */
    if (e->opt_observer_publish) ktx_publish_begin(e);
    uint32_t freed_node[KTX_MAX_RECORDS];
    uint16_t freed_map[KTX_MAX_RECORDS];
    int nfreed = 0;
    for (uint32_t i = 0; i < t->nrecs; i++) {
        const struct eff_rec *r = &t->recs[i];
        if (!apply_rec[i]) continue;     /* unmodified shadow: pure read */
        switch (r->kind) {
        case EFF_SHADOW:
        case EFF_UPDATE: {
            struct ktx_map *m = e->maps[r->map_id];
            const uint8_t *key = t->arena + r->key_off;
            const uint8_t *val = t->arena + r->val_off;
            if (m->type == KTX_MAP_PERCPU_ARRAY) {
                uint32_t idx;
                memcpy(&idx, key, 4);
                if (idx < m->max_entries)
                    memcpy(m->values +
                               ((size_t)t->idx * m->max_entries + idx) *
                                   m->value_size,
                           val, m->value_size);
            } else if (m->type == KTX_MAP_ARRAY) {
                uint32_t idx;
                memcpy(&idx, key, 4);
                if (idx < m->max_entries)
                    memcpy(m->values + (size_t)idx * m->value_size, val,
                           m->value_size);
            } else {
                uint64_t h = ktx_hash64(key, m->key_size);
                ktx_map_locked_upsert(m, h, key, val);
            }
            break;
        }
        case EFF_DELETE: {
            struct ktx_map *m = e->maps[r->map_id];
            const uint8_t *key = t->arena + r->key_off;
            if (m->type == KTX_MAP_HASH) {
                uint64_t h = ktx_hash64(key, m->key_size);
                uint32_t np1 = ktx_map_locked_delete(m, h, key);
                if (np1) {
                    freed_node[nfreed] = np1;
                    freed_map[nfreed] = r->map_id;
                    nfreed++;
                }
            }
            break;
        }
        case EFF_RINGBUF:
            ktx_ringbuf_append(e, t->arena + r->val_off, r->len);
            break;
        case EFF_PKTWRITE:
            if (pkt && (uint64_t)r->pkt_off + r->len <= pkt_len)
                memcpy(pkt + r->pkt_off, t->arena + r->val_off, r->len);
            break;
        default:
            break;
        }
    }

    /* -------- 7. stamp the serialization point, unlock, push freed ---- */
    /* The stamp is taken while every write stripe is still held, so it
     * orders this commit against every transaction it conflicts with. */
    if (e->opt_seq_trace)
        t->last_commit_seq = atomic_fetch_add_explicit(&e->commit_seq, 1,
                                                       memory_order_acq_rel);
    ws_unlock_all(e, ws, nws, /*restore=*/0);
    if (e->opt_observer_publish) ktx_publish_end(e);
    for (int i = 0; i < nfreed; i++)
        ktx_pool_push(e->maps[freed_map[i]], freed_node[i]);
    return KTX_OK;
}
