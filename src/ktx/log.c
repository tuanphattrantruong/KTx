/* log.c — per-thread transaction state: bump arena, effect records,
 * read set, read-your-writes table, abort reset (DESIGN §3.2), plus
 * ktx_thread lifecycle, stats, and the per-thread PRNG.
 */
#include <stdlib.h>
#include <string.h>

#include "ktx_internal.h"

/* ---------------- thread lifecycle ---------------- */

ktx_thread *ktx_thread_create(ktx_env *e, int thread_idx) {
    if (!e || thread_idx < 0 || thread_idx >= e->nthreads) return NULL;
    struct ktx_thread *t = calloc(1, sizeof(*t));
    if (!t) return NULL;
    t->arena = malloc(KTX_ARENA_BYTES);
    if (!t->arena) {
        free(t);
        return NULL;
    }
    t->env = e;
    t->idx = thread_idx;
    ktx_thread_set_seed(t, e->seed);
    t->cur_gen = 0;
    t->last_commit_seq = 0;
    ktx_tx_begin(t);                     /* establish generation 1 */
    return t;
}

void ktx_thread_destroy(ktx_thread *t) {
    if (!t) return;
    free(t->arena);
    free(t);
}

void ktx_thread_set_seed(struct ktx_thread *t, uint64_t seed) {
    uint64_t s = seed ^ (uint64_t)(t->idx + 1);
    t->prng = ktx_splitmix64_next(&s);
    if (!t->prng) t->prng = 0x9E3779B97F4A7C15ULL;
}

uint32_t ktx_prandom_u32(struct ktx_thread *t) {
    uint64_t x = t->prng;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    t->prng = x;
    return (uint32_t)((x * 0x2545F4914F6CDD1DULL) >> 32);
}

void ktx_thread_stats_get(const ktx_thread *t, ktx_thread_stats *out) {
    if (!t || !out) return;
    *out = t->stats;
}

void ktx_thread_stats_reset(ktx_thread *t) {
    if (!t) return;
    memset(&t->stats, 0, sizeof(t->stats));
    t->hwm_arena = t->hwm_recs = t->hwm_reads = 0;
}

void ktx_thread_hwm(const ktx_thread *t, uint32_t *arena, uint32_t *recs,
                    uint32_t *reads) {
    if (arena) *arena = t ? t->hwm_arena : 0;
    if (recs)  *recs  = t ? t->hwm_recs  : 0;
    if (reads) *reads = t ? t->hwm_reads : 0;
}

/* ---------------- begin / abort ---------------- */

/* Called at the start of each transaction, while the *previous* one's
 * final footprint is still visible. */
static inline void note_hwm(struct ktx_thread *t) {
    if (t->arena_used > t->hwm_arena) t->hwm_arena = t->arena_used;
    if (t->nrecs > t->hwm_recs)       t->hwm_recs  = t->nrecs;
    if (t->nreads > t->hwm_reads)     t->hwm_reads = t->nreads;
}

void ktx_tx_begin(struct ktx_thread *t) {
    note_hwm(t);
    t->arena_used = 0;
    t->nrecs = 0;
    t->nreads = 0;
    t->ryw_used = 0;
    if (++t->cur_gen == 0) {             /* generation wrap: hard reset */
        memset(t->ryw, 0, sizeof(t->ryw));
        t->cur_gen = 1;
    }
}

void ktx_tx_abort_reset(struct ktx_thread *t) {
    /* O(1): pointer resets + RYW generation bump; shared state, ring
     * buffer and packet untouched. */
    note_hwm(t);
    t->arena_used = 0;
    t->nrecs = 0;
    t->nreads = 0;
    t->ryw_used = 0;
    if (++t->cur_gen == 0) {
        memset(t->ryw, 0, sizeof(t->ryw));
        t->cur_gen = 1;
    }
}

/* ---------------- arena ---------------- */

/* Returns arena offset, or UINT32_MAX on overflow. */
static uint32_t arena_alloc(struct ktx_thread *t, uint32_t len) {
    uint32_t off = (t->arena_used + 7u) & ~7u;
    if (len > KTX_ARENA_BYTES || off > KTX_ARENA_BYTES - len)
        return UINT32_MAX;
    t->arena_used = off + len;
    return off;
}

/* ---------------- read set ---------------- */

ktx_status ktx_readset_add(struct ktx_thread *t, uint16_t map_id,
                           uint16_t stripe, uint64_t ver) {
    for (uint32_t i = 0; i < t->nreads; i++) {
        struct read_ent *re = &t->readset[i];
        if (re->map_id == map_id && re->stripe == stripe && re->ver == ver)
            return KTX_OK;               /* identical entry: dedupe */
        /* same stripe, different version: keep both — validation will
         * detect the inconsistent snapshot and abort. */
    }
    if (t->nreads >= KTX_MAX_READSET) return KTX_ABORT_HELPER;
    t->readset[t->nreads].map_id = map_id;
    t->readset[t->nreads].stripe = stripe;
    t->readset[t->nreads].ver = ver;
    t->nreads++;
    return KTX_OK;
}

/* Current stripe version, spinning past committers (odd). */
static uint64_t stripe_ver_even(struct ktx_map *m, uint32_t s) {
    uint64_t v = atomic_load_explicit(&m->ver[s], memory_order_acquire);
    while (v & 1)
        v = atomic_load_explicit(&m->ver[s], memory_order_acquire);
    return v;
}

/* ---------------- read-your-writes table ---------------- */

/* Probe for (map_id, khash, key).  Returns matching slot, or an empty
 * slot along the probe path (*is_new = 1), or NULL if the table is full.
 * Key bytes are verified against the record's arena key so hash aliases
 * cannot cross-contaminate. */
static struct ryw_slot *ryw_probe(struct ktx_thread *t, uint16_t map_id,
                                  uint64_t khash, const void *key,
                                  uint32_t key_size, int *is_new) {
    uint32_t slot = (uint32_t)(khash ^ ((uint64_t)map_id * 0x9E3779B9ULL)) &
                    (KTX_RYW_SLOTS - 1);
    struct ryw_slot *first_empty = NULL;
    for (uint32_t probe = 0; probe < KTX_RYW_SLOTS; probe++) {
        struct ryw_slot *sl = &t->ryw[(slot + probe) & (KTX_RYW_SLOTS - 1)];
        if (sl->gen != t->cur_gen) {
            if (!first_empty) first_empty = sl;
            /* Empty slot terminates the cluster for this generation only
             * if the table was never full this gen; since deletions never
             * happen within a gen, an empty slot ends the probe chain. */
            *is_new = 1;
            return first_empty;
        }
        if (sl->map_id == map_id && sl->khash == khash) {
            const struct eff_rec *r = &t->recs[sl->rec];
            if (memcmp(t->arena + r->key_off, key, key_size) == 0) {
                *is_new = 0;
                return sl;
            }
        }
    }
    *is_new = 1;
    return NULL;                         /* full */
}

/* Insert or update the RYW entry for a key to point at record rec_idx. */
static ktx_status ryw_upsert(struct ktx_thread *t, struct ktx_map *m,
                             uint64_t khash, const void *key,
                             uint32_t rec_idx) {
    int is_new = 0;
    struct ryw_slot *sl = ryw_probe(t, (uint16_t)m->id, khash, key,
                                    m->key_size, &is_new);
    if (!sl) return KTX_ABORT_HELPER;    /* RYW overflow */
    if (is_new) {
        if (t->ryw_used >= KTX_RYW_SLOTS) return KTX_ABORT_HELPER;
        sl->gen = t->cur_gen;
        sl->map_id = (uint16_t)m->id;
        sl->khash = khash;
        t->ryw_used++;
    }
    sl->rec = rec_idx;
    return KTX_OK;
}

/* ---------------- log-side helper operations ---------------- */

/* Append an EFF_UPDATE with key+val copied into the arena; register in
 * RYW; record the target stripe version for shared maps (blind writes
 * validate). */
ktx_status ktx_tx_update(struct ktx_thread *t, struct ktx_map *m,
                         const void *key, const void *val) {
    if (t->nrecs >= KTX_MAX_RECORDS) return KTX_ABORT_HELPER;
    uint32_t koff = arena_alloc(t, m->key_size);
    uint32_t voff = arena_alloc(t, m->value_size);
    if (koff == UINT32_MAX || voff == UINT32_MAX) return KTX_ABORT_HELPER;
    memcpy(t->arena + koff, key, m->key_size);
    memcpy(t->arena + voff, val, m->value_size);

    uint64_t khash = ktx_hash64(key, m->key_size);
    uint32_t rec_idx = t->nrecs;
    struct eff_rec *r = &t->recs[rec_idx];
    r->kind = EFF_UPDATE;
    r->map_id = (uint16_t)m->id;
    r->key_off = koff;
    r->val_off = voff;
    r->len = 0;
    r->pkt_off = 0;
    r->orig_off = 0;
    t->nrecs++;

    if (m->type != KTX_MAP_PERCPU_ARRAY) {
        uint32_t s;
        if (m->type == KTX_MAP_ARRAY) {
            uint32_t idx;
            memcpy(&idx, key, 4);
            s = ktx_array_stripe(idx);
        } else {
            s = ktx_hash_stripe(m, khash);
        }
        ktx_status st = ktx_readset_add(t, (uint16_t)m->id, (uint16_t)s,
                                        stripe_ver_even(m, s));
        if (st != KTX_OK) return st;
    }
    return ryw_upsert(t, m, khash, key, rec_idx);
}

ktx_status ktx_tx_delete(struct ktx_thread *t, struct ktx_map *m,
                         const void *key, int *present_out) {
    if (t->nrecs >= KTX_MAX_RECORDS) return KTX_ABORT_HELPER;
    uint32_t koff = arena_alloc(t, m->key_size);
    if (koff == UINT32_MAX) return KTX_ABORT_HELPER;
    memcpy(t->arena + koff, key, m->key_size);

    uint64_t khash = ktx_hash64(key, m->key_size);

    /* Presence at log time (RYW first, else a validated snapshot); the
     * stripe version enters the read set so blind deletes validate. */
    int present;
    int is_new = 0;
    struct ryw_slot *sl = ryw_probe(t, (uint16_t)m->id, khash, key,
                                    m->key_size, &is_new);
    if (sl && !is_new) {
        present = (t->recs[sl->rec].kind == EFF_UPDATE ||
                   t->recs[sl->rec].kind == EFF_SHADOW);
        /* stripe version already recorded by the op that made the entry */
    } else {
        uint16_t stripe;
        uint64_t ver;
        void *p = ktx_map_snapshot_ptr(m, key, khash, &stripe, &ver);
        present = (p != NULL);
        ktx_status st = ktx_readset_add(t, (uint16_t)m->id, stripe, ver);
        if (st != KTX_OK) return st;
    }

    uint32_t rec_idx = t->nrecs;
    struct eff_rec *r = &t->recs[rec_idx];
    r->kind = EFF_DELETE;
    r->map_id = (uint16_t)m->id;
    r->key_off = koff;
    r->val_off = 0;
    r->len = 0;
    r->pkt_off = 0;
    r->orig_off = 0;
    t->nrecs++;

    ktx_status st = ryw_upsert(t, m, khash, key, rec_idx);
    if (st != KTX_OK) return st;
    if (present_out) *present_out = present;
    return KTX_OK;
}

ktx_status ktx_tx_lookup(struct ktx_thread *t, struct ktx_map *m,
                         const void *key, int ro_elide,
                         void **val_out, int *is_shared_out) {
    *val_out = NULL;
    *is_shared_out = 0;
    uint64_t khash = ktx_hash64(key, m->key_size);

    /* 1. read-your-writes */
    int is_new = 0;
    struct ryw_slot *sl = ryw_probe(t, (uint16_t)m->id, khash, key,
                                    m->key_size, &is_new);
    if (sl && !is_new) {
        struct eff_rec *r = &t->recs[sl->rec];
        if (r->kind == EFF_DELETE) return KTX_OK;          /* NULL */
        *val_out = t->arena + r->val_off;                  /* EFF_UPDATE */
        return KTX_OK;
    }

    /* 2a. per-CPU: shadow the owner slice; no read set, no stripes. */
    if (m->type == KTX_MAP_PERCPU_ARRAY) {
        uint32_t idx;
        memcpy(&idx, key, 4);
        if (idx >= m->max_entries) return KTX_OK;          /* NULL */
        if (t->nrecs >= KTX_MAX_RECORDS) return KTX_ABORT_HELPER;
        uint32_t koff = arena_alloc(t, m->key_size);
        uint32_t voff = arena_alloc(t, m->value_size);
        uint32_t ooff = arena_alloc(t, m->value_size);
        if (koff == UINT32_MAX || voff == UINT32_MAX || ooff == UINT32_MAX)
            return KTX_ABORT_HELPER;
        memcpy(t->arena + koff, key, m->key_size);
        memcpy(t->arena + voff,
               m->values + ((size_t)t->idx * m->max_entries + idx) *
                               m->value_size,
               m->value_size);
        memcpy(t->arena + ooff, t->arena + voff, m->value_size);
        uint32_t rec_idx = t->nrecs;
        struct eff_rec *r = &t->recs[rec_idx];
        r->kind = EFF_SHADOW;
        r->map_id = (uint16_t)m->id;
        r->key_off = koff;
        r->val_off = voff;
        r->len = 0;
        r->pkt_off = 0;
        r->orig_off = ooff;
        t->nrecs++;
        ktx_status st = ryw_upsert(t, m, khash, key, rec_idx);
        if (st != KTX_OK) return st;
        *val_out = t->arena + voff;
        return KTX_OK;
    }

    /* Bounds for arrays (out of range -> NULL, no read-set entry needed:
     * absence of an out-of-range index is static). */
    if (m->type == KTX_MAP_ARRAY) {
        uint32_t idx;
        memcpy(&idx, key, 4);
        if (idx >= m->max_entries) return KTX_OK;          /* NULL */
    }

    /* 2b. read-only-proven map (tx-elide): validate-only direct pointer. */
    if (ro_elide) {
        uint16_t stripe;
        uint64_t ver;
        void *p = ktx_map_snapshot_ptr(m, key, khash, &stripe, &ver);
        ktx_status st = ktx_readset_add(t, (uint16_t)m->id, stripe, ver);
        if (st != KTX_OK) return st;
        *val_out = p;                    /* NULL if absent */
        *is_shared_out = (p != NULL);
        return KTX_OK;
    }

    /* 2c. shared map: seqlock snapshot into an arena shadow. */
    if (t->nrecs >= KTX_MAX_RECORDS) return KTX_ABORT_HELPER;
    uint32_t saved = t->arena_used;
    uint32_t koff = arena_alloc(t, m->key_size);
    uint32_t voff = arena_alloc(t, m->value_size);
    if (koff == UINT32_MAX || voff == UINT32_MAX) return KTX_ABORT_HELPER;
    memcpy(t->arena + koff, key, m->key_size);

    uint16_t stripe;
    uint64_t ver;
    int found = ktx_map_snapshot(m, key, khash, t->arena + voff,
                                 &stripe, &ver);
    ktx_status st = ktx_readset_add(t, (uint16_t)m->id, stripe, ver);
    if (st != KTX_OK) return st;
    if (!found) {
        t->arena_used = saved;           /* roll back the unused shadow */
        return KTX_OK;                   /* NULL; absence validates */
    }
    /* Pristine copy of the snapshot, so commit can tell whether the
     * program actually modified the value it was handed. */
    uint32_t ooff = arena_alloc(t, m->value_size);
    if (ooff == UINT32_MAX) return KTX_ABORT_HELPER;
    memcpy(t->arena + ooff, t->arena + voff, m->value_size);
    uint32_t rec_idx = t->nrecs;
    struct eff_rec *r = &t->recs[rec_idx];
    r->kind = EFF_SHADOW;                /* written back only if modified */
    r->map_id = (uint16_t)m->id;
    r->key_off = koff;
    r->val_off = voff;
    r->len = 0;
    r->pkt_off = 0;
    r->orig_off = ooff;
    t->nrecs++;
    st = ryw_upsert(t, m, khash, key, rec_idx);
    if (st != KTX_OK) return st;
    *val_out = t->arena + voff;
    return KTX_OK;
}

ktx_status ktx_tx_ringbuf(struct ktx_thread *t, const void *msg,
                          uint32_t len) {
    if (t->nrecs >= KTX_MAX_RECORDS) return KTX_ABORT_HELPER;
    uint32_t voff = arena_alloc(t, len);
    if (voff == UINT32_MAX) return KTX_ABORT_HELPER;
    memcpy(t->arena + voff, msg, len);
    struct eff_rec *r = &t->recs[t->nrecs++];
    r->kind = EFF_RINGBUF;
    r->map_id = 0;
    r->key_off = 0;
    r->val_off = voff;
    r->len = len;
    r->pkt_off = 0;
    r->orig_off = 0;
    return KTX_OK;
}

ktx_status ktx_tx_pktwrite(struct ktx_thread *t, uint32_t pkt_off,
                           const void *data, uint32_t len) {
    if (t->nrecs >= KTX_MAX_RECORDS) return KTX_ABORT_HELPER;
    uint32_t voff = arena_alloc(t, len);
    if (voff == UINT32_MAX) return KTX_ABORT_HELPER;
    memcpy(t->arena + voff, data, len);
    struct eff_rec *r = &t->recs[t->nrecs++];
    r->kind = EFF_PKTWRITE;
    r->map_id = 0;
    r->key_off = 0;
    r->val_off = voff;
    r->len = len;
    r->pkt_off = pkt_off;
    r->orig_off = 0;
    return KTX_OK;
}
