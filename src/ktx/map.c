/* map.c — chained hash + array + per-CPU array maps, version stripes,
 * preallocated node pool, hash64 (DESIGN §3.1), and the harness-side
 * public map API (stripe-locked / seqlocked).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ktx_internal.h"

/* Optional environment publication seqlock.  Writers serialize only the
 * already-bounded apply phase; extension execution and validation remain
 * concurrent.  Opt-in observers retry a multi-map copy across an odd or
 * changed sequence. */
void ktx_publish_begin(struct ktx_env *e) {
    for (;;) {
        uint32_t expected = 0;
        if (atomic_compare_exchange_weak_explicit(
                &e->publish_lock, &expected, 1, memory_order_acquire,
                memory_order_relaxed))
            break;
    }
    atomic_fetch_add_explicit(&e->publish_seq, 1, memory_order_acq_rel);
}

void ktx_publish_end(struct ktx_env *e) {
    atomic_fetch_add_explicit(&e->publish_seq, 1, memory_order_release);
    atomic_store_explicit(&e->publish_lock, 0, memory_order_release);
}

/* ---------------- hash64 ---------------- */

uint64_t ktx_hash64(const void *key, uint32_t len) {
    const uint8_t *p = (const uint8_t *)key;
    uint64_t h = 0x9E3779B97F4A7C15ULL;
    uint32_t i = 0;
    while (i + 8 <= len) {
        uint64_t chunk;
        memcpy(&chunk, p + i, 8);
        h ^= chunk;
        h = ktx_splitmix64_mix(h);
        i += 8;
    }
    if (i < len) {                       /* zero-padded tail chunk */
        uint64_t chunk = 0;
        memcpy(&chunk, p + i, len - i);
        h ^= chunk;
        h = ktx_splitmix64_mix(h);
    }
    return h;
}

/* ---------------- stripe seqlock ---------------- */

uint64_t ktx_stripe_lock(struct ktx_map *m, uint32_t s) {
    for (;;) {
        uint64_t v = atomic_load_explicit(&m->ver[s], memory_order_relaxed);
        if (!(v & 1) &&
            atomic_compare_exchange_weak_explicit(&m->ver[s], &v, v + 1,
                                                  memory_order_acquire,
                                                  memory_order_relaxed))
            return v;
    }
}

void ktx_stripe_unlock(struct ktx_map *m, uint32_t s, uint64_t prelock) {
    atomic_store_explicit(&m->ver[s], prelock + 2, memory_order_release);
}

/* ---------------- node pool (per-map spinlock) ---------------- */

static inline void pool_acquire(struct ktx_map *m) {
    uint32_t exp = 0;
    while (!atomic_compare_exchange_weak_explicit(&m->pool_lock, &exp, 1,
                                                  memory_order_acquire,
                                                  memory_order_relaxed))
        exp = 0;
}
static inline void pool_release(struct ktx_map *m) {
    atomic_store_explicit(&m->pool_lock, 0, memory_order_release);
}

/* Pop a free node; returns index+1.  Caller must have reserved capacity
 * via free_count, so this cannot legitimately fail; returns 0 only on
 * invariant violation (never expected). */
static uint32_t pool_pop(struct ktx_map *m) {
    pool_acquire(m);
    uint32_t n = m->free_head;
    if (n) m->free_head = ktx_node_at(m, n - 1)->next;
    pool_release(m);
    return n;
}

void ktx_pool_push(struct ktx_map *m, uint32_t node_plus1) {
    struct ktx_node *nd = ktx_node_at(m, node_plus1 - 1);
    nd->in_use = 0;
    pool_acquire(m);
    nd->next = m->free_head;
    m->free_head = node_plus1;
    pool_release(m);
    atomic_fetch_add_explicit(&m->free_count, 1, memory_order_relaxed);
}

/* ---------------- chain ops (caller holds the stripe) ---------------- */

static struct ktx_node *chain_find(struct ktx_map *m, uint32_t bucket,
                                   uint64_t hash, const void *key) {
    uint32_t n = m->buckets[bucket];
    uint32_t steps = 0;
    while (n && steps++ <= m->max_entries) {
        struct ktx_node *nd = ktx_node_at(m, n - 1);
        if (nd->in_use && nd->hash == hash &&
            memcmp(ktx_node_key(m, nd), key, m->key_size) == 0)
            return nd;
        n = nd->next;
    }
    return NULL;
}

int ktx_map_locked_present(struct ktx_map *m, uint64_t hash, const void *key) {
    uint32_t bucket = (uint32_t)(hash & (m->nbuckets - 1));
    return chain_find(m, bucket, hash, key) != NULL;
}

void ktx_map_locked_upsert(struct ktx_map *m, uint64_t hash, const void *key,
                           const void *val) {
    uint32_t bucket = (uint32_t)(hash & (m->nbuckets - 1));
    struct ktx_node *nd = chain_find(m, bucket, hash, key);
    if (nd) {
        memcpy(ktx_node_val(m, nd), val, m->value_size);
        return;
    }
    uint32_t np1 = pool_pop(m);
    if (!np1) return;                    /* reservation invariant violated */
    nd = ktx_node_at(m, np1 - 1);
    nd->hash = hash;
    memcpy(ktx_node_key(m, nd), key, m->key_size);
    memcpy(ktx_node_val(m, nd), val, m->value_size);
    nd->next = m->buckets[bucket];
    nd->in_use = 1;
    m->buckets[bucket] = np1;
}

uint32_t ktx_map_locked_delete(struct ktx_map *m, uint64_t hash,
                               const void *key) {
    uint32_t bucket = (uint32_t)(hash & (m->nbuckets - 1));
    uint32_t *link = &m->buckets[bucket];
    uint32_t n = *link;
    uint32_t steps = 0;
    while (n && steps++ <= m->max_entries) {
        struct ktx_node *nd = ktx_node_at(m, n - 1);
        if (nd->in_use && nd->hash == hash &&
            memcmp(ktx_node_key(m, nd), key, m->key_size) == 0) {
            *link = nd->next;
            nd->in_use = 0;              /* freed node pushed by caller */
            return n;
        }
        link = &nd->next;
        n = *link;
    }
    return 0;
}

/* ---------------- direct (program-visible) ops ---------------- */

void *ktx_map_direct_lookup(struct ktx_map *m, const void *key,
                            int thread_idx) {
    if (m->type == KTX_MAP_ARRAY) {
        uint32_t idx;
        memcpy(&idx, key, 4);
        if (idx >= m->max_entries) return NULL;
        return m->values + (size_t)idx * m->value_size;
    }
    if (m->type == KTX_MAP_PERCPU_ARRAY) {
        uint32_t idx;
        memcpy(&idx, key, 4);
        if (idx >= m->max_entries) return NULL;
        return m->values +
               ((size_t)thread_idx * m->max_entries + idx) * m->value_size;
    }
    /* HASH: unlocked bounded walk, pointer into shared node storage —
     * real-eBPF-like; values may be torn under writers (documented). */
    uint64_t hash = ktx_hash64(key, m->key_size);
    uint32_t bucket = (uint32_t)(hash & (m->nbuckets - 1));
    uint32_t n = m->buckets[bucket];
    uint32_t steps = 0;
    while (n && steps++ <= m->max_entries) {
        struct ktx_node *nd = ktx_node_at(m, n - 1);
        if (nd->in_use && nd->hash == hash &&
            memcmp(ktx_node_key(m, nd), key, m->key_size) == 0)
            return ktx_node_val(m, nd);
        n = nd->next;
    }
    return NULL;
}

int ktx_map_direct_update(struct ktx_map *m, const void *key, const void *val,
                          int thread_idx) {
    if (m->type == KTX_MAP_ARRAY) {
        uint32_t idx;
        memcpy(&idx, key, 4);
        if (idx >= m->max_entries) return -1;
        uint32_t s = ktx_array_stripe(idx);
        uint64_t pl = ktx_stripe_lock(m, s);
        memcpy(m->values + (size_t)idx * m->value_size, val, m->value_size);
        ktx_stripe_unlock(m, s, pl);
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
    uint32_t s = ktx_hash_stripe(m, hash);
    uint64_t pl = ktx_stripe_lock(m, s);
    uint32_t bucket = (uint32_t)(hash & (m->nbuckets - 1));
    struct ktx_node *nd = chain_find(m, bucket, hash, key);
    if (nd) {
        memcpy(ktx_node_val(m, nd), val, m->value_size);
        ktx_stripe_unlock(m, s, pl);
        return 0;
    }
    /* capacity reservation, then guaranteed pop */
    int32_t prev = atomic_fetch_sub_explicit(&m->free_count, 1,
                                             memory_order_relaxed);
    if (prev <= 0) {
        atomic_fetch_add_explicit(&m->free_count, 1, memory_order_relaxed);
        ktx_stripe_unlock(m, s, pl);
        return -1;                       /* map full */
    }
    ktx_map_locked_upsert(m, hash, key, val);
    ktx_stripe_unlock(m, s, pl);
    return 0;
}

int ktx_map_direct_delete(struct ktx_map *m, const void *key) {
    if (m->type != KTX_MAP_HASH) return -2;  /* arrays: no delete */
    uint64_t hash = ktx_hash64(key, m->key_size);
    uint32_t s = ktx_hash_stripe(m, hash);
    uint64_t pl = ktx_stripe_lock(m, s);
    uint32_t freed = ktx_map_locked_delete(m, hash, key);
    ktx_stripe_unlock(m, s, pl);
    if (!freed) return -2;
    ktx_pool_push(m, freed);
    return 0;
}

/* ---------------- seqlock snapshots (tx reads / harness reads) -------- */

int ktx_map_snapshot(struct ktx_map *m, const void *key, uint64_t hash,
                     void *val_out, uint16_t *stripe_out, uint64_t *ver_out) {
    uint32_t s;
    if (m->type == KTX_MAP_ARRAY) {
        uint32_t idx;
        memcpy(&idx, key, 4);
        s = ktx_array_stripe(idx);
        for (;;) {
            uint64_t v1 = atomic_load_explicit(&m->ver[s],
                                               memory_order_acquire);
            if (v1 & 1) continue;
            memcpy(val_out, m->values + (size_t)idx * m->value_size,
                   m->value_size);
            atomic_thread_fence(memory_order_acquire);
            uint64_t v2 = atomic_load_explicit(&m->ver[s],
                                               memory_order_acquire);
            if (v1 == v2) {
                *stripe_out = (uint16_t)s;
                *ver_out = v1;
                return 1;
            }
        }
    }
    /* HASH */
    s = ktx_hash_stripe(m, hash);
    uint32_t bucket = (uint32_t)(hash & (m->nbuckets - 1));
    for (;;) {
        uint64_t v1 = atomic_load_explicit(&m->ver[s], memory_order_acquire);
        if (v1 & 1) continue;
        int found = 0;
        uint32_t n = m->buckets[bucket];
        uint32_t steps = 0;
        while (n) {
            if (steps++ > m->max_entries) break;   /* torn chain: retry */
            struct ktx_node *nd = ktx_node_at(m, n - 1);
            if (nd->in_use && nd->hash == hash &&
                memcmp(ktx_node_key(m, nd), key, m->key_size) == 0) {
                memcpy(val_out, ktx_node_val(m, nd), m->value_size);
                found = 1;
                break;
            }
            n = nd->next;
        }
        atomic_thread_fence(memory_order_acquire);
        uint64_t v2 = atomic_load_explicit(&m->ver[s], memory_order_acquire);
        if (v1 == v2) {
            *stripe_out = (uint16_t)s;
            *ver_out = v1;
            return found;
        }
    }
}

void *ktx_map_snapshot_ptr(struct ktx_map *m, const void *key, uint64_t hash,
                           uint16_t *stripe_out, uint64_t *ver_out) {
    uint32_t s;
    if (m->type == KTX_MAP_ARRAY) {
        uint32_t idx;
        memcpy(&idx, key, 4);
        s = ktx_array_stripe(idx);
        *stripe_out = (uint16_t)s;
        *ver_out = atomic_load_explicit(&m->ver[s], memory_order_acquire);
        while (*ver_out & 1)
            *ver_out = atomic_load_explicit(&m->ver[s], memory_order_acquire);
        return m->values + (size_t)idx * m->value_size;
    }
    s = ktx_hash_stripe(m, hash);
    uint32_t bucket = (uint32_t)(hash & (m->nbuckets - 1));
    for (;;) {
        uint64_t v1 = atomic_load_explicit(&m->ver[s], memory_order_acquire);
        if (v1 & 1) continue;
        void *p = NULL;
        uint32_t n = m->buckets[bucket];
        uint32_t steps = 0;
        while (n) {
            if (steps++ > m->max_entries) break;
            struct ktx_node *nd = ktx_node_at(m, n - 1);
            if (nd->in_use && nd->hash == hash &&
                memcmp(ktx_node_key(m, nd), key, m->key_size) == 0) {
                p = ktx_node_val(m, nd);
                break;
            }
            n = nd->next;
        }
        atomic_thread_fence(memory_order_acquire);
        uint64_t v2 = atomic_load_explicit(&m->ver[s], memory_order_acquire);
        if (v1 == v2) {
            *stripe_out = (uint16_t)s;
            *ver_out = v1;
            return p;
        }
    }
}

/* ---------------- creation / destruction ---------------- */

static uint32_t pow2_roundup(uint32_t x) {
    if (x < 2) return 1;
    x--;
    x |= x >> 1; x |= x >> 2; x |= x >> 4; x |= x >> 8; x |= x >> 16;
    return x + 1;
}

static void map_free(struct ktx_map *m) {
    if (!m) return;
    free(m->buckets);
    free(m->pool);
    free(m->values);
    free(m);
}

struct ktx_map *ktx_env_map_create(struct ktx_env *e, uint32_t type,
                                   uint32_t key_size, uint32_t value_size,
                                   uint32_t max_entries, const char *name,
                                   char *err, size_t errlen) {
    if (err && errlen) err[0] = 0;
#define MAP_ERR(...) do { if (err) snprintf(err, errlen, __VA_ARGS__); \
                          return NULL; } while (0)
    if (type != KTX_MAP_HASH && type != KTX_MAP_ARRAY &&
        type != KTX_MAP_PERCPU_ARRAY)
        MAP_ERR("map '%s': bad type %u", name, type);
    if ((type == KTX_MAP_ARRAY || type == KTX_MAP_PERCPU_ARRAY) &&
        key_size != 4)
        MAP_ERR("map '%s': array key_size must be 4", name);
    if (key_size < 1 || key_size > 64)
        MAP_ERR("map '%s': key_size %u out of range [1,64]", name, key_size);
    if (value_size < 1 || value_size > 4096)
        MAP_ERR("map '%s': value_size %u out of range [1,4096]", name,
                value_size);
    if (max_entries < 1 || max_entries > (1u << 20))
        MAP_ERR("map '%s': max_entries %u out of range", name, max_entries);
    if (e->nmaps >= KTX_MAX_MAPS)
        MAP_ERR("environment map table full (%d)", KTX_MAX_MAPS);

    struct ktx_map *m = calloc(1, sizeof(*m));
    if (!m) MAP_ERR("map '%s': out of memory", name);
    m->id = e->nmaps;
    m->type = type;
    m->key_size = key_size;
    m->value_size = value_size;
    m->max_entries = max_entries;
    m->nthreads = e->nthreads;
    atomic_store_explicit(&m->invoke_lock, 0, memory_order_relaxed);
    strncpy(m->name, name, 31);
    m->name[31] = 0;

    if (type == KTX_MAP_HASH) {
        m->nbuckets = pow2_roundup(max_entries);
        m->node_stride =
            (uint32_t)((sizeof(struct ktx_node) + key_size + value_size + 7u)
                       & ~7u);
        m->buckets = calloc(m->nbuckets, sizeof(uint32_t));
        m->pool = calloc(max_entries, m->node_stride);
        if (!m->buckets || !m->pool) {
            map_free(m);
            MAP_ERR("map '%s': out of memory", name);
        }
        for (uint32_t i = 0; i < max_entries; i++)
            ktx_node_at(m, i)->next = (i + 1 < max_entries) ? i + 2 : 0;
        m->free_head = 1;
        atomic_store_explicit(&m->free_count, (int32_t)max_entries,
                              memory_order_relaxed);
    } else {
        size_t n = (size_t)max_entries * value_size;
        if (type == KTX_MAP_PERCPU_ARRAY) n *= (size_t)e->nthreads;
        m->values = calloc(1, n ? n : 1);
        if (!m->values) {
            map_free(m);
            MAP_ERR("map '%s': out of memory", name);
        }
    }
    e->maps[e->nmaps++] = m;
    return m;
#undef MAP_ERR
}

/* Called by ktx_env_destroy (loader.c). */
void ktx_map_destroy_internal(struct ktx_map *m);
void ktx_map_destroy_internal(struct ktx_map *m) { map_free(m); }

/* ---------------- public harness API ---------------- */

static struct ktx_map *env_map(ktx_env *e, int id) {
    if (!e || id < 0 || (uint32_t)id >= e->nmaps) return NULL;
    return e->maps[id];
}

int ktx_map_id(ktx_env *e, const char *name) {
    if (!e || !name) return -1;
    for (uint32_t i = 0; i < e->nmaps; i++)
        if (strncmp(e->maps[i]->name, name, 32) == 0) return (int)i;
    return -1;
}

int ktx_map_update(ktx_env *e, int map, const void *key, const void *val) {
    struct ktx_map *m = env_map(e, map);
    if (!m || !key || !val) return -1;
    if (m->type == KTX_MAP_PERCPU_ARRAY) {
        /* Harness update writes the value into EVERY thread's slot
         * (initialization convenience; documented). */
        uint32_t idx;
        memcpy(&idx, key, 4);
        if (idx >= m->max_entries) return -1;
        for (int t = 0; t < m->nthreads; t++)
            memcpy(m->values +
                       ((size_t)t * m->max_entries + idx) * m->value_size,
                   val, m->value_size);
        return 0;
    }
    if (e->opt_observer_publish) ktx_publish_begin(e);
    int rc = ktx_map_direct_update(m, key, val, 0);
    if (e->opt_observer_publish) ktx_publish_end(e);
    return rc;
}

int ktx_map_lookup(ktx_env *e, int map, const void *key, void *val_out) {
    struct ktx_map *m = env_map(e, map);
    if (!m || !key || !val_out) return -1;
    if (m->type == KTX_MAP_PERCPU_ARRAY)
        return ktx_map_lookup_percpu(e, map, key, 0, val_out);
    if (m->type == KTX_MAP_ARRAY) {
        uint32_t idx;
        memcpy(&idx, key, 4);
        if (idx >= m->max_entries) return -1;
    }
    uint16_t stripe;
    uint64_t ver;
    uint64_t hash = (m->type == KTX_MAP_HASH)
                        ? ktx_hash64(key, m->key_size) : 0;
    int found = ktx_map_snapshot(m, key, hash, val_out, &stripe, &ver);
    return found ? 0 : -1;
}

int ktx_map_delete(ktx_env *e, int map, const void *key) {
    struct ktx_map *m = env_map(e, map);
    if (!m || !key) return -1;
    if (e->opt_observer_publish) ktx_publish_begin(e);
    int rc = ktx_map_direct_delete(m, key) == 0 ? 0 : -1;
    if (e->opt_observer_publish) ktx_publish_end(e);
    return rc;
}

int ktx_map_lookup_batch(ktx_env *e, const ktx_lookup_item *items,
                         size_t nitems) {
    if (!e || !items || nitems == 0 || !e->opt_observer_publish) return -1;
    for (;;) {
        uint64_t s1 = atomic_load_explicit(&e->publish_seq,
                                           memory_order_acquire);
        if (s1 & 1) continue;
        int rc = 0;
        for (size_t i = 0; i < nitems; i++)
            if (ktx_map_lookup(e, items[i].map, items[i].key,
                               items[i].val_out) != 0)
                rc = -1;
        atomic_thread_fence(memory_order_acquire);
        uint64_t s2 = atomic_load_explicit(&e->publish_seq,
                                           memory_order_acquire);
        if (s1 == s2) return rc;
    }
}

int ktx_map_lookup_percpu(ktx_env *e, int map, const void *key,
                          int thread_idx, void *val_out) {
    struct ktx_map *m = env_map(e, map);
    if (!m || !key || !val_out) return -1;
    if (m->type != KTX_MAP_PERCPU_ARRAY) return -1;
    if (thread_idx < 0 || thread_idx >= m->nthreads) return -1;
    uint32_t idx;
    memcpy(&idx, key, 4);
    if (idx >= m->max_entries) return -1;
    memcpy(val_out,
           m->values + ((size_t)thread_idx * m->max_entries + idx) *
                           m->value_size,
           m->value_size);
    return 0;
}

uint32_t ktx_map_count(ktx_env *e, int map) {
    struct ktx_map *m = env_map(e, map);
    if (!m) return 0;
    if (m->type == KTX_MAP_HASH) {
        int32_t fc = atomic_load_explicit(&m->free_count,
                                          memory_order_relaxed);
        if (fc < 0) fc = 0;
        return m->max_entries - (uint32_t)fc;
    }
    return m->max_entries;
}

int ktx_map_iter(ktx_env *e, int map, uint32_t *iter,
                 void *key_out, void *val_out) {
    if (!e || atomic_load_explicit(&e->quiesce_state,
                                   memory_order_acquire) != KTX_QUIESCE_WRITER)
        return -1;
    struct ktx_map *m = env_map(e, map);
    if (!m || !iter) return -1;
    if (m->type == KTX_MAP_HASH) {
        for (uint32_t i = *iter; i < m->max_entries; i++) {
            struct ktx_node *nd = ktx_node_at(m, i);
            if (nd->in_use) {
                if (key_out) memcpy(key_out, ktx_node_key(m, nd), m->key_size);
                if (val_out) memcpy(val_out, ktx_node_val(m, nd),
                                    m->value_size);
                *iter = i + 1;
                return 0;
            }
        }
        return -1;
    }
    /* ARRAY / PERCPU (thread 0 slice): iterate indices. */
    uint32_t i = *iter;
    if (i >= m->max_entries) return -1;
    if (key_out) memcpy(key_out, &i, 4);
    if (val_out) memcpy(val_out, m->values + (size_t)i * m->value_size,
                        m->value_size);
    *iter = i + 1;
    return 0;
}

int ktx_env_quiesce_begin(ktx_env *e) {
    if (!e) return -1;
    uint32_t expected = 0;
    return atomic_compare_exchange_strong_explicit(
               &e->quiesce_state, &expected, KTX_QUIESCE_WRITER,
               memory_order_acq_rel, memory_order_acquire) ? 0 : -1;
}

void ktx_env_quiesce_end(ktx_env *e) {
    if (!e) return;
    uint32_t expected = KTX_QUIESCE_WRITER;
    (void)atomic_compare_exchange_strong_explicit(
        &e->quiesce_state, &expected, 0, memory_order_release,
        memory_order_relaxed);
}
