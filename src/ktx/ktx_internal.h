/* ktx_internal.h — package-1 internal structures and functions.
 * NOT part of the public contract; package 2 must not include this.
 */
#ifndef KTX_INTERNAL_H
#define KTX_INTERNAL_H

#include <stdatomic.h>
#include <stdint.h>
#include <string.h>

#include "ktx.h"
#include "ktx_format.h"

/* ---------------- parameter defaults (DESIGN §12) ---------------- */
#define KTX_STACK_BYTES   512
#define KTX_DEFAULT_FUEL  65536
#define KTX_ARENA_BYTES   (64 * 1024)
#define KTX_MAX_RECORDS   512
#define KTX_MAX_READSET   128
#define KTX_RYW_SLOTS     256          /* power of two */
#define KTX_STRIPES       64
#define KTX_MAX_REGIONS   16           /* 3 fixed + 13 mapval */
#define KTX_LOCK_SPIN     1024
#define KTX_RING_BYTES    (1024 * 1024)
#define KTX_RING_MAX_MSG  512
#define KTX_MAX_MAPS      32
#define KTX_ENV_SEED      42ULL
#define KTX_MAX_HELD      32           /* 2PL: stripes one invocation may hold */
#define KTX_QUIESCE_WRITER (1u << 31)

/* ---------------- maps (DESIGN §3.1) ---------------- */

/* Node header; key/value bytes follow, stride-packed. */
struct ktx_node {
    uint32_t next;             /* node index+1, 0 = end of chain */
    uint32_t in_use;
    uint64_t hash;
    /* uint8_t key[key_size]; uint8_t val[value_size]; (8-byte aligned) */
};

struct ktx_map {
    uint32_t id, type, key_size, value_size, max_entries;
    char     name[32];
    uint8_t  ro_elide;         /* from sidecar map_ro, set at prog load */
    /* HASH */
    uint32_t nbuckets;         /* max_entries rounded up to power of two */
    uint32_t node_stride;      /* sizeof(node hdr) + key + val, 8-aligned */
    uint32_t *buckets;         /* node index+1, 0 = empty */
    uint8_t  *pool;            /* max_entries nodes, flat stride array */
    _Atomic uint32_t pool_lock;
    uint32_t free_head;        /* node index+1, guarded by pool_lock */
    _Atomic int32_t  free_count;   /* capacity reservation counter */
    /* ARRAY / PERCPU_ARRAY */
    uint8_t  *values;          /* ARRAY: max*vsz; PERCPU: nthr*max*vsz */
    int      nthreads;         /* copied from env, for PERCPU slicing */
    /* OCC / locking */
    _Atomic uint64_t ver[KTX_STRIPES]; /* seqlock stripes, even = free */
    _Atomic uint32_t invoke_lock;      /* ordered predeclared-map 2PL */
};

static inline struct ktx_node *ktx_node_at(const struct ktx_map *m, uint32_t i) {
    return (struct ktx_node *)(m->pool + (size_t)i * m->node_stride);
}
static inline uint8_t *ktx_node_key(const struct ktx_map *m, struct ktx_node *n) {
    (void)m; return (uint8_t *)n + sizeof(struct ktx_node);
}
static inline uint8_t *ktx_node_val(const struct ktx_map *m, struct ktx_node *n) {
    return (uint8_t *)n + sizeof(struct ktx_node) + m->key_size;
}

/* splitmix64 finalizer + hash64 over key bytes (DESIGN §3.1). */
static inline uint64_t ktx_splitmix64_mix(uint64_t z) {
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}
static inline uint64_t ktx_splitmix64_next(uint64_t *s) {
    *s += 0x9E3779B97F4A7C15ULL;
    return ktx_splitmix64_mix(*s);
}
uint64_t ktx_hash64(const void *key, uint32_t len);

/* ---------------- environment ---------------- */

struct ktx_env {
    int      nthreads;
    uint32_t nmaps;
    struct ktx_map *maps[KTX_MAX_MAPS];
    /* ring buffer (1 MiB, single spinlock — not a measured hot path) */
    _Atomic uint32_t ring_lock;
    uint8_t *ring;
    uint32_t ring_used;
    _Atomic uint64_t ring_count;
    uint64_t seed;             /* deterministic PRNG seeding, default 42 */
    uint64_t tb_num, tb_denom; /* mach_timebase_info */
    /* runtime options (ktx_opt) */
    uint8_t  opt_shadow_diff;  /* default 1 */
    uint8_t  opt_seq_trace;    /* default 0 */
    uint8_t  opt_jit;          /* default 0 (set before ktx_prog_load) */
    uint8_t  opt_observer_publish; /* default 0; opt-in mixed observers */
    _Atomic uint64_t commit_seq; /* serialization stamp source (seq trace) */
    _Atomic uint32_t coarse_lock; /* whole-invocation transaction baseline */
    _Atomic uint32_t publish_lock; /* apply-only writer serialization */
    _Atomic uint64_t publish_seq;  /* even=stable, odd=apply in progress */
    _Atomic uint32_t quiesce_state; /* high bit=iterator gate, low=invocations */
};

/* ---------------- program ---------------- */

/* Pre-decoded instruction (DESIGN §1.4). */
typedef struct {
    uint16_t handler;
    uint8_t  dst, src;
    int16_t  off;
    int32_t  imm;
    uint64_t imm64;            /* LD_IMM64 value / map handle */
    uint8_t  certified;        /* audit stream: the analyzer proved this
                                * access in bounds */
} ktx_dinsn;

struct ktx_prog {
    struct ktx_env *env;
    uint32_t n_insns, n_maps, min_pkt;
    uint16_t map_env_id[KTX_MAX_MAPS]; /* prog map idx -> env map id */
    uint8_t  map_ro[KTX_MAX_MAPS];     /* sidecar map_ro (per prog) */
    uint8_t  fuel_elidable;            /* sidecar flags bit0 (if complete) */
    uint8_t  have_elide;               /* a completed sidecar was loaded */
    ktx_dinsn *d_vanilla;              /* all-unguarded */
    ktx_dinsn *d_guarded;              /* all-guarded */
    ktx_dinsn *d_elided;               /* per-sidecar (tx bit) */
    ktx_dinsn *d_audit;                /* all-guarded + certified flags */
    /* Native code for the three decoded streams (NULL = interpret).
     * The JIT compiles the *same* streams, so "elided" means the guard
     * instructions are physically absent from the machine code. */
    void    *jit_vanilla, *jit_guarded, *jit_elided;
    size_t   jit_sz_vanilla, jit_sz_guarded, jit_sz_elided;   /* mapped */
    size_t   jit_emit_vanilla, jit_emit_guarded, jit_emit_elided; /* code */
};

/* ---------------- per-thread transaction state (DESIGN §3.2) -------- */

#define EFF_UPDATE   1
#define EFF_DELETE   2
#define EFF_RINGBUF  3
#define EFF_PKTWRITE 4
#define EFF_SHADOW   5             /* lookup shadow: written back only if the
                                    * program actually changed it (commit-time
                                    * diff against orig_off).  Semantically an
                                    * EFF_UPDATE whose value may be unchanged. */

struct eff_rec {
    uint16_t kind;             /* EFF_* */
    uint16_t map_id;           /* env map id; unused for RINGBUF/PKTWRITE */
    uint32_t key_off, val_off; /* arena offsets */
    uint32_t len;              /* RINGBUF msg len / PKTWRITE len */
    uint32_t pkt_off;          /* PKTWRITE packet offset */
    uint32_t orig_off;         /* EFF_SHADOW: pristine snapshot bytes */
};
struct read_ent { uint16_t map_id; uint16_t stripe; uint64_t ver; };
struct ryw_slot {
    uint32_t gen; uint16_t map_id; uint16_t _pad;
    uint64_t khash;
    uint32_t rec;              /* index into records[] (latest for key) */
};

struct ktx_thread {
    struct ktx_env *env;
    int      idx;
    /* tx state */
    uint8_t *arena;            /* KTX_ARENA_BYTES bump allocator */
    uint32_t arena_used;
    struct eff_rec  recs[KTX_MAX_RECORDS];
    uint32_t nrecs;
    struct read_ent readset[KTX_MAX_READSET];
    uint32_t nreads;
    struct ryw_slot ryw[KTX_RYW_SLOTS];
    uint32_t ryw_used;
    uint32_t cur_gen;
    /* PRNG (xorshift64*), seeded splitmix64(env->seed ^ (idx+1)) */
    uint64_t prng;
    ktx_thread_stats stats;
    uint64_t last_commit_seq;  /* KTX_OPT_SEQ_TRACE stamp of last commit */
    /* High-water marks of the per-invocation structures, so the 64 KiB /
     * 512-record provisioning can be compared against actual use (E7). */
    uint32_t hwm_arena, hwm_recs, hwm_reads;
    /* 512-byte eBPF stack for this thread's invocations */
    _Alignas(16) uint8_t stack[KTX_STACK_BYTES];
};

/* ---------------- execution state ---------------- */

typedef struct { uint64_t base, end; uint8_t rw; } ktx_region;

/* 2PL: one stripe lock held by the running invocation. */
typedef struct { uint16_t map_id, stripe; uint64_t prelock; } ktx_held;

typedef struct ktx_exec {
    uint64_t regs[11];
    const ktx_dinsn *code;
    uint32_t n;
    int64_t  fuel;             /* remaining (fuel builds) */
    struct ktx_thread *th;
    struct ktx_env    *env;
    struct ktx_prog   *prog;
    uint8_t  tx;               /* effects logged + commit at exit */
    uint8_t  check_args;       /* helper arg region checks (sfi/tx modes) */
    uint8_t  ro_elide;         /* mode is TX_ELIDE: RO-map validate-only */
    uint8_t  twopl;            /* mode is 2PL: lock-on-touch, hold to exit */
    uint8_t  p2pl;             /* predeclared maps locked in global order */
    uint8_t  audit;            /* mode is TX_AUDIT: check analyzer facts */
    uint8_t *pkt;
    uint32_t pkt_len;
    struct ktx_ctx ctx;
    ktx_status status;         /* set by helper/guard abort paths */
    uint64_t r0_out;
    ktx_region regions[KTX_MAX_REGIONS];
    uint32_t nregions;
    /* 2PL held-lock set (twopl only) */
    ktx_held held[KTX_MAX_HELD];
    uint32_t nheld;
    uint16_t held_maps[KTX_MAX_MAPS];
    uint32_t nheld_maps;
} ktx_exec;

/* ---------------- 2PL strawman (twopl.c) ---------------- */
/* Acquire the stripe covering `key` on map m if not already held.
 * Returns KTX_OK, or KTX_ABORT_DEADLOCK when the bounded spin is
 * exhausted (the strawman's only escape from a lock cycle). */
ktx_status ktx_2pl_acquire(struct ktx_exec *ex, struct ktx_map *m,
                           const void *key);
/* Release every held stripe, publishing a version bump (locks are only
 * taken by invocations that may mutate the stripe). */
void ktx_2pl_release_all(struct ktx_exec *ex);
/* Lock every shared map named by the program in ascending environment-map-id
 * order.  The set is known before execution, so cycles are impossible. */
void ktx_p2pl_acquire_all(struct ktx_exec *ex);
void ktx_p2pl_release_all(struct ktx_exec *ex);
/* Insert/overwrite under an already-held stripe; -1 if the map is full. */
int  ktx_2pl_update(struct ktx_map *m, const void *key, const void *val,
                    int thread_idx);
int  ktx_2pl_delete(struct ktx_map *m, const void *key);

/* Bounds guard: some region grants [a, a+size) with the required right.
 * Overflow-safe: works on offsets within the region. */
static inline int ktx_guard_ok(const ktx_exec *ex, uint64_t a,
                               uint32_t size, int write) {
    for (uint32_t i = 0; i < ex->nregions; i++) {
        const ktx_region *rg = &ex->regions[i];
        if (a >= rg->base) {
            uint64_t rlen = rg->end - rg->base;
            uint64_t off  = a - rg->base;
            if (off < rlen && rlen - off >= size && (!write || rg->rw))
                return 1;
        }
    }
    return 0;
}

/* Register a mapval region (slots 3..15); dedupes identical regions.
 * Returns 0 on success, -1 on overflow (caller aborts HELPER). */
static inline int ktx_region_add(ktx_exec *ex, uint64_t base, uint64_t end,
                                 uint8_t rw) {
    for (uint32_t i = 3; i < ex->nregions; i++)
        if (ex->regions[i].base == base && ex->regions[i].end == end) {
            if (rw && !ex->regions[i].rw) ex->regions[i].rw = 1;
            return 0;
        }
    if (ex->nregions >= KTX_MAX_REGIONS) return -1;
    ex->regions[ex->nregions].base = base;
    ex->regions[ex->nregions].end  = end;
    ex->regions[ex->nregions].rw   = rw;
    ex->nregions++;
    return 0;
}

/* ---------------- vm (decode.c / vm.c) ---------------- */

/* Dense handler enum.  Convention: for memory ops, guarded = unguarded+1. */
enum {
    H_NOP = 0,
    /* ALU64 */
    H_ADD64_K, H_ADD64_X, H_SUB64_K, H_SUB64_X, H_MUL64_K, H_MUL64_X,
    H_DIV64_K, H_DIV64_X, H_OR64_K,  H_OR64_X,  H_AND64_K, H_AND64_X,
    H_LSH64_K, H_LSH64_X, H_RSH64_K, H_RSH64_X, H_NEG64,
    H_MOD64_K, H_MOD64_X, H_XOR64_K, H_XOR64_X, H_MOV64_K, H_MOV64_X,
    H_ARSH64_K, H_ARSH64_X,
    /* ALU32 (zero-extend) */
    H_ADD32_K, H_ADD32_X, H_SUB32_K, H_SUB32_X, H_MUL32_K, H_MUL32_X,
    H_DIV32_K, H_DIV32_X, H_OR32_K,  H_OR32_X,  H_AND32_K, H_AND32_X,
    H_LSH32_K, H_LSH32_X, H_RSH32_K, H_RSH32_X, H_NEG32,
    H_MOD32_K, H_MOD32_X, H_XOR32_K, H_XOR32_X, H_MOV32_K, H_MOV32_X,
    H_ARSH32_K, H_ARSH32_X,
    /* JMP (64-bit compare) */
    H_JA,
    H_JEQ_K,  H_JEQ_X,  H_JGT_K,  H_JGT_X,  H_JGE_K,  H_JGE_X,
    H_JSET_K, H_JSET_X, H_JNE_K,  H_JNE_X,  H_JSGT_K, H_JSGT_X,
    H_JSGE_K, H_JSGE_X, H_JLT_K,  H_JLT_X,  H_JLE_K,  H_JLE_X,
    H_JSLT_K, H_JSLT_X, H_JSLE_K, H_JSLE_X,
    /* JMP32 (32-bit compare) */
    H_JEQ32_K,  H_JEQ32_X,  H_JGT32_K,  H_JGT32_X,  H_JGE32_K,  H_JGE32_X,
    H_JSET32_K, H_JSET32_X, H_JNE32_K,  H_JNE32_X,  H_JSGT32_K, H_JSGT32_X,
    H_JSGE32_K, H_JSGE32_X, H_JLT32_K,  H_JLT32_X,  H_JLE32_K,  H_JLE32_X,
    H_JSLT32_K, H_JSLT32_X, H_JSLE32_K, H_JSLE32_X,
    H_CALL, H_EXIT, H_LD_IMM64,
    /* memory: unguarded, guarded pairs (guarded = unguarded + 1) */
    H_LDXB,  H_LDXB_G,  H_LDXH,  H_LDXH_G,
    H_LDXW,  H_LDXW_G,  H_LDXDW, H_LDXDW_G,
    H_STXB,  H_STXB_G,  H_STXH,  H_STXH_G,
    H_STXW,  H_STXW_G,  H_STXDW, H_STXDW_G,
    H_STB,   H_STB_G,   H_STH,   H_STH_G,
    H_STW,   H_STW_G,   H_STDW,  H_STDW_G,
    H_MAX
};

/* Decode variants. */
#define KTX_DECODE_VANILLA 0   /* all memory ops unguarded */
#define KTX_DECODE_GUARDED 1   /* all memory ops guarded */
#define KTX_DECODE_ELIDED  2   /* guarded unless iflags tx bit set */
#define KTX_DECODE_AUDIT   3   /* always guarded, iflags recorded in
                                * dinsn.certified for the runtime audit */

/* Translate n insns into out[n].  iflags used only for KTX_DECODE_ELIDED
 * (may be NULL -> same as GUARDED).  Returns 0 or -1 with message in err. */
int ktx_decode(const struct ktx_insn *ins, uint32_t n, uint32_t n_maps,
               const uint8_t *iflags, int variant,
               ktx_dinsn *out, char *err, size_t errlen);

/* Interpreter loops (vm.c).  Return KTX_OK when EXIT reached (and, in tx
 * mode, commit succeeded); an abort status otherwise. */
ktx_status vm_exec_fuel(ktx_exec *ex);
ktx_status vm_exec_audit(ktx_exec *ex);
ktx_status vm_exec_nofuel(ktx_exec *ex);

/* Helper dispatch (helpers.c).  Returns new r0; sets ex->status on abort. */
uint64_t ktx_helper_call(ktx_exec *ex, uint64_t *r, int32_t imm);

/* ---------------- map internals (map.c) ---------------- */

struct ktx_map *ktx_env_map_create(struct ktx_env *e, uint32_t type,
                                   uint32_t key_size, uint32_t value_size,
                                   uint32_t max_entries, const char *name,
                                   char *err, size_t errlen);
void ktx_map_destroy_internal(struct ktx_map *m);

/* Stripe of a key/index. */
static inline uint32_t ktx_hash_stripe(const struct ktx_map *m, uint64_t hash) {
    return (uint32_t)(hash & (m->nbuckets - 1)) & (KTX_STRIPES - 1);
}
static inline uint32_t ktx_array_stripe(uint32_t index) {
    return index & (KTX_STRIPES - 1);
}

/* Stripe seqlock: lock returns the pre-lock (even) value. */
uint64_t ktx_stripe_lock(struct ktx_map *m, uint32_t s);
void     ktx_stripe_unlock(struct ktx_map *m, uint32_t s, uint64_t prelock);

/* Direct (program-visible, vanilla/sfi) lookup: pointer into shared
 * storage, no lock, bounded chain walk.  thread_idx for PERCPU. */
void *ktx_map_direct_lookup(struct ktx_map *m, const void *key, int thread_idx);
/* Direct stripe-locked upsert / unlink.  0 ok, -1 full/bad index. */
int ktx_map_direct_update(struct ktx_map *m, const void *key, const void *val,
                          int thread_idx);
int ktx_map_direct_delete(struct ktx_map *m, const void *key);

/* Seqlock snapshot for tx reads: returns 1 found (val copied), 0 absent.
 * Fills *stripe_out / *ver_out (the consistent pre-read version) always.
 * hash must be ktx_hash64(key, key_size) for HASH maps (ignored ARRAY). */
int ktx_map_snapshot(struct ktx_map *m, const void *key, uint64_t hash,
                     void *val_out, uint16_t *stripe_out, uint64_t *ver_out);
/* Like snapshot but returns the shared value pointer (RO-elide fast path);
 * NULL if absent. */
void *ktx_map_snapshot_ptr(struct ktx_map *m, const void *key, uint64_t hash,
                           uint16_t *stripe_out, uint64_t *ver_out);

/* Commit-side ops; caller holds the stripe. */
int  ktx_map_locked_present(struct ktx_map *m, uint64_t hash, const void *key);
void ktx_map_locked_upsert(struct ktx_map *m, uint64_t hash, const void *key,
                           const void *val);   /* must not fail (reserved) */
/* Returns node index+1 to free after unlock, or 0 if key absent. */
uint32_t ktx_map_locked_delete(struct ktx_map *m, uint64_t hash,
                               const void *key);
void ktx_pool_push(struct ktx_map *m, uint32_t node_plus1);
void ktx_publish_begin(struct ktx_env *e);
void ktx_publish_end(struct ktx_env *e);

/* ---------------- tx log (log.c) ---------------- */

void       ktx_tx_begin(struct ktx_thread *t);
void       ktx_tx_abort_reset(struct ktx_thread *t);   /* O(1) */
/* Log-side helper ops; return KTX_OK or an abort status (overflow etc). */
ktx_status ktx_tx_update(struct ktx_thread *t, struct ktx_map *m,
                         const void *key, const void *val);
/* *present_out (nullable): whether the key was visible at log time
 * (consistent iff the commit later validates). */
ktx_status ktx_tx_delete(struct ktx_thread *t, struct ktx_map *m,
                         const void *key, int *present_out);
/* TX lookup: *val_out = arena shadow / shared ptr (ro_elide) / NULL.
 * *is_shared_out = 1 when the returned pointer is shared storage (RO). */
ktx_status ktx_tx_lookup(struct ktx_thread *t, struct ktx_map *m,
                         const void *key, int ro_elide,
                         void **val_out, int *is_shared_out);
ktx_status ktx_tx_ringbuf(struct ktx_thread *t, const void *msg, uint32_t len);
ktx_status ktx_tx_pktwrite(struct ktx_thread *t, uint32_t pkt_off,
                           const void *data, uint32_t len);
/* Read-set entry (dedupes on identical (map,stripe,ver)). */
ktx_status ktx_readset_add(struct ktx_thread *t, uint16_t map_id,
                           uint16_t stripe, uint64_t ver);

/* ---------------- commit (commit.c) ---------------- */

ktx_status ktx_tx_commit(struct ktx_thread *t, uint8_t *pkt, uint32_t pkt_len);
/* True when an EFF_SHADOW record's value differs from its snapshot. */
int ktx_shadow_dirty(const struct ktx_thread *t, const struct eff_rec *r);

/* ---------------- JIT (jit/jit_arm64.c, wired in loader.c) ---------- */
void ktx_prog_jit(struct ktx_prog *p);

/* ---------------- misc ---------------- */

uint64_t ktx_time_ns(struct ktx_env *e);        /* mach time in ns */
uint32_t ktx_prandom_u32(struct ktx_thread *t); /* xorshift64* */
void     ktx_thread_set_seed(struct ktx_thread *t, uint64_t seed);
/* Direct-mode ringbuf append (env spinlock). */
void     ktx_ringbuf_append(struct ktx_env *e, const void *msg, uint32_t len);

#endif /* KTX_INTERNAL_H */
