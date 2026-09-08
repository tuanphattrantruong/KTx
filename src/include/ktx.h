/* ktx.h — public C API of the KTx core runtime (DESIGN §4).
 *
 * Frozen contract between package 1 (core runtime) and package 2
 * (bench/torn harnesses).  Package 2 codes ONLY against this header and
 * ktx_format.h.
 */
#ifndef KTX_H
#define KTX_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Execution modes (the four experiment configs). */
typedef enum {
    KTX_MODE_VANILLA = 0,   /* no guards, no fuel, direct effects (baseline) */
    KTX_MODE_SFI     = 1,   /* guards+fuel, direct effects (KFlex-style)     */
    KTX_MODE_TX      = 2,   /* guards+fuel, logged effects + OCC commit      */
    KTX_MODE_TX_ELIDE= 3,   /* elided guards, logged effects, RO validate    */
    KTX_MODE_2PL     = 4,   /* guards+fuel, DIRECT effects under two-phase   */
                            /* locking: stripe locks taken lazily on first  */
                            /* touch and held to program exit (the          */
                            /* "cross-map bpf_spin_lock" strawman)          */
    KTX_MODE_TX_AUDIT= 5    /* TX, but guards the analyzer said were         */
                            /* unnecessary are still executed and counted   */
                            /* if they fire: a runtime audit of the sidecar */
    ,KTX_MODE_COARSE  = 6,  /* guards+fuel, logged effects, and one          */
                            /* environment-wide lock held for the complete  */
                            /* invocation: abort-safe serialization baseline */
    KTX_MODE_P2PL    = 7    /* guards+fuel, direct effects; predeclares all  */
                            /* program maps and locks them in global map-id  */
                            /* order: a deadlock-free strict-2PL baseline    */
} ktx_mode;

/* Invocation status. */
typedef enum {
    KTX_OK             = 0,
    KTX_ABORT_GUARD    = 1,
    KTX_ABORT_FUEL     = 2,
    KTX_ABORT_HELPER   = 3,
    KTX_ABORT_CONFLICT = 4,
    KTX_ABORT_CAPACITY = 5,
    KTX_ABORT_DEADLOCK = 6   /* 2PL only: lock acquisition spin exhausted */
} ktx_status;

/* Runtime options settable per environment (defaults in parens). */
typedef enum {
    KTX_OPT_SHADOW_DIFF = 0,  /* (1) commit-time diffing of lookup shadows:
                               * an unmodified shadow is neither locked nor
                               * written back.  0 reproduces the naive redo
                               * log that writes every shadow back. */
    KTX_OPT_SEQ_TRACE   = 1,  /* (0) stamp each commit with a global
                               * serialization sequence number, for the
                               * offline serializability checker. */
    KTX_OPT_JIT         = 2,  /* (0) compile programs to native code at
                               * load time.  Must be set on the env
                               * *before* ktx_prog_load; the interpreter
                               * is used for any program that fails to
                               * compile. */
    KTX_OPT_OBSERVER_PUBLISH = 3 /* (0) serialize only the apply phase and
                                  * expose an environment publication
                                  * sequence to opt-in multi-map observers. */
} ktx_opt;

typedef struct ktx_env    ktx_env;    /* maps + ringbuf, shared across threads */
typedef struct ktx_prog   ktx_prog;   /* immutable after load */
typedef struct ktx_thread ktx_thread; /* per-thread arena/log/PRNG/stats */

ktx_env  *ktx_env_create(int nthreads);
void      ktx_env_destroy(ktx_env *e);

/* Loads .kbin; elide_path may be NULL (then TX_ELIDE behaves like TX and
 * VANILLA still runs unguarded).  Creates maps in e, or binds to existing
 * same-name maps (spec mismatch -> NULL).  On error returns NULL and writes
 * a message into errbuf. */
ktx_prog *ktx_prog_load(ktx_env *e, const char *kbin_path,
                        const char *elide_path, char *errbuf, size_t errlen);
/* For unit tests / microbench: build from an in-memory image with no files.
 * elide_bytes may be NULL (elide_n 0). */
ktx_prog *ktx_prog_load_mem(ktx_env *e, const void *kbin_bytes, size_t n,
                            const void *elide_bytes, size_t elide_n,
                            char *errbuf, size_t errlen);
void      ktx_prog_free(ktx_prog *p);
uint32_t  ktx_prog_ninsns(const ktx_prog *p);

/* Harness-side map access: stripe-locked / seqlocked, safe concurrently
 * with running programs.  Returns -1 on error (bad id / absent key / full),
 * 0 on success unless noted. */
int  ktx_map_id(ktx_env *e, const char *name);               /* -1 if absent */
int  ktx_map_update(ktx_env *e, int map, const void *key, const void *val);
int  ktx_map_lookup(ktx_env *e, int map, const void *key, void *val_out);
int  ktx_map_delete(ktx_env *e, int map, const void *key);
int  ktx_map_lookup_percpu(ktx_env *e, int map, const void *key,
                           int thread_idx, void *val_out);
uint32_t ktx_map_count(ktx_env *e, int map);
/* Quiesced iteration: acquire the environment gate first. begin returns -1
 * rather than racing an active invocation; new invocations fail closed while
 * the gate is held. *iter starts at 0; map_iter returns 0 or -1 at end/error. */
int  ktx_env_quiesce_begin(ktx_env *e);
void ktx_env_quiesce_end(ktx_env *e);
int  ktx_map_iter(ktx_env *e, int map, uint32_t *iter,
                  void *key_out, void *val_out);

/* Opt-in mixed-observer API.  When KTX_OPT_OBSERVER_PUBLISH is enabled,
 * all items are copied from one stable publication interval; the call
 * retries if a participating transaction/direct harness write overlaps it.
 * Returns 0 when every key exists, -1 for an invalid/absent item. */
typedef struct {
    int map;
    const void *key;
    void *val_out;
} ktx_lookup_item;
int ktx_map_lookup_batch(ktx_env *e, const ktx_lookup_item *items,
                         size_t nitems);

ktx_thread *ktx_thread_create(ktx_env *e, int thread_idx);
void        ktx_thread_destroy(ktx_thread *t);

typedef struct {
    ktx_status status;
    uint64_t   verdict;      /* r0 on success; KTX_PASS (2) on any abort */
    uint32_t   log_records;  /* effect records this invocation (tx modes) */
    uint64_t   fuel_used;    /* instructions charged (0 in nofuel paths) */
} ktx_result;

/* One invocation.  pkt may be written at commit (intents) or directly
 * (direct modes).  fuel<=0 means "use default 65536". */
ktx_result ktx_run(ktx_thread *t, ktx_prog *p, ktx_mode mode,
                   uint8_t *pkt, uint32_t pkt_len, int64_t fuel);

/* Abort policy at an attachment point (DESIGN: abort semantics are a
 * mechanism; what an aborted invocation *returns* is policy). */
typedef struct {
    uint64_t default_verdict; /* verdict returned when the invocation aborts */
    uint32_t max_retries;     /* re-executions attempted on a conflict abort */
} ktx_policy;

/* ktx_run with an explicit abort policy.  ktx_run == ktx_run_ex with
 * {KTX_VERDICT_PASS, 0}.  Retries are attempted only for conflict aborts
 * (retrying a guard/fuel/helper abort would just repeat it). */
ktx_result ktx_run_ex(ktx_thread *t, ktx_prog *p, ktx_mode mode,
                      uint8_t *pkt, uint32_t pkt_len, int64_t fuel,
                      const ktx_policy *pol);

typedef struct {
    uint64_t commits, aborts_guard, aborts_fuel, aborts_helper,
             aborts_conflict, aborts_capacity, aborts_deadlock;
    uint64_t retries;            /* re-executions driven by ktx_policy */
    uint64_t elide_faults;       /* TX_AUDIT: analyzer facts proven wrong */
    uint64_t elide_audited;      /* TX_AUDIT: certified accesses executed */
} ktx_thread_stats;
void ktx_thread_stats_get(const ktx_thread *t, ktx_thread_stats *out);
void ktx_thread_stats_reset(ktx_thread *t);

uint64_t ktx_ringbuf_count(ktx_env *e);   /* records committed so far */
void     ktx_ringbuf_reset(ktx_env *e);

/* Runtime options (see ktx_opt).  Returns 0, or -1 on a bad option id. */
int ktx_env_set_opt(ktx_env *e, ktx_opt opt, int value);
int ktx_env_get_opt(const ktx_env *e, ktx_opt opt);

/* Memory accounting (E7): bytes of runtime state, so a deployment can be
 * sized.  Any out pointer may be NULL. */
void ktx_env_memory(const ktx_env *e, uint64_t *map_bytes,
                    uint64_t *map_meta_bytes, uint64_t *ring_bytes);
uint64_t ktx_thread_memory(void);        /* per-thread tx state, bytes */
/* High-water use of the per-invocation structures since the last stats
 * reset: arena bytes, effect records, read-set entries. */
void ktx_thread_hwm(const ktx_thread *t, uint32_t *arena_bytes,
                    uint32_t *records, uint32_t *readset);
uint64_t ktx_prog_memory(const ktx_prog *p); /* decoded streams, bytes */
/* Bytes of executable code emitted for p (0 when interpreted). */
uint64_t ktx_prog_jit_bytes(const ktx_prog *p);
int      ktx_prog_is_jitted(const ktx_prog *p);

/* Serialization stamp of this thread's most recent successful commit
 * (valid only when KTX_OPT_SEQ_TRACE is enabled). */
uint64_t ktx_thread_last_commit_seq(const ktx_thread *t);

#ifdef __cplusplus
}
#endif

#endif /* KTX_H */
