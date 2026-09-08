/* ser.c -> bin/ktxser : E8, a *falsifiable* serializability check on the
 * KTx transactional layer.
 *
 * Method (chain recovery).  Every transaction is a read-modify-write over
 * one key in each of two shared maps: it reads A[ka] and B[kb] and writes
 * back globally unique 64-bit tokens.  Because each write value is unique
 * and every read is of a key the same transaction also writes, the
 * observed history determines its own conflict graph with no global clock:
 *
 *   - reads-from: the transaction that wrote the value T read on key k is
 *     T's predecessor on k.  Following predecessors from the initial token
 *     reconstructs the total order of writes on k as a *chain*.
 *   - a fork in a chain (two transactions reading the same version of k and
 *     both committing a write to k) is a lost update: not serializable.
 *   - a cycle in the union of the per-key chains is a non-serializable
 *     interleaving across keys.
 *
 * A history is conflict-serializable exactly when every chain is a simple
 * path covering all its writers and the union graph is acyclic; the
 * offline checker (tools/ser_check.py) tests precisely that.  Running the
 * same workload with --mode direct (immediate, unsynchronised helper
 * effects, the eBPF model) is the control: it must fail, or the check is
 * vacuous.
 *
 * Output: one JSON envelope with metadata plus the full committed history.
 */
#include <inttypes.h>
#include <mach/mach_time.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <math.h>

#include "ktx_internal.h"

#define INIT_TOKEN 0x1000000000000000ULL   /* value both maps start at */

/* Transaction shapes.  `rmw` is the one the offline chain-recovery
 * checker consumes; the other three carry exact arithmetic invariants
 * that this harness checks itself, and exist because they exercise the
 * paths chain recovery cannot reach: the delete path, the lock-free
 * per-CPU commit path, and the validate-only read-only-map path (plus,
 * via a deliberately undersized map, the capacity-abort path). */
enum { SH_RMW = 0, SH_DELETE, SH_PERCPU, SH_ROELIDE, SH_N };
static const char *SHAPE_NAME[SH_N] = { "rmw", "delete", "percpu",
                                        "roelide" };
#define TOMB 0xFFFFFFFFFFFFFFFFULL

struct txrec {
    uint64_t seq;                          /* commit stamp (reporting only) */
    uint32_t ka, kb;
    uint64_t ra, rb, wa, wb;
};

typedef struct {
    ktx_env *env;
    int tid, nthreads;
    int direct;                            /* control: no transactions */
    int shape, split_writer;
    uint32_t nkeys;
    uint64_t ntx, seed;
    int map_a, map_b, map_c, map_d;
    double zipf_theta;
    /* out */
    struct txrec *recs;
    uint64_t nrecs, aborts, retries;
    /* shape-specific accounting */
    uint64_t inserted, removed, percpu_ops, ro_reads, cap_aborts;
    uint64_t *ins_tok, *del_tok;           /* delete shape: token ledgers */
    uint64_t n_ins, n_del;
    uint64_t ro_inconsistent;
} worker_t;

static pthread_mutex_t start_m = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  start_c = PTHREAD_COND_INITIALIZER;
static int start_go = 0;

static int cmp_u64(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

static inline uint64_t xs64(uint64_t *s) {
    uint64_t x = *s; x ^= x >> 12; x ^= x << 25; x ^= x >> 27; *s = x;
    return x * 0x2545F4914F6CDD1DULL;
}

/* Zipf via inverse-CDF over a precomputed table (small key space). */
static double *zipf_cdf;
static uint32_t zipf_n;
static void zipf_init(uint32_t n, double theta) {
    zipf_n = n;
    zipf_cdf = malloc(sizeof(double) * n);
    double sum = 0;
    for (uint32_t i = 0; i < n; i++) sum += 1.0 / pow((double)(i + 1), theta);
    double acc = 0;
    for (uint32_t i = 0; i < n; i++) {
        acc += (1.0 / pow((double)(i + 1), theta)) / sum;
        zipf_cdf[i] = acc;
    }
}
static uint32_t zipf_pick(uint64_t *s, double theta) {
    if (theta <= 0.0) return (uint32_t)(xs64(s) % zipf_n);
    double u = (double)(xs64(s) >> 11) / 9007199254740992.0;
    uint32_t lo = 0, hi = zipf_n - 1;
    while (lo < hi) {
        uint32_t mid = (lo + hi) / 2;
        if (zipf_cdf[mid] < u) lo = mid + 1; else hi = mid;
    }
    return lo;
}

static void *worker(void *arg) {
#if defined(__APPLE__)
    pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0);
#endif
    worker_t *w = (worker_t *)arg;
    ktx_thread *t = ktx_thread_create(w->env, w->tid);
    struct ktx_map *A = w->env->maps[w->map_a];
    struct ktx_map *B = w->env->maps[w->map_b];
    uint64_t s = w->seed ^ ((uint64_t)(w->tid + 1) * 0x9E3779B97F4A7C15ULL);
    uint64_t token = ((uint64_t)(w->tid + 1)) << 48;

    pthread_mutex_lock(&start_m);
    while (!start_go) pthread_cond_wait(&start_c, &start_m);
    pthread_mutex_unlock(&start_m);

    if (w->shape != SH_RMW) {
        struct ktx_map *C = w->map_c >= 0 ? w->env->maps[w->map_c] : NULL;
        struct ktx_map *D = w->map_d >= 0 ? w->env->maps[w->map_d] : NULL;
        uint64_t token = ((uint64_t)(w->tid + 1)) << 48;
        for (uint64_t i = 0; i < w->ntx; i++) {
            uint64_t k64 = zipf_pick(&s, w->zipf_theta);
            for (int attempt = 0; ; attempt++) {
                ktx_tx_begin(t);
                ktx_status st = KTX_OK;
                void *v = NULL; int sh = 0;
                if (w->shape == SH_DELETE) {
                    /* Present -> delete it (recording which token we
                     * removed); absent -> insert a fresh unique token.
                     * Every token must be inserted once and deleted at
                     * most once, and only after its insertion. */
                    st = ktx_tx_lookup(t, A, &k64, 0, &v, &sh);
                    uint64_t seen = 0;
                    if (st == KTX_OK && v) memcpy(&seen, v, 8);
                    if (st == KTX_OK && v) {
                        int present = 0;
                        st = ktx_tx_delete(t, A, &k64, &present);
                        if (st == KTX_OK && present) {
                            if (ktx_tx_commit(t, NULL, 0) == KTX_OK) {
                                w->del_tok[w->n_del++] = seen;
                                w->removed++;
                                break;
                            }
                        } else if (st == KTX_OK) {
                            ktx_tx_abort_reset(t); w->aborts++;
                            if (attempt >= 10000) break; continue;
                        }
                    } else if (st == KTX_OK) {
                        uint64_t nt = ++token;
                        st = ktx_tx_update(t, A, &k64, &nt);
                        ktx_status cs = (st == KTX_OK)
                            ? ktx_tx_commit(t, NULL, 0) : st;
                        if (cs == KTX_OK) {
                            w->ins_tok[w->n_ins++] = nt;
                            w->inserted++;
                            break;
                        }
                        if (cs == KTX_ABORT_CAPACITY) {
                            /* A full map is still full on retry: count
                             * the capacity abort and move on. */
                            w->cap_aborts++;
                            ktx_tx_abort_reset(t);
                            break;
                        }
                    }
                } else if (w->shape == SH_PERCPU) {
                    /* Lock-free per-CPU commit: the sum of all slots must
                     * equal the number of committed transactions, so an
                     * abort that leaked or a commit that dropped shows up
                     * as an arithmetic discrepancy. */
                    uint64_t slot = k64 & 7;
                    st = ktx_tx_lookup(t, C, &slot, 0, &v, &sh);
                    if (st == KTX_OK && v) {
                        uint64_t c; memcpy(&c, v, 8); c++;
                        memcpy(v, &c, 8);
                        if (ktx_tx_commit(t, NULL, 0) == KTX_OK) {
                            w->percpu_ops++; break;
                        }
                    }
                } else if (w->shape == SH_ROELIDE && (i & 15) == 0) {
                    /* One transaction in sixteen is the control-plane
                     * writer: it bumps both keys of the pair *together*,
                     * so a validate-only reader that commits having seen
                     * two different generations is a torn read through
                     * the read-only fast path. */
                    /* Disjoint pairs (2p, 2p+1): overlapping windows
                     * would mean no writer ever establishes the invariant
                     * the readers check. */
                    k64 = (k64 / 2) * 2;
                    uint64_t k2 = k64 + 1, g = 0;
                    void *p1 = NULL;
                    st = ktx_tx_lookup(t, D, &k64, 0, &p1, &sh);
                    if (st == KTX_OK && p1) { memcpy(&g, p1, 8); g++; }
                    if (w->split_writer) {
                        /* Control: update the two keys in *separate*
                         * transactions, so the pair invariant genuinely
                         * breaks and a checker with any power must see
                         * it. */
                        if (st == KTX_OK) st = ktx_tx_update(t, D, &k64, &g);
                        if (st == KTX_OK) ktx_tx_commit(t, NULL, 0);
                        ktx_tx_begin(t);
                        st = ktx_tx_update(t, D, &k2, &g);
                        if (st == KTX_OK) ktx_tx_commit(t, NULL, 0);
                        break;
                    }
                    if (st == KTX_OK) st = ktx_tx_update(t, D, &k64, &g);
                    if (st == KTX_OK) st = ktx_tx_update(t, D, &k2, &g);
                    if (st == KTX_OK && ktx_tx_commit(t, NULL, 0) == KTX_OK)
                        break;
                } else {  /* SH_ROELIDE reader */
                    /* Validate-only reads of a map the program never
                     * writes, while a control thread rewrites it: two
                     * keys of D always carry the same generation, so a
                     * committed transaction that saw two different
                     * generations is a torn validate-only read. */
                    k64 = (k64 / 2) * 2;
                    uint64_t k2 = k64 + 1, g1 = 0, g2 = 0;
                    void *p1 = NULL, *p2 = NULL;
                    st = ktx_tx_lookup(t, D, &k64, 1, &p1, &sh);
                    if (st == KTX_OK && p1) memcpy(&g1, p1, 8);
                    if (st == KTX_OK)
                        st = ktx_tx_lookup(t, D, &k2, 1, &p2, &sh);
                    if (st == KTX_OK && p2) memcpy(&g2, p2, 8);
                    uint64_t nt = ++token;
                    if (st == KTX_OK) st = ktx_tx_update(t, A, &k64, &nt);
                    if (st == KTX_OK && p1 && p2 &&
                        ktx_tx_commit(t, NULL, 0) == KTX_OK) {
                        w->ro_reads++;
                        if (g1 != g2) w->ro_inconsistent++;
                        break;
                    }
                }
                ktx_tx_abort_reset(t);
                w->aborts++;
                if (attempt >= 10000) break;
                w->retries++;
            }
        }
        ktx_thread_destroy(t);
        return NULL;
    }

    for (uint64_t i = 0; i < w->ntx; i++) {
        uint64_t ka64 = zipf_pick(&s, w->zipf_theta);
        uint64_t kb64 = zipf_pick(&s, w->zipf_theta);
        uint32_t ka = (uint32_t)ka64, kb = (uint32_t)kb64;
        uint64_t wa = ++token, wb = ++token;

        if (w->direct) {
            /* Control: immediate effects, exactly eBPF's helper model. */
            uint64_t *pa = (uint64_t *)ktx_map_direct_lookup(A, &ka64, w->tid);
            uint64_t *pb = (uint64_t *)ktx_map_direct_lookup(B, &kb64, w->tid);
            if (!pa || !pb) continue;
            uint64_t ra = *pa, rb = *pb;
            *pa = wa;
            *pb = wb;
            struct txrec *r = &w->recs[w->nrecs++];
            r->seq = atomic_fetch_add_explicit(&w->env->commit_seq, 1,
                                               memory_order_acq_rel);
            r->ka = ka; r->kb = kb; r->ra = ra; r->rb = rb;
            r->wa = wa; r->wb = wb;
            continue;
        }

        for (int attempt = 0; ; attempt++) {
            ktx_tx_begin(t);
            void *va = NULL, *vb = NULL;
            int sh = 0;
            ktx_status st = ktx_tx_lookup(t, A, &ka64, 0, &va, &sh);
            if (st == KTX_OK) st = ktx_tx_lookup(t, B, &kb64, 0, &vb, &sh);
            if (st != KTX_OK || !va || !vb) { ktx_tx_abort_reset(t); break; }
            uint64_t ra, rb;
            memcpy(&ra, va, 8);
            memcpy(&rb, vb, 8);
            memcpy(va, &wa, 8);            /* store through the shadow */
            memcpy(vb, &wb, 8);
            st = ktx_tx_commit(t, NULL, 0);
            if (st == KTX_OK) {
                struct txrec *r = &w->recs[w->nrecs++];
                r->seq = ktx_thread_last_commit_seq(t);
                r->ka = ka; r->kb = kb; r->ra = ra; r->rb = rb;
                r->wa = wa; r->wb = wb;
                break;
            }
            ktx_tx_abort_reset(t);
            w->aborts++;
            if (attempt >= 10000) break;   /* livelock guard; never hit */
            w->retries++;
        }
    }
    ktx_thread_destroy(t);
    return NULL;
}

int main(int argc, char **argv) {
    int nthreads = 8, direct = 0, shape = SH_RMW, split_writer = 0;
    uint32_t nkeys = 64;
    uint64_t ntx = 100000, seed = 42;
    double theta = 0.0;
    uint32_t capmax = 4096;                /* undersize to force capacity */
    const char *out = NULL;
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        const char *v = (i + 1 < argc) ? argv[i + 1] : NULL;
#define ARG(n) (strcmp(a, n) == 0 && v && ++i)
        if (ARG("--threads")) nthreads = atoi(v);
        else if (ARG("--tx-per-thread")) ntx = strtoull(v, NULL, 0);
        else if (ARG("--keys")) nkeys = (uint32_t)strtoul(v, NULL, 0);
        else if (ARG("--seed")) seed = strtoull(v, NULL, 0);
        else if (ARG("--zipf")) theta = atof(v);
        else if (ARG("--mode")) direct = (strcmp(v, "direct") == 0);
        else if (ARG("--cap")) capmax = (uint32_t)strtoul(v, NULL, 0);
        else if (strcmp(a, "--split-writer") == 0) { split_writer = 1;
                                                     continue; }
        else if (ARG("--shape")) {
            shape = -1;
            for (int j = 0; j < SH_N; j++)
                if (strcmp(v, SHAPE_NAME[j]) == 0) shape = j;
            if (shape < 0) { fprintf(stderr, "bad --shape %s\n", v);
                             return 2; }
        }
        else if (ARG("--out")) out = v;
        else { fprintf(stderr,
                "usage: ktxser [--threads N] [--tx-per-thread M] [--keys K]\n"
                "  [--zipf T] [--mode tx|direct] [--shape rmw|delete|percpu|"
                "roelide]\n  [--cap N] [--seed S] --out FILE.json\n");
               return 2; }
#undef ARG
    }
    if (!out) { fprintf(stderr, "ktxser: --out required\n"); return 2; }

    ktx_env *env = ktx_env_create(nthreads);
    if (!env) { fprintf(stderr, "env create failed\n"); return 1; }
    ktx_env_set_opt(env, KTX_OPT_SEQ_TRACE, 1);
    char err[256];
    struct ktx_map *A = ktx_env_map_create(env, KTX_MAP_HASH, 8, 8, capmax,
                                           "ser_a", err, sizeof err);
    struct ktx_map *B = ktx_env_map_create(env, KTX_MAP_HASH, 8, 8, capmax,
                                           "ser_b", err, sizeof err);
    struct ktx_map *C = ktx_env_map_create(env, KTX_MAP_PERCPU_ARRAY, 4, 8,
                                           8, "ser_c", err, sizeof err);
    struct ktx_map *D = ktx_env_map_create(env, KTX_MAP_HASH, 8, 8, 4096,
                                           "ser_d", err, sizeof err);
    if (!A || !B || !C || !D) {
        fprintf(stderr, "map create: %s\n", err); return 1;
    }
    for (uint32_t k = 0; k < nkeys; k++) {
        uint64_t k64 = k, init = INIT_TOKEN;
        if (shape != SH_DELETE) ktx_map_update(env, (int)A->id, &k64, &init);
        ktx_map_update(env, (int)B->id, &k64, &init);
        uint64_t gen = 1;
        ktx_map_update(env, (int)D->id, &k64, &gen);
    }
    for (uint32_t k = 0; k < 8; k++) {
        uint32_t k32 = k; uint64_t z = 0;
        ktx_map_update(env, (int)C->id, &k32, &z);
    }
    zipf_init(nkeys, theta);

    worker_t *ws = calloc(nthreads, sizeof(*ws));
    pthread_t *th = calloc(nthreads, sizeof(*th));
    for (int i = 0; i < nthreads; i++) {
        ws[i] = (worker_t){ .env = env, .tid = i, .nthreads = nthreads,
                            .direct = direct, .shape = shape,
                            .split_writer = split_writer,
                            .nkeys = nkeys, .ntx = ntx,
                            .seed = seed, .map_a = (int)A->id,
                            .map_b = (int)B->id, .map_c = (int)C->id,
                            .map_d = (int)D->id, .zipf_theta = theta };
        ws[i].recs = malloc(sizeof(struct txrec) * ntx);
        ws[i].ins_tok = malloc(sizeof(uint64_t) * ntx);
        ws[i].del_tok = malloc(sizeof(uint64_t) * ntx);
        if (!ws[i].recs || !ws[i].ins_tok || !ws[i].del_tok) {
            fprintf(stderr, "oom\n"); return 1;
        }
        pthread_create(&th[i], NULL, worker, &ws[i]);
    }
    mach_timebase_info_data_t tb; mach_timebase_info(&tb);
    pthread_mutex_lock(&start_m); start_go = 1;
    pthread_cond_broadcast(&start_c); pthread_mutex_unlock(&start_m);
    uint64_t t0 = mach_absolute_time();
    for (int i = 0; i < nthreads; i++) pthread_join(th[i], NULL);
    uint64_t t1 = mach_absolute_time();
    double wall = (double)(t1 - t0) * tb.numer / tb.denom / 1e9;

    FILE *f = fopen(out, "w");
    if (!f) { perror("fopen"); return 1; }
    uint64_t total = 0, aborts = 0, retries = 0;
    for (int i = 0; i < nthreads; i++) {
        total += ws[i].nrecs; aborts += ws[i].aborts; retries += ws[i].retries;
    }
    /* ---- shape invariants, checked here rather than offline ---- */
    uint64_t inserted = 0, removed = 0, percpu_ops = 0, ro_reads = 0,
             ro_bad = 0, cap_aborts = 0;
    uint64_t dup_delete = 0, delete_without_insert = 0, live_mismatch = 0,
             percpu_sum = 0;
    for (int i = 0; i < nthreads; i++) {
        inserted += ws[i].inserted; removed += ws[i].removed;
        percpu_ops += ws[i].percpu_ops; ro_reads += ws[i].ro_reads;
        ro_bad += ws[i].ro_inconsistent; cap_aborts += ws[i].cap_aborts;
    }
    if (shape == SH_DELETE) {
        /* Every deleted token must have been inserted exactly once and
         * deleted at most once; and the map must end holding exactly the
         * inserted-but-not-deleted tokens. */
        uint64_t ni = 0, nd = 0;
        for (int i = 0; i < nthreads; i++) { ni += ws[i].n_ins;
                                             nd += ws[i].n_del; }
        uint64_t *ins = malloc(sizeof(uint64_t) * (ni ? ni : 1));
        uint64_t *del = malloc(sizeof(uint64_t) * (nd ? nd : 1));
        uint64_t a = 0, b = 0;
        for (int i = 0; i < nthreads; i++) {
            memcpy(ins + a, ws[i].ins_tok, ws[i].n_ins * 8); a += ws[i].n_ins;
            memcpy(del + b, ws[i].del_tok, ws[i].n_del * 8); b += ws[i].n_del;
        }
        qsort(ins, ni, sizeof(uint64_t), cmp_u64);
        qsort(del, nd, sizeof(uint64_t), cmp_u64);
        for (uint64_t x = 0; x < nd; x++) {
            if (x + 1 < nd && del[x + 1] == del[x]) dup_delete++;
            if (!bsearch(&del[x], ins, ni, sizeof(uint64_t), cmp_u64))
                delete_without_insert++;
        }
        uint64_t live = 0;
        for (uint32_t k = 0; k < nkeys; k++) {
            uint64_t k64 = k, v = 0;
            if (ktx_map_lookup(env, (int)A->id, &k64, &v) == 0) {
                live++;
                int was_ins = bsearch(&v, ins, ni, sizeof(uint64_t),
                                      cmp_u64) != NULL;
                int was_del = bsearch(&v, del, nd, sizeof(uint64_t),
                                      cmp_u64) != NULL;
                if (!was_ins || was_del) live_mismatch++;
            }
        }
        if (live != inserted - removed) live_mismatch++;
        free(ins); free(del);
    }
    if (shape == SH_DELETE) total = inserted + removed;
    else if (shape == SH_PERCPU) total = percpu_ops;
    else if (shape == SH_ROELIDE) total = ro_reads;
    if (shape == SH_PERCPU)
        for (uint32_t k = 0; k < 8; k++)
            for (int t2 = 0; t2 < nthreads; t2++) {
                uint32_t k32 = k; uint64_t v = 0;
                if (ktx_map_lookup_percpu(env, (int)C->id, &k32, t2, &v) == 0)
                    percpu_sum += v;
            }

    fprintf(f, "{\n  \"experiment\": \"e8_serializability\",\n");
    fprintf(f, "  \"meta\": { \"mode\": \"%s\", \"threads\": %d, "
               "\"tx_per_thread\": %" PRIu64 ", \"keys\": %u, "
               "\"zipf_theta\": %.3f, \"seed\": %" PRIu64 ", "
               "\"init_token\": %" PRIu64 ", \"wall_s\": %.6f,\n"
               "            \"cmdline\": \"",
            direct ? "direct" : "tx", nthreads, ntx, nkeys, theta, seed,
            (uint64_t)INIT_TOKEN, wall);
    for (int i = 0; i < argc; i++) fprintf(f, "%s%s", i ? " " : "", argv[i]);
    fprintf(f, "\" },\n");
    fprintf(f, "  \"shape\": \"%s\", \"split_writer\": %d,\n",
            SHAPE_NAME[shape], split_writer);
    fprintf(f, "  \"committed\": %" PRIu64 ", \"conflict_aborts\": %" PRIu64
               ", \"retries\": %" PRIu64 ",\n", total, aborts, retries);
    fprintf(f, "  \"shape_metrics\": { \"inserted\": %" PRIu64
               ", \"removed\": %" PRIu64 ", \"percpu_ops\": %" PRIu64
               ", \"percpu_sum\": %" PRIu64 ",\n"
               "    \"ro_reads\": %" PRIu64 ", \"capacity_aborts\": %" PRIu64
               ",\n    \"VIOL_double_delete\": %" PRIu64
               ", \"VIOL_delete_without_insert\": %" PRIu64 ",\n"
               "    \"VIOL_live_set_mismatch\": %" PRIu64
               ", \"VIOL_torn_readonly_read\": %" PRIu64
               ", \"VIOL_percpu_count\": %" PRId64 " },\n",
            inserted, removed, percpu_ops, percpu_sum, ro_reads, cap_aborts,
            dup_delete, delete_without_insert, live_mismatch, ro_bad,
            (int64_t)percpu_sum - (int64_t)percpu_ops);
    /* final map state, for the end-to-end check */
    fprintf(f, "  \"final_a\": [");
    for (uint32_t k = 0; k < nkeys; k++) {
        uint64_t k64 = k, v = 0;
        ktx_map_lookup(env, (int)A->id, &k64, &v);
        fprintf(f, "%s%" PRIu64, k ? "," : "", v);
    }
    fprintf(f, "],\n  \"final_b\": [");
    for (uint32_t k = 0; k < nkeys; k++) {
        uint64_t k64 = k, v = 0;
        ktx_map_lookup(env, (int)B->id, &k64, &v);
        fprintf(f, "%s%" PRIu64, k ? "," : "", v);
    }
    fprintf(f, "],\n  \"history\": [\n");
    int first = 1;
    for (int i = 0; i < nthreads; i++)
        for (uint64_t j = 0; j < ws[i].nrecs; j++) {
            struct txrec *r = &ws[i].recs[j];
            fprintf(f, "%s    [%" PRIu64 ",%u,%u,%" PRIu64 ",%" PRIu64
                       ",%" PRIu64 ",%" PRIu64 "]",
                    first ? "" : ",\n", r->seq, r->ka, r->kb, r->ra, r->rb,
                    r->wa, r->wb);
            first = 0;
        }
    fprintf(f, "\n  ]\n}\n");
    fclose(f);
    fprintf(stderr, "ktxser: shape=%s %s, %" PRIu64 " committed, %" PRIu64
                    " aborts (%" PRIu64 " capacity), %.3f s; violations:"
                    " dbl-del %" PRIu64 " del-w/o-ins %" PRIu64
                    " live %" PRIu64 " torn-RO %" PRIu64
                    " percpu %" PRId64 "\n",
            SHAPE_NAME[shape], direct ? "direct" : "tx", total, aborts,
            cap_aborts, wall, dup_delete, delete_without_insert,
            live_mismatch, ro_bad,
            shape == SH_PERCPU ? (int64_t)percpu_sum - (int64_t)percpu_ops
                               : 0);
    for (int i = 0; i < nthreads; i++) {
        free(ws[i].recs); free(ws[i].ins_tok); free(ws[i].del_tok);
    }
    free(ws); free(th);
    ktx_env_destroy(env);
    return 0;
}
