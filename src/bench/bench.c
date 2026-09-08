/* bench.c -> bin/ktxbench : E1 (latency/throughput) and E5 (contention).
 * DESIGN.md section 8.1. C11, macOS/mach timing, pthreads.
 *
 * Latency (threads==1): warmup, then M invocations timed in batches of
 * --batch mach_absolute_time reads; packets for a batch are generated
 * OUTSIDE the timed region (timed_region = ktx_run_only).
 * Throughput: N threads, start barrier, per-thread op counts; packet
 * generation inline (part of the measured pipeline).
 *
 * Honesty: every metric in the output JSON comes from this process's own
 * run; failures produce an "error" field and a nonzero exit code.
 */
#include <errno.h>
#include <inttypes.h>
#include <mach/mach_time.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <mach/mach.h>

#include "ktx.h"
#include "ktx_format.h"
#include "trace.h"

/* Resident set size of this process, for the memory accounting (E7). */
static uint64_t rss_bytes(void) {
    mach_task_basic_info_data_t info;
    mach_msg_type_number_t cnt = MACH_TASK_BASIC_INFO_COUNT;
    if (task_info(mach_task_self(), MACH_TASK_BASIC_INFO,
                  (task_info_t)&info, &cnt) != KERN_SUCCESS)
        return 0;
    return (uint64_t)info.resident_size;
}

#define PKT_CAP 2048u
#define ERRLEN 512

typedef struct {
    const char *prog_path, *elide_path, *mode_str, *measure, *exp, *out;
    ktx_mode mode;
    int threads;
    uint64_t iters, warmup;
    uint64_t seed;
    uint32_t nkeys;
    double zipf_theta;
    uint32_t pktlen_min, pktlen_max;
    int64_t fuel;
    uint32_t batch;
    int no_shadow_diff;               /* reproduce the naive redo log */
    int jit;                          /* compile the body to native code */
} opts_t;

/* ---- barrier (macOS has no pthread_barrier) ------------------------------ */
typedef struct {
    pthread_mutex_t m;
    pthread_cond_t c;
    int count, total, gen;
} bar_t;

static void bar_init(bar_t *b, int total) {
    pthread_mutex_init(&b->m, NULL);
    pthread_cond_init(&b->c, NULL);
    b->count = 0;
    b->total = total;
    b->gen = 0;
}

static void bar_wait(bar_t *b) {
    pthread_mutex_lock(&b->m);
    int g = b->gen;
    if (++b->count == b->total) {
        b->count = 0;
        b->gen++;
        pthread_cond_broadcast(&b->c);
    } else {
        while (g == b->gen) pthread_cond_wait(&b->c, &b->m);
    }
    pthread_mutex_unlock(&b->m);
}

/* ---- map init (harness detects maps by name, DESIGN 7/8.1) --------------- */
static void init_named_maps(ktx_env *env) {
    int id = ktx_map_id(env, "table");
    if (id >= 0) { /* maglev: table[i] = splitmix64(i) % 64, 4093 entries */
        for (uint32_t i = 0; i < 4093; i++) {
            uint64_t s = i;
            uint32_t v = (uint32_t)(tr_splitmix64(&s) % 64);
            ktx_map_update(env, id, &i, &v);
        }
    }
    int lt = ktx_map_id(env, "lb_table");
    if (lt >= 0) { /* l4lb: 64 backends spread over the lookup table */
        for (uint32_t i = 0; i < 4096; i++) {
            uint64_t sd = i;
            uint32_t v = (uint32_t)(tr_splitmix64(&sd) % 64);
            ktx_map_update(env, lt, &i, &v);
        }
    }
    int pr = ktx_map_id(env, "pol_rules");
    if (pr >= 0) { /* policy: 1 in 8 identities denied */
        for (uint32_t id = 0; id < 1024; id++)
            for (uint32_t dp = 0; dp < 8; dp++) {
                struct { uint32_t identity, dport; } k = { id, dp };
                uint64_t v = (id % 8 == 0) ? 1 : 2;   /* DROP : PASS */
                ktx_map_update(env, pr, &k, &v);
            }
    }
    int bl = ktx_map_id(env, "blocklist");
    if (bl >= 0) { /* firewall: block 1/8 of the flow-id space */
        for (uint32_t k = 0; k < 128; k++) {
            uint64_t key = tr_flow_key(k * 8), one = 1;
            ktx_map_update(env, bl, &key, &one);
        }
    }
    int a = ktx_map_id(env, "acct_a"), b = ktx_map_id(env, "acct_b");
    if (a >= 0 && b >= 0) { /* atomic pair: A[k]=1000, B[k]=0 */
        for (uint32_t k = 0; k < 256; k++) {
            uint64_t va = 1000, vb = 0;
            ktx_map_update(env, a, &k, &va);
            ktx_map_update(env, b, &k, &vb);
        }
    }
}

/* ---- throughput worker --------------------------------------------------- */
typedef struct {
    const opts_t *o;
    ktx_env *env;
    ktx_prog *prog;
    const tr_zipf *zipf;
    bar_t *bar;
    int tid;
    /* out */
    uint64_t start_tick, end_tick, ops;
    ktx_thread_stats stats;
    uint32_t hwm_arena, hwm_recs, hwm_reads;
    int failed;
    char err[ERRLEN];
} worker_t;

static void *thr_main(void *arg) {
    worker_t *w = (worker_t *)arg;
    tr_qos_perf();
    const opts_t *o = w->o;
    uint8_t *pkt = malloc(PKT_CAP);
    ktx_thread *th = ktx_thread_create(w->env, w->tid);
    if (!th || !pkt) {
        snprintf(w->err, ERRLEN, "thread %d: alloc/create failed", w->tid);
        w->failed = 1;
        bar_wait(w->bar);
        free(pkt);
        if (th) ktx_thread_destroy(th);
        return NULL;
    }
    uint64_t prng = tr_thread_seed(o->seed, w->tid);
    for (uint64_t i = 0; i < o->warmup; i++) {
        uint32_t fid = tr_zipf_sample(w->zipf, &prng);
        uint32_t len = tr_fill_packet(pkt, PKT_CAP, fid, &prng,
                                      o->pktlen_min, o->pktlen_max);
        (void)ktx_run(th, w->prog, o->mode, pkt, len, o->fuel);
    }
    ktx_thread_stats_reset(th);
    bar_wait(w->bar);
    w->start_tick = mach_absolute_time();
    for (uint64_t i = 0; i < o->iters; i++) {
        uint32_t fid = tr_zipf_sample(w->zipf, &prng);
        uint32_t len = tr_fill_packet(pkt, PKT_CAP, fid, &prng,
                                      o->pktlen_min, o->pktlen_max);
        (void)ktx_run(th, w->prog, o->mode, pkt, len, o->fuel);
    }
    w->end_tick = mach_absolute_time();
    w->ops = o->iters;
    ktx_thread_stats_get(th, &w->stats);
    ktx_thread_hwm(th, &w->hwm_arena, &w->hwm_recs, &w->hwm_reads);
    ktx_thread_destroy(th);
    free(pkt);
    return NULL;
}

/* ---- JSON helpers -------------------------------------------------------- */
static void write_stats(FILE *f, const ktx_thread_stats *s) {
    fprintf(f,
            "\"commits\": %llu, \"aborts_guard\": %llu, "
            "\"aborts_fuel\": %llu, \"aborts_helper\": %llu, "
            "\"aborts_conflict\": %llu, \"aborts_capacity\": %llu, "
            "\"aborts_deadlock\": %llu, \"retries\": %llu, "
            "\"elide_faults\": %llu, \"elide_audited\": %llu",
            (unsigned long long)s->commits,
            (unsigned long long)s->aborts_guard,
            (unsigned long long)s->aborts_fuel,
            (unsigned long long)s->aborts_helper,
            (unsigned long long)s->aborts_conflict,
            (unsigned long long)s->aborts_capacity,
            (unsigned long long)s->aborts_deadlock,
            (unsigned long long)s->retries,
            (unsigned long long)s->elide_faults,
            (unsigned long long)s->elide_audited);
}

static const char *prog_basename(const char *p) {
    const char *s = strrchr(p, '/');
    return s ? s + 1 : p;
}

static int cmp_dbl(const void *a, const void *b) {
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}

static double nearest_rank(const double *sorted, uint64_t n, double pct) {
    uint64_t rank = (uint64_t)((pct / 100.0) * (double)n + 0.9999999);
    if (rank < 1) rank = 1;
    if (rank > n) rank = n;
    return sorted[rank - 1];
}

/* ---- main ---------------------------------------------------------------- */
static void usage(void) {
    fprintf(stderr,
        "usage: ktxbench --prog F.kbin [--elide F.elide] --mode "
        "vanilla|sfi|tx|tx-elide|2pl|p2pl|coarse\n  [--no-shadow-diff] "
        "vanilla|sfi|tx|tx-elide\n"
        "  --measure latency|throughput [--threads N] [--iters M] "
        "[--warmup W]\n"
        "  [--seed S] [--nkeys K] [--zipf T] [--pktlen-min A] "
        "[--pktlen-max B]\n"
        "  [--fuel F] [--batch 32] [--exp NAME] --out FILE.json\n");
}

int main(int argc, char **argv) {
    tr_qos_perf();
    opts_t o = {
        .prog_path = NULL, .elide_path = NULL, .mode_str = NULL,
        .measure = NULL, .exp = "e1", .out = NULL,
        .mode = KTX_MODE_VANILLA, .threads = 1,
        .iters = 1000000, .warmup = 100000, .seed = 42, .nkeys = 1024,
        .zipf_theta = 0.0, .pktlen_min = 64, .pktlen_max = 256,
        .fuel = 65536, .batch = 32,
    };
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        const char *v = (i + 1 < argc) ? argv[i + 1] : NULL;
#define ARG(name) (strcmp(a, name) == 0 && v && ++i)
        if (ARG("--prog")) o.prog_path = v;
        else if (ARG("--elide")) o.elide_path = v;
        else if (ARG("--mode")) o.mode_str = v;
        else if (ARG("--measure")) o.measure = v;
        else if (ARG("--threads")) o.threads = atoi(v);
        else if (ARG("--iters")) o.iters = strtoull(v, NULL, 0);
        else if (ARG("--warmup")) o.warmup = strtoull(v, NULL, 0);
        else if (ARG("--seed")) o.seed = strtoull(v, NULL, 0);
        else if (ARG("--nkeys")) o.nkeys = (uint32_t)strtoul(v, NULL, 0);
        else if (ARG("--zipf")) o.zipf_theta = atof(v);
        else if (ARG("--pktlen-min")) o.pktlen_min = (uint32_t)atoi(v);
        else if (ARG("--pktlen-max")) o.pktlen_max = (uint32_t)atoi(v);
        else if (ARG("--fuel")) o.fuel = strtoll(v, NULL, 0);
        else if (strcmp(a, "--no-shadow-diff") == 0) { o.no_shadow_diff = 1; continue; }
        else if (strcmp(a, "--jit") == 0) { o.jit = 1; continue; }
        else if (ARG("--batch")) o.batch = (uint32_t)atoi(v);
        else if (ARG("--exp")) o.exp = v;
        else if (ARG("--out")) o.out = v;
        else { usage(); fprintf(stderr, "bad arg: %s\n", a); return 2; }
#undef ARG
    }
    if (!o.prog_path || !o.mode_str || !o.measure || !o.out) {
        usage();
        return 2;
    }
    int is_latency;
    if (strcmp(o.measure, "latency") == 0) is_latency = 1;
    else if (strcmp(o.measure, "throughput") == 0) is_latency = 0;
    else { usage(); return 2; }
    if (strcmp(o.mode_str, "vanilla") == 0) o.mode = KTX_MODE_VANILLA;
    else if (strcmp(o.mode_str, "sfi") == 0) o.mode = KTX_MODE_SFI;
    else if (strcmp(o.mode_str, "tx") == 0) o.mode = KTX_MODE_TX;
    else if (strcmp(o.mode_str, "tx-elide") == 0) o.mode = KTX_MODE_TX_ELIDE;
    else if (strcmp(o.mode_str, "2pl") == 0) o.mode = KTX_MODE_2PL;
    else if (strcmp(o.mode_str, "p2pl") == 0) o.mode = KTX_MODE_P2PL;
    else if (strcmp(o.mode_str, "coarse") == 0) o.mode = KTX_MODE_COARSE;
    else if (strcmp(o.mode_str, "tx-audit") == 0) o.mode = KTX_MODE_TX_AUDIT;
    else { usage(); fprintf(stderr, "bad mode %s\n", o.mode_str); return 2; }

    char err[ERRLEN] = "";
    uint32_t hwm_arena = 0, hwm_recs = 0, hwm_reads = 0;
    ktx_env *env = NULL;
    ktx_prog *prog = NULL;
    tr_zipf zipf = {0};

    /* results (latency) */
    double ns_min = 0, p50 = 0, p90 = 0, p99 = 0, p999 = 0, ns_mean = 0;
    uint64_t iters_timed = 0, nbatches = 0;
    ktx_thread_stats agg;
    memset(&agg, 0, sizeof agg);
    /* results (throughput) */
    double wall_s = 0, mops = 0;
    uint64_t ops_total = 0;
    worker_t *ws = NULL;
    int nthr = o.threads;

    if (nthr < 1 || nthr > 64) {
        snprintf(err, ERRLEN, "bad thread count %d", nthr);
        goto out;
    }
    if (is_latency && nthr != 1) {
        snprintf(err, ERRLEN, "latency requires --threads 1 (got %d)", nthr);
        goto out;
    }
    if (o.batch < 1 || o.nkeys < 1 || o.iters < 1) {
        snprintf(err, ERRLEN, "batch/nkeys/iters must be >= 1");
        goto out;
    }
    env = ktx_env_create(nthr);
    if (!env) {
        snprintf(err, ERRLEN, "ktx_env_create(%d) failed", nthr);
        goto out;
    }
    if (o.no_shadow_diff) ktx_env_set_opt(env, KTX_OPT_SHADOW_DIFF, 0);
    if (o.jit) ktx_env_set_opt(env, KTX_OPT_JIT, 1);   /* before prog load */
    prog = ktx_prog_load(env, o.prog_path, o.elide_path, err, ERRLEN);
    if (!prog) {
        if (!err[0]) snprintf(err, ERRLEN, "ktx_prog_load failed");
        goto out;
    }
    init_named_maps(env);
    if (tr_zipf_init(&zipf, o.nkeys, o.zipf_theta) != 0) {
        snprintf(err, ERRLEN, "zipf init failed (nkeys=%u)", o.nkeys);
        goto out;
    }

    if (is_latency) {
        ktx_thread *th = ktx_thread_create(env, 0);
        uint8_t *bufs = malloc((size_t)o.batch * PKT_CAP);
        uint32_t *lens = malloc(o.batch * sizeof(uint32_t));
        nbatches = o.iters / o.batch;
        double *means = malloc(nbatches * sizeof(double));
        if (!th || !bufs || !lens || !means || nbatches == 0) {
            snprintf(err, ERRLEN, "latency setup failed (alloc or iters<batch)");
            free(bufs); free(lens); free(means);
            if (th) ktx_thread_destroy(th);
            goto out;
        }
        uint64_t prng = tr_thread_seed(o.seed, 0);
        for (uint64_t i = 0; i < o.warmup; i++) {
            uint32_t fid = tr_zipf_sample(&zipf, &prng);
            uint32_t len = tr_fill_packet(bufs, PKT_CAP, fid, &prng,
                                          o.pktlen_min, o.pktlen_max);
            (void)ktx_run(th, prog, o.mode, bufs, len, o.fuel);
        }
        ktx_thread_stats_reset(th);
        uint64_t total_ticks = 0;
        for (uint64_t b = 0; b < nbatches; b++) {
            for (uint32_t j = 0; j < o.batch; j++) {
                uint32_t fid = tr_zipf_sample(&zipf, &prng);
                lens[j] = tr_fill_packet(bufs + (size_t)j * PKT_CAP, PKT_CAP,
                                         fid, &prng, o.pktlen_min,
                                         o.pktlen_max);
            }
            uint64_t t0 = mach_absolute_time();
            for (uint32_t j = 0; j < o.batch; j++)
                (void)ktx_run(th, prog, o.mode, bufs + (size_t)j * PKT_CAP,
                              lens[j], o.fuel);
            uint64_t t1 = mach_absolute_time();
            total_ticks += t1 - t0;
            means[b] = tr_ticks_to_ns(t1 - t0) / (double)o.batch;
        }
        iters_timed = nbatches * o.batch;
        ktx_thread_stats_get(th, &agg);
        ktx_thread_hwm(th, &hwm_arena, &hwm_recs, &hwm_reads);
        qsort(means, nbatches, sizeof(double), cmp_dbl);
        ns_min = means[0];
        p50 = nearest_rank(means, nbatches, 50.0);
        p90 = nearest_rank(means, nbatches, 90.0);
        p99 = nearest_rank(means, nbatches, 99.0);
        p999 = nearest_rank(means, nbatches, 99.9);
        ns_mean = tr_ticks_to_ns(total_ticks) / (double)iters_timed;
        ktx_thread_destroy(th);
        free(bufs); free(lens); free(means);
    } else {
        ws = calloc((size_t)nthr, sizeof(worker_t));
        pthread_t *tids = calloc((size_t)nthr, sizeof(pthread_t));
        bar_t bar;
        if (!ws || !tids) {
            snprintf(err, ERRLEN, "worker alloc failed");
            free(tids);
            goto out;
        }
        bar_init(&bar, nthr);
        (void)tr_timebase(); /* init timebase before workers race on it */
        for (int t = 0; t < nthr; t++) {
            ws[t] = (worker_t){ .o = &o, .env = env, .prog = prog,
                                .zipf = &zipf, .bar = &bar, .tid = t };
            if (pthread_create(&tids[t], NULL, thr_main, &ws[t]) != 0) {
                snprintf(err, ERRLEN, "pthread_create %d failed", t);
                /* threads already started will block on the barrier;
                   fail hard rather than deadlock */
                fprintf(stderr, "ktxbench: %s\n", err);
                exit(1);
            }
        }
        for (int t = 0; t < nthr; t++) pthread_join(tids[t], NULL);
        free(tids);
        uint64_t min_start = UINT64_MAX, max_end = 0;
        for (int t = 0; t < nthr; t++) {
            if (ws[t].failed) {
                snprintf(err, ERRLEN, "%s", ws[t].err);
                goto out;
            }
            if (ws[t].start_tick < min_start) min_start = ws[t].start_tick;
            if (ws[t].end_tick > max_end) max_end = ws[t].end_tick;
            ops_total += ws[t].ops;
            agg.commits += ws[t].stats.commits;
            agg.aborts_guard += ws[t].stats.aborts_guard;
            agg.aborts_fuel += ws[t].stats.aborts_fuel;
            agg.aborts_helper += ws[t].stats.aborts_helper;
            agg.aborts_conflict += ws[t].stats.aborts_conflict;
            agg.aborts_capacity += ws[t].stats.aborts_capacity;
            agg.aborts_deadlock += ws[t].stats.aborts_deadlock;
            agg.retries += ws[t].stats.retries;
            agg.elide_faults += ws[t].stats.elide_faults;
            agg.elide_audited += ws[t].stats.elide_audited;
            if (ws[t].hwm_arena > hwm_arena) hwm_arena = ws[t].hwm_arena;
            if (ws[t].hwm_recs  > hwm_recs)  hwm_recs  = ws[t].hwm_recs;
            if (ws[t].hwm_reads > hwm_reads) hwm_reads = ws[t].hwm_reads;
        }
        wall_s = tr_ticks_to_ns(max_end - min_start) / 1e9;
        mops = (wall_s > 0) ? (double)ops_total / wall_s / 1e6 : 0.0;
    }

out:;
    FILE *f = fopen(o.out, "w");
    if (!f) {
        fprintf(stderr, "ktxbench: cannot open %s: %s\n", o.out,
                strerror(errno));
        return 1;
    }
    fprintf(f, "{\n  \"experiment\": \"%s\",\n  ", o.exp);
    tr_write_meta(f, o.seed, argc, argv, is_latency ? (int)o.batch : -1);
    fprintf(f, ",\n  \"runs\": [\n    {\n");
    fprintf(f, "      \"prog\": \"%s\", \"mode\": \"%s\", "
               "\"measure\": \"%s\",\n", prog_basename(o.prog_path),
            o.mode_str, o.measure);
    fprintf(f, "      \"threads\": %d, \"iters\": %llu, \"warmup\": %llu, "
               "\"fuel\": %lld,\n", nthr, (unsigned long long)o.iters,
            (unsigned long long)o.warmup, (long long)o.fuel);
    fprintf(f, "      \"nkeys\": %u, \"zipf_theta\": %.3f, "
               "\"pktlen_min\": %u, \"pktlen_max\": %u,\n",
            o.nkeys, o.zipf_theta, o.pktlen_min, o.pktlen_max);
    fprintf(f, "      \"shadow_diff\": %d, \"jit\": %d, "
               "\"jit_active\": %d, \"jit_code_bytes\": %llu,\n",
            o.no_shadow_diff ? 0 : 1, o.jit, ktx_prog_is_jitted(prog),
            (unsigned long long)ktx_prog_jit_bytes(prog));
    {   /* E7: bytes of runtime state, so a deployment can be sized. */
        uint64_t mb = 0, mm = 0, rb = 0;
        ktx_env_memory(env, &mb, &mm, &rb);
        fprintf(f, "      \"memory\": { \"thread_bytes\": %llu, "
                   "\"prog_bytes\": %llu, \"map_data_bytes\": %llu, "
                   "\"map_meta_bytes\": %llu, \"ring_bytes\": %llu, "
                   "\"threads\": %d, \"rss_bytes\": %llu, "
                   "\"hwm_arena_bytes\": %u, \"hwm_records\": %u, "
                   "\"hwm_readset\": %u },\n",
                (unsigned long long)ktx_thread_memory(),
                (unsigned long long)ktx_prog_memory(prog),
                (unsigned long long)mb, (unsigned long long)mm,
                (unsigned long long)rb, nthr,
                (unsigned long long)rss_bytes(),
                hwm_arena, hwm_recs, hwm_reads);
    }
    fprintf(f, "      \"elide\": %s%s%s,\n",
            o.elide_path ? "\"" : "", o.elide_path ? o.elide_path : "null",
            o.elide_path ? "\"" : "");
    if (err[0]) {
        fprintf(f, "      \"error\": \"");
        tr_json_escape(f, err);
        fprintf(f, "\"\n");
    } else if (is_latency) {
        fprintf(f, "      \"timed_region\": \"ktx_run_only\", "
                   "\"batch\": %u,\n", o.batch);
        fprintf(f, "      \"metrics\": {\n");
        fprintf(f, "        \"iters_timed\": %llu, \"batches\": %llu,\n",
                (unsigned long long)iters_timed,
                (unsigned long long)nbatches);
        fprintf(f, "        \"ns_min\": %.3f, \"ns_p50\": %.3f, "
                   "\"ns_p90\": %.3f, \"ns_p99\": %.3f, "
                   "\"ns_p999\": %.3f, \"ns_mean\": %.3f,\n",
                ns_min, p50, p90, p99, p999, ns_mean);
        fprintf(f, "        ");
        write_stats(f, &agg);
        fprintf(f, "\n      }\n");
    } else {
        fprintf(f, "      \"metrics\": {\n");
        fprintf(f, "        \"ops_total\": %llu, \"wall_s\": %.6f, "
                   "\"mops_per_s\": %.4f,\n",
                (unsigned long long)ops_total, wall_s, mops);
        fprintf(f, "        \"goodput_commits_per_s\": %.1f,\n",
                (wall_s > 0) ? (double)agg.commits / wall_s : 0.0);
        fprintf(f, "        \"per_thread_ops\": [");
        for (int t = 0; t < nthr; t++)
            fprintf(f, "%s%llu", t ? ", " : "",
                    (unsigned long long)(ws ? ws[t].ops : 0));
        fprintf(f, "],\n        ");
        write_stats(f, &agg);
        fprintf(f, "\n      }\n");
    }
    fprintf(f, "    }\n  ]\n}\n");
    fclose(f);
    free(ws);
    tr_zipf_free(&zipf);
    if (prog) ktx_prog_free(prog);
    if (env) ktx_env_destroy(env);
    if (err[0]) {
        fprintf(stderr, "ktxbench: ERROR: %s (recorded in %s)\n", err, o.out);
        return 1;
    }
    return 0;
}
