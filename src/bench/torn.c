/* torn.c -> bin/ktxtorn : E3 torn-update study. DESIGN.md section 8.2.
 *
 * E3a (readers > 0, no fuel window): writers each perform --ops-per-writer
 * SUCCESSFUL writer-program invocations (conflict aborts retry the same
 * packet and are counted as writer_retries); concurrent readers run the
 * invariant-checker program; a reader invocation that COMMITS with verdict
 * DROP(1) is one observed cross-map violation. Reader conflict aborts are
 * prevented torn reads, counted separately.
 *
 * E3b (readers == 0, fuel window given): each writer invocation draws fuel
 * uniform in [fuel-lo, fuel-hi]; no retries. Afterwards the harness
 * quiesces and scans shared state with ktx_map_iter / ktx_map_lookup for
 * keys violating the pair invariant (torn_keys).
 *
 * Honesty: metrics come from this run only; failures land in "error".
 */
#include <errno.h>
#include <inttypes.h>
#include <mach/mach_time.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ktx.h"
#include "ktx_format.h"
#include "trace.h"

#define PKT_CAP 2048u
#define ERRLEN 512
#define DEFAULT_FUEL 65536

typedef struct {
    const char *pair, *mode_str, *dir, *out;
    int jit;
    ktx_mode mode;
    int writers, readers;
    uint64_t ops_per_writer;
    uint64_t seed;
    uint32_t nkeys;
    int64_t fuel_lo, fuel_hi; /* -1 = unset */
} opts_t;

typedef struct {
    pthread_mutex_t m;
    pthread_cond_t c;
    int count, total, gen;
} bar_t;

static void bar_init(bar_t *b, int total) {
    pthread_mutex_init(&b->m, NULL);
    pthread_cond_init(&b->c, NULL);
    b->count = 0; b->total = total; b->gen = 0;
}

static void bar_wait(bar_t *b) {
    pthread_mutex_lock(&b->m);
    int g = b->gen;
    if (++b->count == b->total) {
        b->count = 0; b->gen++;
        pthread_cond_broadcast(&b->c);
    } else {
        while (g == b->gen) pthread_cond_wait(&b->c, &b->m);
    }
    pthread_mutex_unlock(&b->m);
}

typedef struct {
    const opts_t *o;
    ktx_env *env;
    ktx_prog *prog;      /* writer or reader program */
    bar_t *bar;
    _Atomic int *writers_left;
    int tid;             /* env thread index */
    int is_writer;
    /* out */
    uint64_t start_tick, end_tick;
    uint64_t successes, attempts, retries, other_aborts;   /* writer */
    uint64_t commits, violations, conflicts;               /* reader */
    uint64_t aborts_fuel;                                  /* E3b writer */
    int failed;
    char err[ERRLEN];
} twork_t;

static void *torn_thread(void *arg) {
    tr_qos_perf();
    twork_t *w = (twork_t *)arg;
    const opts_t *o = w->o;
    uint8_t *pkt = malloc(PKT_CAP);
    ktx_thread *th = ktx_thread_create(w->env, w->tid);
    if (!th || !pkt) {
        snprintf(w->err, ERRLEN, "thread %d setup failed", w->tid);
        w->failed = 1;
        bar_wait(w->bar);
        if (w->is_writer) atomic_fetch_sub(w->writers_left, 1);
        free(pkt);
        if (th) ktx_thread_destroy(th);
        return NULL;
    }
    uint64_t prng = tr_thread_seed(o->seed, w->tid);
    int fuel_window = (o->fuel_lo >= 0 && o->fuel_hi >= o->fuel_lo);
    bar_wait(w->bar);
    w->start_tick = mach_absolute_time();

    if (w->is_writer) {
        uint64_t max_attempts = o->ops_per_writer * 100 + 1000;
        while (w->successes < o->ops_per_writer) {
            uint32_t fid = (uint32_t)(tr_xorshift64s(&prng) % o->nkeys);
            uint32_t len = tr_fill_packet(pkt, PKT_CAP, fid, &prng, 64, 256);
            int64_t fuel = DEFAULT_FUEL;
            if (fuel_window)
                fuel = o->fuel_lo + (int64_t)(tr_xorshift64s(&prng) %
                        (uint64_t)(o->fuel_hi - o->fuel_lo + 1));
            for (;;) {
                w->attempts++;
                ktx_result r = ktx_run(th, w->prog, o->mode, pkt, len, fuel);
                if (r.status == KTX_OK) {
                    w->successes++;
                    break;
                }
                if (r.status == KTX_ABORT_FUEL) w->aborts_fuel++;
                if (fuel_window) {
                    /* E3b: no retries; the abort IS the experiment.
                     * Non-fuel aborts (OCC conflicts between writers in tx
                     * mode) are counted so attempts == commits +
                     * aborts_fuel + aborts_other holds. */
                    if (r.status != KTX_ABORT_FUEL) w->other_aborts++;
                    break;
                }
                if (r.status == KTX_ABORT_CONFLICT) {
                    w->retries++;      /* retry the same packet (E3a) */
                    continue;
                }
                w->other_aborts++;     /* unexpected: count, move on */
                break;
            }
            if (fuel_window && w->attempts >= o->ops_per_writer)
                break;                 /* E3b: attempts, not successes */
            if (w->attempts > max_attempts) {
                snprintf(w->err, ERRLEN,
                         "writer %d live-locked (%llu attempts)", w->tid,
                         (unsigned long long)w->attempts);
                w->failed = 1;
                break;
            }
        }
        w->end_tick = mach_absolute_time();
        atomic_fetch_sub(w->writers_left, 1);
    } else {
        while (atomic_load(w->writers_left) > 0) {
            uint32_t fid = (uint32_t)(tr_xorshift64s(&prng) % o->nkeys);
            uint32_t len = tr_fill_packet(pkt, PKT_CAP, fid, &prng, 64, 256);
            ktx_result r = ktx_run(th, w->prog, o->mode, pkt, len,
                                   DEFAULT_FUEL);
            if (r.status == KTX_OK) {
                w->commits++;
                if (r.verdict == 1) w->violations++;
            } else if (r.status == KTX_ABORT_CONFLICT) {
                w->conflicts++;
            } else {
                w->other_aborts++;
            }
        }
        w->end_tick = mach_absolute_time();
    }
    ktx_thread_destroy(th);
    free(pkt);
    return NULL;
}

static void init_named_maps(ktx_env *env) {
    int a = ktx_map_id(env, "acct_a"), b = ktx_map_id(env, "acct_b");
    if (a >= 0 && b >= 0) {
        for (uint32_t k = 0; k < 256; k++) {
            uint64_t va = 1000, vb = 0;
            ktx_map_update(env, a, &k, &va);
            ktx_map_update(env, b, &k, &vb);
        }
    }
}

/* post-run quiesced invariant scans (E3b) --------------------------------- */
static int scan_ctnat(ktx_env *env, uint64_t *torn, uint64_t *scanned,
                      char *err) {
    int ct = ktx_map_id(env, "conntrack"), nat = ktx_map_id(env, "nat");
    if (ct < 0 || nat < 0) {
        snprintf(err, ERRLEN, "conntrack/nat maps not found for scan");
        return -1;
    }
    uint8_t key[8], v1[16], v2[16];
    uint32_t iter = 0;
    *torn = 0; *scanned = 0;
    while (ktx_map_iter(env, ct, &iter, key, v1) == 0) {
        (*scanned)++;
        if (ktx_map_lookup(env, nat, key, v2) != 0) (*torn)++;
        else if (memcmp(v1 + 4, v2 + 4, 4) != 0) (*torn)++;  /* gen fields */
    }
    iter = 0;
    while (ktx_map_iter(env, nat, &iter, key, v2) == 0) {
        if (ktx_map_lookup(env, ct, key, v1) != 0) { (*torn)++; (*scanned)++; }
    }
    return 0;
}

static int scan_atomic(ktx_env *env, uint64_t *torn, uint64_t *scanned,
                       char *err) {
    int a = ktx_map_id(env, "acct_a"), b = ktx_map_id(env, "acct_b");
    if (a < 0 || b < 0) {
        snprintf(err, ERRLEN, "acct_a/acct_b maps not found for scan");
        return -1;
    }
    *torn = 0; *scanned = 0;
    for (uint32_t k = 0; k < 256; k++) {
        uint64_t va = 0, vb = 0;
        if (ktx_map_lookup(env, a, &k, &va) != 0 ||
            ktx_map_lookup(env, b, &k, &vb) != 0) {
            (*torn)++;
        } else if (va + vb != 1000) {
            (*torn)++;
        }
        (*scanned)++;
    }
    return 0;
}

static void usage(void) {
    fprintf(stderr,
        "usage: ktxtorn --pair ctnat|atomic --mode vanilla|sfi|tx|tx-elide|2pl|p2pl\n"
        "  --writers N --readers N --ops-per-writer M [--seed S] [--nkeys K]\n"
        "  [--fuel-lo X --fuel-hi Y] [--workloads-dir D] --out FILE.json\n");
}

int main(int argc, char **argv) {
    tr_qos_perf();
    opts_t o = { .pair = NULL, .mode_str = NULL, .dir = "workloads",
                 .out = NULL, .mode = KTX_MODE_VANILLA, .writers = 4,
                 .readers = 2, .ops_per_writer = 1000000, .seed = 42,
                 .nkeys = 512, .fuel_lo = -1, .fuel_hi = -1 };
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        const char *v = (i + 1 < argc) ? argv[i + 1] : NULL;
#define ARG(name) (strcmp(a, name) == 0 && v && ++i)
        if (ARG("--pair")) o.pair = v;
        else if (ARG("--mode")) o.mode_str = v;
        else if (ARG("--writers")) o.writers = atoi(v);
        else if (ARG("--readers")) o.readers = atoi(v);
        else if (ARG("--ops-per-writer")) o.ops_per_writer = strtoull(v, NULL, 0);
        else if (ARG("--seed")) o.seed = strtoull(v, NULL, 0);
        else if (ARG("--nkeys")) o.nkeys = (uint32_t)strtoul(v, NULL, 0);
        else if (ARG("--fuel-lo")) o.fuel_lo = strtoll(v, NULL, 0);
        else if (ARG("--fuel-hi")) o.fuel_hi = strtoll(v, NULL, 0);
        else if (ARG("--workloads-dir")) o.dir = v;
        else if (ARG("--out")) o.out = v;
        else if (strcmp(a, "--jit") == 0) { o.jit = 1; continue; }
        else { usage(); fprintf(stderr, "bad arg: %s\n", a); return 2; }
#undef ARG
    }
    if (!o.pair || !o.mode_str || !o.out) { usage(); return 2; }
    if (strcmp(o.mode_str, "vanilla") == 0) o.mode = KTX_MODE_VANILLA;
    else if (strcmp(o.mode_str, "sfi") == 0) o.mode = KTX_MODE_SFI;
    else if (strcmp(o.mode_str, "tx") == 0) o.mode = KTX_MODE_TX;
    else if (strcmp(o.mode_str, "tx-elide") == 0) o.mode = KTX_MODE_TX_ELIDE;
    else if (strcmp(o.mode_str, "2pl") == 0) o.mode = KTX_MODE_2PL;
    else if (strcmp(o.mode_str, "p2pl") == 0) o.mode = KTX_MODE_P2PL;
    else { usage(); return 2; }

    const char *wname, *rname;
    if (strcmp(o.pair, "ctnat") == 0) {
        wname = "ctnat"; rname = "ctnat_reader";
    } else if (strcmp(o.pair, "atomic") == 0) {
        wname = "atomic_demo"; rname = "atomic_reader";
    } else { usage(); return 2; }

    int fuel_window = (o.fuel_lo >= 0 && o.fuel_hi >= o.fuel_lo);
    char err[ERRLEN] = "";
    ktx_env *env = NULL;
    ktx_prog *wprog = NULL, *rprog = NULL;
    twork_t *ws = NULL;
    int nthr = o.writers + o.readers;
    const char *sub = fuel_window ? "e3b" : "e3a";

    /* aggregated metrics */
    uint64_t writer_ops = 0, writer_retries = 0, writer_attempts = 0;
    uint64_t writer_other = 0, writer_aborts_fuel = 0;
    uint64_t reader_commits = 0, violations = 0, reader_conflicts = 0;
    uint64_t reader_other = 0, torn_keys = 0, scanned_keys = 0;
    double wall_s = 0;

    if (o.writers < 1 || o.readers < 0 || nthr > 64) {
        snprintf(err, ERRLEN, "bad writers/readers (%d/%d)", o.writers,
                 o.readers);
        goto out;
    }
    if (fuel_window && o.readers != 0) {
        snprintf(err, ERRLEN,
                 "E3b (fuel window) requires --readers 0");
        goto out;
    }
    if (!fuel_window && o.readers == 0) {
        snprintf(err, ERRLEN,
                 "E3a requires readers > 0 (or pass a fuel window for E3b)");
        goto out;
    }

    char wkbin[1024], rkbin[1024], welide[1024], relide[1024];
    snprintf(wkbin, sizeof wkbin, "%s/%s.kbin", o.dir, wname);
    snprintf(rkbin, sizeof rkbin, "%s/%s.kbin", o.dir, rname);
    snprintf(welide, sizeof welide, "%s/%s.elide", o.dir, wname);
    snprintf(relide, sizeof relide, "%s/%s.elide", o.dir, rname);
    const char *wel = (access(welide, R_OK) == 0) ? welide : NULL;
    const char *rel = (access(relide, R_OK) == 0) ? relide : NULL;

    env = ktx_env_create(nthr);
    if (!env) { snprintf(err, ERRLEN, "ktx_env_create failed"); goto out; }
    if (o.jit) ktx_env_set_opt(env, KTX_OPT_JIT, 1);
    wprog = ktx_prog_load(env, wkbin, wel, err, ERRLEN);
    if (!wprog) {
        if (!err[0]) snprintf(err, ERRLEN, "load %s failed", wkbin);
        goto out;
    }
    rprog = ktx_prog_load(env, rkbin, rel, err, ERRLEN);
    if (!rprog) {
        if (!err[0]) snprintf(err, ERRLEN, "load %s failed", rkbin);
        goto out;
    }
    init_named_maps(env);

    ws = calloc((size_t)nthr, sizeof(twork_t));
    pthread_t *tids = calloc((size_t)nthr, sizeof(pthread_t));
    _Atomic int writers_left = o.writers;
    bar_t bar;
    if (!ws || !tids) {
        snprintf(err, ERRLEN, "alloc failed");
        free(tids);
        goto out;
    }
    bar_init(&bar, nthr);
    (void)tr_timebase();
    for (int t = 0; t < nthr; t++) {
        ws[t] = (twork_t){ .o = &o, .env = env, .bar = &bar,
                           .writers_left = &writers_left, .tid = t,
                           .is_writer = (t < o.writers),
                           .prog = (t < o.writers) ? wprog : rprog };
        if (pthread_create(&tids[t], NULL, torn_thread, &ws[t]) != 0) {
            fprintf(stderr, "ktxtorn: pthread_create failed\n");
            exit(1);
        }
    }
    for (int t = 0; t < nthr; t++) pthread_join(tids[t], NULL);
    free(tids);

    uint64_t min_start = UINT64_MAX, max_end = 0;
    for (int t = 0; t < nthr; t++) {
        if (ws[t].failed && !err[0]) snprintf(err, ERRLEN, "%s", ws[t].err);
        if (ws[t].is_writer) {
            writer_ops += ws[t].successes;
            writer_retries += ws[t].retries;
            writer_attempts += ws[t].attempts;
            writer_other += ws[t].other_aborts;
            writer_aborts_fuel += ws[t].aborts_fuel;
            if (ws[t].start_tick < min_start) min_start = ws[t].start_tick;
            if (ws[t].end_tick > max_end) max_end = ws[t].end_tick;
        } else {
            reader_commits += ws[t].commits;
            violations += ws[t].violations;
            reader_conflicts += ws[t].conflicts;
            reader_other += ws[t].other_aborts;
        }
    }
    if (err[0]) goto out;
    wall_s = tr_ticks_to_ns(max_end - min_start) / 1e9;

    {   /* Quiesced post-run scan.  E3b needs it (that is the whole
         * experiment); E3a reports it too, because a design whose aborts
         * do not roll back can leave the *final* state torn even with no
         * fuel injection at all — 2PL's deadlock aborts do exactly that. */
        if (ktx_env_quiesce_begin(env) != 0) {
            snprintf(err, ERRLEN, "could not acquire post-run quiescence");
            goto out;
        }
        int rc = (strcmp(o.pair, "ctnat") == 0)
                 ? scan_ctnat(env, &torn_keys, &scanned_keys, err)
                 : scan_atomic(env, &torn_keys, &scanned_keys, err);
        ktx_env_quiesce_end(env);
        if (rc != 0) goto out;
    }

out:;
    FILE *f = fopen(o.out, "w");
    if (!f) {
        fprintf(stderr, "ktxtorn: cannot open %s: %s\n", o.out,
                strerror(errno));
        return 1;
    }
    fprintf(f, "{\n  \"experiment\": \"e3_torn\",\n  ");
    tr_write_meta(f, o.seed, argc, argv, -1);
    fprintf(f, ",\n  \"runs\": [\n    {\n");
    fprintf(f, "      \"sub_experiment\": \"%s\", \"pair\": \"%s\", "
               "\"mode\": \"%s\",\n", sub, o.pair, o.mode_str);
    fprintf(f, "      \"writers\": %d, \"readers\": %d, "
               "\"ops_per_writer\": %llu, \"nkeys\": %u, \"seed\": %llu,\n",
            o.writers, o.readers, (unsigned long long)o.ops_per_writer,
            o.nkeys, (unsigned long long)o.seed);
    if (fuel_window)
        fprintf(f, "      \"fuel_lo\": %lld, \"fuel_hi\": %lld,\n",
                (long long)o.fuel_lo, (long long)o.fuel_hi);
    else
        fprintf(f, "      \"fuel_lo\": null, \"fuel_hi\": null, "
                   "\"fuel\": %d,\n", DEFAULT_FUEL);
    if (err[0]) {
        fprintf(f, "      \"error\": \"");
        tr_json_escape(f, err);
        fprintf(f, "\"\n");
    } else {
        fprintf(f, "      \"metrics\": {\n");
        fprintf(f, "        \"wall_s\": %.6f,\n", wall_s);
        if (fuel_window) {
            fprintf(f, "        \"attempts\": %llu, \"commits\": %llu, "
                       "\"aborts_fuel\": %llu, \"aborts_other\": %llu,\n",
                    (unsigned long long)writer_attempts,
                    (unsigned long long)writer_ops,
                    (unsigned long long)writer_aborts_fuel,
                    (unsigned long long)writer_other);
            fprintf(f, "        \"abort_fraction\": %.6f,\n",
                    writer_attempts ? (double)(writer_attempts - writer_ops) /
                                      (double)writer_attempts : 0.0);
            fprintf(f, "        \"torn_keys\": %llu, "
                       "\"scanned_keys\": %llu\n",
                    (unsigned long long)torn_keys,
                    (unsigned long long)scanned_keys);
        } else {
            fprintf(f, "        \"writer_ops\": %llu, "
                       "\"writer_attempts\": %llu, "
                       "\"writer_retries\": %llu, "
                       "\"writer_other_aborts\": %llu,\n",
                    (unsigned long long)writer_ops,
                    (unsigned long long)writer_attempts,
                    (unsigned long long)writer_retries,
                    (unsigned long long)writer_other);
            fprintf(f, "        \"reader_commits\": %llu, "
                       "\"violations\": %llu, "
                       "\"reader_conflicts\": %llu, "
                       "\"reader_other_aborts\": %llu,\n",
                    (unsigned long long)reader_commits,
                    (unsigned long long)violations,
                    (unsigned long long)reader_conflicts,
                    (unsigned long long)reader_other);
            fprintf(f, "        \"final_torn_keys\": %llu, "
                       "\"final_scanned_keys\": %llu\n",
                    (unsigned long long)torn_keys,
                    (unsigned long long)scanned_keys);
        }
        fprintf(f, "      }\n");
    }
    fprintf(f, "    }\n  ]\n}\n");
    fclose(f);
    free(ws);
    if (rprog) ktx_prog_free(rprog);
    if (wprog) ktx_prog_free(wprog);
    if (env) ktx_env_destroy(env);
    if (err[0]) {
        fprintf(stderr, "ktxtorn: ERROR: %s (recorded in %s)\n", err, o.out);
        return 1;
    }
    return 0;
}
