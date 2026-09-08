/* policy.c -> bin/ktxpolicy : E9, abort-induced policy bypass.
 *
 * Making aborts effect-free does not make them *free*.  An aborted
 * invocation still has to return something, and whatever it returns is
 * the attachment point's default verdict.  For a program whose verdict
 * IS the policy — a firewall, a rate limiter — an attacker who can raise
 * the abort rate can raise the rate at which their traffic receives the
 * default verdict instead of the decision the program would have made.
 *
 * This harness measures that.  A blocklisted attacker drives one of two
 * abort vectors against workloads/firewall.S:
 *
 *   conflict — many concurrent invocations on the same hot flow key, so
 *              their write-through counter updates collide at commit.
 *              This vector is *created by* the transactional contract.
 *   fuel     — oversized packets that push the length-driven header scan
 *              past the fuel budget.  This vector exists for any design
 *              with runtime termination (KFlex-style cancellation
 *              included), transactional or not.
 *
 * and we report, per execution mode and per policy:
 *   bypass_rate      attacker packets that received PASS (should be 0)
 *   false_drop_rate  legitimate packets that received DROP (the cost of
 *                    a fail-closed default)
 */
#include <errno.h>
#include <inttypes.h>
#include <mach/mach_time.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ktx.h"
#include "ktx_format.h"
#include "trace.h"

#define PKT_CAP 2048u
#define ERRLEN 512

typedef struct {
    const char *prog_path, *elide_path, *mode_str, *vector, *policy_str,
               *out;
    ktx_mode mode;
    int attackers, legit;
    uint64_t ops, seed;
    uint32_t attack_keys, legit_keys;
    uint32_t atk_len_min, atk_len_max, leg_len_min, leg_len_max;
    int64_t fuel;
    uint32_t retries, attacker_retries, legit_retries;
    uint64_t default_verdict;
    int jit;
} opts_t;

typedef struct {
    pthread_mutex_t m; pthread_cond_t c; int count, total, gen;
} bar_t;
static void bar_init(bar_t *b, int total) {
    pthread_mutex_init(&b->m, NULL); pthread_cond_init(&b->c, NULL);
    b->count = 0; b->total = total; b->gen = 0;
}
static void bar_wait(bar_t *b) {
    pthread_mutex_lock(&b->m);
    int g = b->gen;
    if (++b->count == b->total) { b->count = 0; b->gen++;
                                  pthread_cond_broadcast(&b->c); }
    else while (g == b->gen) pthread_cond_wait(&b->c, &b->m);
    pthread_mutex_unlock(&b->m);
}

typedef struct {
    const opts_t *o;
    ktx_env *env; ktx_prog *prog; bar_t *bar;
    int tid, attacker;
    /* out */
    uint64_t ops, v_pass, v_drop, v_other;
    double elapsed_ns;
    ktx_thread_stats stats;
} worker_t;

static void *thr_main(void *arg) {
    worker_t *w = (worker_t *)arg;
    tr_qos_perf();
    const opts_t *o = w->o;
    uint8_t *pkt = malloc(PKT_CAP);
    ktx_thread *th = ktx_thread_create(w->env, w->tid);
    uint64_t prng = tr_thread_seed(o->seed, w->tid);
    ktx_policy pol = { o->default_verdict,
                       w->attacker ? o->attacker_retries : o->legit_retries };
    uint32_t lmin = w->attacker ? o->atk_len_min : o->leg_len_min;
    uint32_t lmax = w->attacker ? o->atk_len_max : o->leg_len_max;

    /* warm the maps so steady-state behaviour is measured */
    for (int i = 0; i < 1000; i++) {
        uint32_t fid = w->attacker
            ? (uint32_t)(tr_xorshift64s(&prng) % o->attack_keys)
            : (uint32_t)(1000000 + tr_xorshift64s(&prng) % o->legit_keys);
        uint32_t len = tr_fill_packet(pkt, PKT_CAP, fid, &prng, lmin, lmax);
        (void)ktx_run_ex(th, w->prog, o->mode, pkt, len, o->fuel, &pol);
    }
    ktx_thread_stats_reset(th);
    bar_wait(w->bar);
    uint64_t t0 = mach_absolute_time();

    for (uint64_t i = 0; i < o->ops; i++) {
        uint32_t fid = w->attacker
            ? (uint32_t)(tr_xorshift64s(&prng) % o->attack_keys)
            : (uint32_t)(1000000 + tr_xorshift64s(&prng) % o->legit_keys);
        uint32_t len = tr_fill_packet(pkt, PKT_CAP, fid, &prng, lmin, lmax);
        ktx_result r = ktx_run_ex(th, w->prog, o->mode, pkt, len, o->fuel,
                                  &pol);
        w->ops++;
        if (r.verdict == KTX_VERDICT_PASS) w->v_pass++;
        else if (r.verdict == KTX_VERDICT_DROP) w->v_drop++;
        else w->v_other++;
    }
    uint64_t t1 = mach_absolute_time();
    mach_timebase_info_data_t tb; mach_timebase_info(&tb);
    w->elapsed_ns = (double)(t1 - t0) * (double)tb.numer / (double)tb.denom;
    bar_wait(w->bar);
    ktx_thread_stats_get(th, &w->stats);
    ktx_thread_destroy(th);
    free(pkt);
    return NULL;
}

static void usage(void) {
    fprintf(stderr,
      "usage: ktxpolicy --prog F.kbin [--elide F.elide] "
      "--mode sfi|tx|tx-elide|2pl|p2pl\n"
      "  --vector conflict|fuel  [--attackers A] [--legit L] [--ops N]\n"
      "  [--attack-keys K] [--legit-keys K] [--fuel F] [--retries R]\n"
      "  [--attacker-retries R] [--legit-retries R]\n"
      "  [--default pass|drop] [--seed S] --out FILE.json\n");
}

int main(int argc, char **argv) {
    tr_qos_perf();
    opts_t o = { .prog_path = NULL, .elide_path = NULL, .mode_str = NULL,
                 .vector = "conflict", .policy_str = "pass", .out = NULL,
                 .mode = KTX_MODE_TX, .attackers = 4, .legit = 4,
                 .ops = 200000, .seed = 42, .attack_keys = 1,
                 .legit_keys = 1024, .atk_len_min = 64, .atk_len_max = 64,
                 .leg_len_min = 64, .leg_len_max = 64, .fuel = 65536,
                 .retries = 0, .attacker_retries = 0, .legit_retries = 0,
                 .default_verdict = KTX_VERDICT_PASS };
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        const char *v = (i + 1 < argc) ? argv[i + 1] : NULL;
#define ARG(n) (strcmp(a, n) == 0 && v && ++i)
        if (ARG("--prog")) o.prog_path = v;
        else if (ARG("--elide")) o.elide_path = v;
        else if (ARG("--mode")) o.mode_str = v;
        else if (ARG("--vector")) o.vector = v;
        else if (ARG("--attackers")) o.attackers = atoi(v);
        else if (ARG("--legit")) o.legit = atoi(v);
        else if (ARG("--ops")) o.ops = strtoull(v, NULL, 0);
        else if (ARG("--attack-keys")) o.attack_keys = (uint32_t)atoi(v);
        else if (ARG("--legit-keys")) o.legit_keys = (uint32_t)atoi(v);
        else if (ARG("--fuel")) o.fuel = strtoll(v, NULL, 0);
        else if (ARG("--retries")) {
            o.retries = (uint32_t)atoi(v);
            o.attacker_retries = o.legit_retries = o.retries;
        }
        else if (ARG("--attacker-retries"))
            o.attacker_retries = (uint32_t)atoi(v);
        else if (ARG("--legit-retries"))
            o.legit_retries = (uint32_t)atoi(v);
        else if (ARG("--default")) o.policy_str = v;
        else if (ARG("--seed")) o.seed = strtoull(v, NULL, 0);
        else if (ARG("--out")) o.out = v;
        else if (strcmp(a, "--jit") == 0) { o.jit = 1; continue; }
        else { usage(); fprintf(stderr, "bad arg: %s\n", a); return 2; }
#undef ARG
    }
    if (!o.prog_path || !o.mode_str || !o.out) { usage(); return 2; }
    if (strcmp(o.mode_str, "vanilla") == 0) o.mode = KTX_MODE_VANILLA;
    else if (strcmp(o.mode_str, "sfi") == 0) o.mode = KTX_MODE_SFI;
    else if (strcmp(o.mode_str, "tx") == 0) o.mode = KTX_MODE_TX;
    else if (strcmp(o.mode_str, "tx-elide") == 0) o.mode = KTX_MODE_TX_ELIDE;
    else if (strcmp(o.mode_str, "2pl") == 0) o.mode = KTX_MODE_2PL;
    else if (strcmp(o.mode_str, "p2pl") == 0) o.mode = KTX_MODE_P2PL;
    else { usage(); return 2; }
    if (strcmp(o.policy_str, "drop") == 0) o.default_verdict = KTX_VERDICT_DROP;
    /* the fuel vector: long attacker packets against a tight budget */
    if (strcmp(o.vector, "fuel") == 0) {
        o.atk_len_min = o.atk_len_max = 256;
        o.attack_keys = o.attack_keys > 1 ? o.attack_keys : 1024;
    }

    char err[ERRLEN] = {0};
    int nthr = o.attackers + o.legit;
    ktx_env *env = ktx_env_create(nthr);
    if (!env) { fprintf(stderr, "env create failed\n"); return 1; }
    if (o.jit) ktx_env_set_opt(env, KTX_OPT_JIT, 1);
    ktx_prog *prog = ktx_prog_load(env, o.prog_path, o.elide_path, err,
                                   ERRLEN);
    if (!prog) { fprintf(stderr, "load: %s\n", err); return 1; }
    int bl = ktx_map_id(env, "blocklist");
    if (bl < 0) { fprintf(stderr, "no blocklist map\n"); return 1; }
    for (uint32_t k = 0; k < o.attack_keys; k++) {
        uint64_t key = tr_flow_key(k), one = 1;
        ktx_map_update(env, bl, &key, &one);
    }

    bar_t bar; bar_init(&bar, nthr);
    worker_t *ws = calloc(nthr, sizeof(*ws));
    pthread_t *th = calloc(nthr, sizeof(*th));
    for (int i = 0; i < nthr; i++) {
        ws[i] = (worker_t){ .o = &o, .env = env, .prog = prog, .bar = &bar,
                            .tid = i, .attacker = (i < o.attackers) };
        pthread_create(&th[i], NULL, thr_main, &ws[i]);
    }
    for (int i = 0; i < nthr; i++) pthread_join(th[i], NULL);

    uint64_t a_ops = 0, a_pass = 0, a_drop = 0, l_ops = 0, l_pass = 0,
             l_drop = 0;
    ktx_thread_stats agg; memset(&agg, 0, sizeof agg);
    double elapsed_max_ns = 0.0, legit_min_kops = 0.0, legit_max_kops = 0.0;
    double legit_rate_sum = 0.0, legit_rate_sq = 0.0;
    for (int i = 0; i < nthr; i++) {
        if (ws[i].attacker) { a_ops += ws[i].ops; a_pass += ws[i].v_pass;
                              a_drop += ws[i].v_drop; }
        else { l_ops += ws[i].ops; l_pass += ws[i].v_pass;
               l_drop += ws[i].v_drop; }
        agg.commits += ws[i].stats.commits;
        agg.aborts_guard += ws[i].stats.aborts_guard;
        agg.aborts_fuel += ws[i].stats.aborts_fuel;
        agg.aborts_helper += ws[i].stats.aborts_helper;
        agg.aborts_conflict += ws[i].stats.aborts_conflict;
        agg.aborts_capacity += ws[i].stats.aborts_capacity;
        agg.aborts_deadlock += ws[i].stats.aborts_deadlock;
        agg.retries += ws[i].stats.retries;
        if (ws[i].elapsed_ns > elapsed_max_ns) elapsed_max_ns = ws[i].elapsed_ns;
        if (!ws[i].attacker) {
            double rate = ws[i].elapsed_ns > 0.0
                ? (double)ws[i].ops * 1e6 / ws[i].elapsed_ns : 0.0;
            if (legit_min_kops == 0.0 || rate < legit_min_kops) legit_min_kops = rate;
            if (rate > legit_max_kops) legit_max_kops = rate;
            legit_rate_sum += rate; legit_rate_sq += rate * rate;
        }
    }
    uint64_t aborts = agg.aborts_guard + agg.aborts_fuel + agg.aborts_helper +
        agg.aborts_conflict + agg.aborts_capacity + agg.aborts_deadlock;
    uint64_t external_ops = a_ops + l_ops;
    double jain = (o.legit > 0 && legit_rate_sq > 0.0)
        ? (legit_rate_sum * legit_rate_sum) / ((double)o.legit * legit_rate_sq)
        : 0.0;
    FILE *f = fopen(o.out, "w");
    if (!f) { perror("fopen"); return 1; }
    fprintf(f, "{\n  \"experiment\": \"e9_policy_bypass\",\n  ");
    tr_write_meta(f, o.seed, argc, argv, -1);
    fprintf(f, ",\n  \"runs\": [\n    {\n");
    fprintf(f, "      \"prog\": \"%s\", \"mode\": \"%s\", \"vector\": \"%s\",\n",
            o.prog_path, o.mode_str, o.vector);
    fprintf(f, "      \"default_verdict\": \"%s\", \"retries\": %u, "
               "\"attacker_retries\": %u, \"legit_retries\": %u,\n",
            o.default_verdict == KTX_VERDICT_DROP ? "drop" : "pass",
            o.retries, o.attacker_retries, o.legit_retries);
    fprintf(f, "      \"attackers\": %d, \"legit\": %d, \"ops_per_thread\": "
               "%" PRIu64 ", \"attack_keys\": %u, \"legit_keys\": %u, "
               "\"fuel\": %" PRId64 ",\n",
            o.attackers, o.legit, o.ops, o.attack_keys, o.legit_keys, o.fuel);
    fprintf(f, "      \"jit\": %d, \"jit_active\": %d,\n", o.jit,
            ktx_prog_is_jitted(prog));
    fprintf(f, "      \"metrics\": {\n");
    fprintf(f, "        \"attacker_ops\": %" PRIu64 ", \"attacker_pass\": %"
               PRIu64 ", \"attacker_drop\": %" PRIu64 ",\n",
            a_ops, a_pass, a_drop);
    fprintf(f, "        \"legit_ops\": %" PRIu64 ", \"legit_pass\": %" PRIu64
               ", \"legit_drop\": %" PRIu64 ",\n", l_ops, l_pass, l_drop);
    fprintf(f, "        \"bypass_rate\": %.6f, \"false_drop_rate\": %.6f,\n",
            a_ops ? (double)a_pass / (double)a_ops : 0.0,
            l_ops ? (double)l_drop / (double)l_ops : 0.0);
    fprintf(f, "        \"elapsed_ms\": %.6f, \"aggregate_kops_s\": %.6f,\n"
               "        \"attempts_per_invocation\": %.6f, "
               "\"abort_fraction_of_attempts\": %.6f,\n"
               "        \"legit_thread_kops_min\": %.6f, "
               "\"legit_thread_kops_max\": %.6f, \"legit_jain_fairness\": %.6f,\n",
            elapsed_max_ns / 1e6,
            elapsed_max_ns > 0.0 ? (double)external_ops * 1e6 / elapsed_max_ns : 0.0,
            external_ops ? (double)(agg.commits + aborts) / (double)external_ops : 0.0,
            (agg.commits + aborts) ? (double)aborts / (double)(agg.commits + aborts) : 0.0,
            legit_min_kops, legit_max_kops, jain);
    fprintf(f, "        \"commits\": %" PRIu64 ", \"aborts_guard\": %" PRIu64
               ", \"aborts_fuel\": %" PRIu64 ", \"aborts_helper\": %" PRIu64
               ",\n        \"aborts_conflict\": %" PRIu64
               ", \"aborts_capacity\": %" PRIu64 ", \"aborts_deadlock\": %"
               PRIu64 ", \"retries\": %" PRIu64 "\n",
            agg.commits, agg.aborts_guard, agg.aborts_fuel, agg.aborts_helper,
            agg.aborts_conflict, agg.aborts_capacity, agg.aborts_deadlock,
            agg.retries);
    fprintf(f, "      }\n    }\n  ]\n}\n");
    fclose(f);
    fprintf(stderr, "ktxpolicy: mode=%s vector=%s default=%s retries=%u "
                    "bypass=%.4f%% false_drop=%.4f%%\n",
            o.mode_str, o.vector, o.policy_str, o.retries,
            100.0 * (a_ops ? (double)a_pass / (double)a_ops : 0.0),
            100.0 * (l_ops ? (double)l_drop / (double)l_ops : 0.0));
    free(ws); free(th);
    ktx_prog_free(prog);
    ktx_env_destroy(env);
    return 0;
}
