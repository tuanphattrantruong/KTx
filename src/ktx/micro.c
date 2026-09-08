/* micro.c — bin/ktxmicro: E2 commit/abort/append microbenchmark
 * (DESIGN §8.3).  Uses the internal tx API directly (no bytecode):
 * one hash map 4096 (key 8 B, value 16 B); for each log size
 * k in {1,2,4,8,16,32,64,128,256} and op in {commit, abort, append},
 * 200k reps timed in batches of 32 with mach_absolute_time.
 *
 * Steady-state choice (documented in the JSON notes field): the 256
 * distinct keys are PRE-POPULATED once before timing, so every commit
 * apply phase overwrites existing nodes — no free-list churn inside the
 * timed region, and the map content is identical across reps.
 *
 * Timed-rep composition (also in notes): every rep includes
 * ktx_tx_begin + k ktx_tx_update appends; op=commit adds ktx_tx_commit,
 * op=abort adds ktx_tx_abort_reset, op=append adds nothing (the next
 * rep's begin is the O(1) reset).  Commit-only / abort-only costs are
 * derived downstream as (commit - append) / (abort - append).
 *
 * HONESTY: every metric written comes from the run that wrote the file;
 * failures are recorded as "error" fields.
 */
#include <errno.h>
#include <mach/mach_time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <time.h>

#include "ktx_internal.h"

#define DEFAULT_REPS   200000
#define DEFAULT_WARMUP 2000
#define BATCH          32
#define MAX_K          256
#define N_KS           9

static const int ks[N_KS] = { 1, 2, 4, 8, 16, 32, 64, 128, 256 };
static const char *ops[3] = { "commit", "abort", "append" };

static int cmp_double(const void *a, const void *b) {
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}

/* mkdir -p for the directory part of a path. */
static void mkpath_for(const char *path) {
    char buf[1024];
    snprintf(buf, sizeof(buf), "%s", path);
    char *slash = strrchr(buf, '/');
    if (!slash) return;
    *slash = 0;
    char partial[1024];
    partial[0] = 0;
    char *save = NULL;
    int absolute = (buf[0] == '/');
    for (char *tok = strtok_r(buf, "/", &save); tok;
         tok = strtok_r(NULL, "/", &save)) {
        size_t len = strlen(partial);
        snprintf(partial + len, sizeof(partial) - len, "%s%s",
                 (len || absolute) ? "/" : "", tok);
        mkdir(partial, 0755);            /* EEXIST is fine */
    }
}

static void json_escape(FILE *f, const char *s) {
    for (; *s; s++) {
        if (*s == '"' || *s == '\\') fputc('\\', f);
        if (*s == '\n') { fputs("\\n", f); continue; }
        fputc(*s, f);
    }
}

int main(int argc, char **argv) {
    const char *out = "experiments/results/e2_micro.json";
    long reps = DEFAULT_REPS;
    long warmup = DEFAULT_WARMUP;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--out") && i + 1 < argc) out = argv[++i];
        else if (!strcmp(argv[i], "--reps") && i + 1 < argc)
            reps = atol(argv[++i]);
        else if (!strcmp(argv[i], "--warmup") && i + 1 < argc)
            warmup = atol(argv[++i]);
        else {
            fprintf(stderr, "usage: %s [--out F] [--reps N] [--warmup W]\n",
                    argv[0]);
            return 2;
        }
    }
    if (reps < BATCH) reps = BATCH;
    long nbatches = reps / BATCH;
    reps = nbatches * BATCH;

    /* ---- metadata ---- */
    char date_iso[64];
    time_t now = time(NULL);
    struct tm tmv;
    localtime_r(&now, &tmv);
    strftime(date_iso, sizeof(date_iso), "%Y-%m-%dT%H:%M:%S%z", &tmv);

    char host[256] = "unknown";
    size_t hostlen = sizeof(host);
    sysctlbyname("machdep.cpu.brand_string", host, &hostlen, NULL, 0);
    int ncpu = 0;
    size_t ncpulen = sizeof(ncpu);
    sysctlbyname("hw.ncpu", &ncpu, &ncpulen, NULL, 0);

    mach_timebase_info_data_t tb;
    mach_timebase_info(&tb);
    double tick_ns = (double)tb.numer / (double)tb.denom;

    char cmdline[1024];
    cmdline[0] = 0;
    for (int i = 0; i < argc; i++) {
        size_t len = strlen(cmdline);
        snprintf(cmdline + len, sizeof(cmdline) - len, "%s%s",
                 i ? " " : "", argv[i]);
    }

    mkpath_for(out);
    FILE *f = fopen(out, "w");
    if (!f) {
        fprintf(stderr, "ktxmicro: cannot open output '%s': %s\n", out,
                strerror(errno));
        return 1;
    }
    fprintf(f, "{\n  \"experiment\": \"e2_micro\",\n  \"meta\": {\n");
    fprintf(f, "    \"date_iso\": \"%s\",\n", date_iso);
    fprintf(f, "    \"host\": \"");
    json_escape(f, host);
    fprintf(f, "\", \"ncpu\": %d,\n", ncpu);
    fprintf(f, "    \"cores_note\": \"Apple Silicon asymmetric cores; "
               "the macOS harness does not expose thread pinning\",\n");
    fprintf(f, "    \"cc\": \"");
    json_escape(f, __clang_version__);
    fprintf(f, "\",\n");
    fprintf(f, "    \"timer\": \"mach_absolute_time\", "
               "\"timebase_num\": %u, \"timebase_denom\": %u,\n",
            tb.numer, tb.denom);
    fprintf(f, "    \"timer_granularity_ns\": %.2f, \"latency_batch\": %d,\n",
            tick_ns, BATCH);
    fprintf(f, "    \"seed\": %d, \"cmdline\": \"", (int)KTX_ENV_SEED);
    json_escape(f, cmdline);
    fprintf(f, "\"\n  },\n");
    fprintf(f, "  \"notes\": \"map hash 4096 key=8 value=16; 256 distinct "
               "keys pre-populated before timing so commit applies "
               "overwrite in place (steady state, no free-list churn); "
               "each timed rep = tx_begin + k appends + "
               "(commit|abort_reset|nothing); commit-only and abort-only "
               "costs derive as (op - append); batch-of-32 timing because "
               "the timer tick is %.2f ns\",\n"
               "  \"runs\": [\n", tick_ns);

    /* ---- environment ---- */
    char err[256] = "";
    ktx_env *env = ktx_env_create(1);
    struct ktx_map *map = NULL;
    ktx_thread *th = NULL;
    const char *fatal = NULL;
    if (!env) fatal = "ktx_env_create failed";
    if (!fatal) {
        map = ktx_env_map_create(env, KTX_MAP_HASH, 8, 16, 4096, "micro",
                                 err, sizeof(err));
        if (!map) fatal = err[0] ? err : "map create failed";
    }
    if (!fatal) {
        th = ktx_thread_create(env, 0);
        if (!th) fatal = "ktx_thread_create failed";
    }

    uint64_t keys[MAX_K];
    uint8_t val[16];
    for (int j = 0; j < MAX_K; j++) keys[j] = 0x1000u + (uint64_t)j;
    memset(val, 0xAB, sizeof(val));

    if (!fatal) {
        for (int j = 0; j < MAX_K; j++)
            if (ktx_map_direct_update(map, &keys[j], val, 0) != 0) {
                fatal = "pre-population failed";
                break;
            }
    }

    double *batch_ns = malloc((size_t)nbatches * sizeof(double));
    if (!batch_ns && !fatal) fatal = "out of memory (batch buffer)";

    if (fatal) {
        fprintf(f, "    { \"error\": \"");
        json_escape(f, fatal);
        fprintf(f, "\" }\n  ]\n}\n");
        fclose(f);
        fprintf(stderr, "ktxmicro: FATAL: %s\n", fatal);
        free(batch_ns);
        if (th) ktx_thread_destroy(th);
        if (env) ktx_env_destroy(env);
        return 1;
    }

    int first = 1;
    for (int oi = 0; oi < 3; oi++) {
        for (int ki = 0; ki < N_KS; ki++) {
            int k = ks[ki];
            const char *op = ops[oi];
            const char *run_err = NULL;

            /* warmup */
            for (long w = 0; w < warmup && !run_err; w++) {
                ktx_tx_begin(th);
                for (int j = 0; j < k; j++)
                    if (ktx_tx_update(th, map, &keys[j], val) != KTX_OK) {
                        run_err = "tx_update failed in warmup";
                        break;
                    }
                if (run_err) break;
                if (oi == 0) {
                    if (ktx_tx_commit(th, NULL, 0) != KTX_OK)
                        run_err = "commit failed in warmup";
                } else if (oi == 1) {
                    ktx_tx_abort_reset(th);
                }
            }

            /* timed batches */
            double total_ticks = 0;
            for (long b = 0; b < nbatches && !run_err; b++) {
                uint64_t t0 = mach_absolute_time();
                for (int it = 0; it < BATCH; it++) {
                    ktx_tx_begin(th);
                    for (int j = 0; j < k; j++)
                        (void)ktx_tx_update(th, map, &keys[j], val);
                    if (oi == 0) {
                        if (ktx_tx_commit(th, NULL, 0) != KTX_OK)
                            run_err = "commit failed in timed region";
                    } else if (oi == 1) {
                        ktx_tx_abort_reset(th);
                    }
                }
                uint64_t t1 = mach_absolute_time();
                batch_ns[b] = (double)(t1 - t0) * tick_ns / BATCH;
                total_ticks += (double)(t1 - t0);
            }

            if (!first) fprintf(f, ",\n");
            first = 0;
            fprintf(f, "    { \"prog\": \"internal-micro\", "
                       "\"mode\": \"tx\", \"threads\": 1, "
                       "\"iters\": %ld, \"warmup\": %ld, \"fuel\": 0, "
                       "\"nkeys\": %d, \"zipf_theta\": 0.0, "
                       "\"pktlen_min\": 0, \"pktlen_max\": 0, "
                       "\"op\": \"%s\", \"log_k\": %d,\n      ",
                    reps, warmup, k, op, k);
            if (run_err) {
                fprintf(f, "\"error\": \"");
                json_escape(f, run_err);
                fprintf(f, "\" }");
                fprintf(stderr, "ktxmicro: run k=%d op=%s ERROR: %s\n", k,
                        op, run_err);
                continue;
            }
            qsort(batch_ns, (size_t)nbatches, sizeof(double), cmp_double);
            double p50 = batch_ns[(nbatches * 50) / 100];
            double mean = total_ticks * tick_ns / (double)reps;
            double mn = batch_ns[0];
            fprintf(f, "\"metrics\": { \"ns_p50\": %.3f, "
                       "\"ns_mean\": %.3f, \"ns_min\": %.3f } }",
                    p50, mean, mn);
            fprintf(stderr, "ktxmicro: k=%3d op=%-6s p50=%9.1f ns "
                            "mean=%9.1f ns\n", k, op, p50, mean);
        }
    }
    fprintf(f, "\n  ]\n}\n");
    fclose(f);
    free(batch_ns);
    ktx_thread_destroy(th);
    ktx_env_destroy(env);
    fprintf(stderr, "ktxmicro: wrote %s\n", out);
    return 0;
}
