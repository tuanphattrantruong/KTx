/* observer.c -- E16 mixed transactional/userspace observer litmus.
 * One writer atomically replaces an invariant pair in two maps.  The unsafe
 * arm performs two ordinary lookups with a yield between them; the published
 * arm uses the opt-in batch API and apply-only publication sequence. */
#include <inttypes.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "ktx_internal.h"

typedef struct {
    ktx_env *env;
    struct ktx_map *a, *b;
    int aid, bid, published;
    uint64_t writes, reads, torn, retries;
    _Atomic int done;
} run_t;

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static void *writer(void *arg) {
    run_t *r = arg;
    ktx_thread *t = ktx_thread_create(r->env, 0);
    uint32_t key = 0;
    for (uint64_t gen = 1; gen <= r->writes; gen++) {
        for (;;) {
            ktx_tx_begin(t);
            if (ktx_tx_update(t, r->a, &key, &gen) != KTX_OK ||
                ktx_tx_update(t, r->b, &key, &gen) != KTX_OK) {
                fprintf(stderr, "log failure\n"); exit(1);
            }
            ktx_status st = ktx_tx_commit(t, NULL, 0);
            if (st == KTX_OK) break;
            if (st != KTX_ABORT_CONFLICT) {
                fprintf(stderr, "commit failure %d\n", st); exit(1);
            }
            r->retries++;
            ktx_tx_abort_reset(t);
        }
    }
    atomic_store_explicit(&r->done, 1, memory_order_release);
    ktx_thread_destroy(t);
    return NULL;
}

static void *reader(void *arg) {
    run_t *r = arg;
    uint32_t key = 0;
    do {
        uint64_t a = 0, b = 0;
        if (r->published) {
            ktx_lookup_item items[2] = {
                {r->aid, &key, &a}, {r->bid, &key, &b}};
            if (ktx_map_lookup_batch(r->env, items, 2) != 0) continue;
        } else {
            if (ktx_map_lookup(r->env, r->aid, &key, &a) != 0) continue;
            sched_yield();
            if (ktx_map_lookup(r->env, r->bid, &key, &b) != 0) continue;
        }
        r->reads++;
        if (a != b) r->torn++;
    } while (!atomic_load_explicit(&r->done, memory_order_acquire));
    return NULL;
}

int main(int argc, char **argv) {
    int published = 0;
    uint64_t writes = 250000;
    const char *out = NULL;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--published")) published = 1;
        else if (!strcmp(argv[i], "--writes") && i + 1 < argc)
            writes = strtoull(argv[++i], NULL, 0);
        else if (!strcmp(argv[i], "--out") && i + 1 < argc)
            out = argv[++i];
        else return 2;
    }
    if (!out || writes == 0) return 2;
    ktx_env *env = ktx_env_create(2);
    if (published)
        ktx_env_set_opt(env, KTX_OPT_OBSERVER_PUBLISH, 1);
    char err[128];
    struct ktx_map *a = ktx_env_map_create(env, KTX_MAP_ARRAY, 4, 8, 1,
                                           "left", err, sizeof err);
    struct ktx_map *b = ktx_env_map_create(env, KTX_MAP_ARRAY, 4, 8, 1,
                                           "right", err, sizeof err);
    if (!a || !b) return 1;
    uint32_t key = 0; uint64_t zero = 0;
    ktx_map_update(env, (int)a->id, &key, &zero);
    ktx_map_update(env, (int)b->id, &key, &zero);
    run_t run = {.env=env, .a=a, .b=b, .aid=(int)a->id, .bid=(int)b->id,
                 .published=published, .writes=writes};
    pthread_t wt, rt;
    uint64_t t0 = now_ns();
    pthread_create(&rt, NULL, reader, &run);
    pthread_create(&wt, NULL, writer, &run);
    pthread_join(wt, NULL);
    pthread_join(rt, NULL);
    uint64_t t1 = now_ns();
    FILE *f = fopen(out, "w");
    if (!f) return 2;
    double sec = (double)(t1 - t0) / 1e9;
    fprintf(f, "{\n  \"experiment\": \"E16_mixed_observer\",\n");
    fprintf(f, "  \"mode\": \"%s\", \"writes\": %" PRIu64
               ", \"reader_samples\": %" PRIu64 ",\n",
            published ? "published" : "ordinary", writes, run.reads);
    fprintf(f, "  \"torn_observations\": %" PRIu64
               ", \"writer_retries\": %" PRIu64 ",\n", run.torn, run.retries);
    fprintf(f, "  \"seconds\": %.9f, \"commits_per_s\": %.3f\n}\n",
            sec, writes / sec);
    fclose(f);
    fprintf(stderr, "E16 %s: reads=%" PRIu64 " torn=%" PRIu64
                    " commits/s=%.0f\n",
            published ? "published" : "ordinary", run.reads, run.torn,
            writes / sec);
    ktx_env_destroy(env);
    return published && run.torn ? 1 : 0;
}
