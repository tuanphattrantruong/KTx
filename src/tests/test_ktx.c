/* test_ktx.c — transactional-layer unit tests: map ops (collisions,
 * full map, iteration), read-your-writes, commit/abort visibility,
 * OCC conflicts (two threads, interleaved manual commits via the
 * internal API), capacity abort, per-CPU commit, RO-elide validate-only
 * lookups, deferred intents (ringbuf, packet writes).
 * Self-sufficient: programs built with KTX_INSN + ktx_prog_load_mem.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../ktx/ktx_internal.h"

static int failures = 0, checks = 0;
#define CHECK(cond, ...) do { \
        checks++; \
        if (cond) { printf("PASS "); printf(__VA_ARGS__); printf("\n"); } \
        else { failures++; printf("FAIL "); printf(__VA_ARGS__); \
               printf("  [%s:%d]\n", __FILE__, __LINE__); } \
    } while (0)

/* ---------- image builders ---------- */

static size_t build_kbin(uint8_t *buf, size_t bufsz,
                         const struct ktx_map_desc *maps, uint32_t n_maps,
                         const struct ktx_insn *ins, uint32_t n_insns,
                         uint32_t min_pkt) {
    struct ktx_kbin_hdr h = { KTX_KBIN_MAGIC_LE, KTX_KBIN_VERSION,
                              n_insns, n_maps, min_pkt };
    size_t need = sizeof(h) + (size_t)n_maps * sizeof(struct ktx_map_desc)
                  + (size_t)n_insns * sizeof(struct ktx_insn);
    if (need > bufsz) return 0;
    memcpy(buf, &h, sizeof(h));
    if (n_maps)
        memcpy(buf + sizeof(h), maps,
               (size_t)n_maps * sizeof(struct ktx_map_desc));
    memcpy(buf + sizeof(h) + (size_t)n_maps * sizeof(struct ktx_map_desc),
           ins, (size_t)n_insns * sizeof(struct ktx_insn));
    return need;
}

static size_t build_elide(uint8_t *buf, size_t bufsz, uint32_t n_insns,
                          uint32_t flags, const uint8_t *iflags,
                          uint32_t n_maps, const uint8_t *map_ro) {
    struct ktx_elide_hdr h = { KTX_ELIDE_MAGIC_LE, KTX_ELIDE_VERSION,
                               n_insns, flags, n_maps };
    size_t need = sizeof(h) + n_insns + n_maps;
    if (need > bufsz) return 0;
    memcpy(buf, &h, sizeof(h));
    if (iflags) memcpy(buf + sizeof(h), iflags, n_insns);
    else memset(buf + sizeof(h), 0, n_insns);
    if (map_ro) memcpy(buf + sizeof(h) + n_insns, map_ro, n_maps);
    else memset(buf + sizeof(h) + n_insns, 0, n_maps);
    return need;
}

/* ---------- 1. hash map basics, collisions, full map, iter ---------- */

static void test_hash_basics(void) {
    ktx_env *e = ktx_env_create(1);
    char err[256];
    struct ktx_map *m = ktx_env_map_create(e, KTX_MAP_HASH, 8, 16, 8,
                                           "h8", err, sizeof(err));
    CHECK(m != NULL, "hash map create (%s)", err);
    int mid = ktx_map_id(e, "h8");
    CHECK(mid >= 0, "ktx_map_id finds map");

    uint64_t k;
    uint8_t v[16], out[16];
    for (k = 1; k <= 8; k++) {
        memset(v, (int)k, 16);
        CHECK(ktx_map_update(e, mid, &k, v) == 0, "insert key %llu",
              (unsigned long long)k);
    }
    CHECK(ktx_map_count(e, mid) == 8, "count == 8 after fill");
    k = 9;
    memset(v, 9, 16);
    CHECK(ktx_map_update(e, mid, &k, v) == -1, "9th insert fails (full)");
    k = 3;
    memset(v, 0x33, 16);
    CHECK(ktx_map_update(e, mid, &k, v) == 0, "overwrite existing when full");
    CHECK(ktx_map_lookup(e, mid, &k, out) == 0 && out[0] == 0x33,
          "lookup sees overwrite");
    CHECK(ktx_map_delete(e, mid, &k) == 0, "delete key 3");
    CHECK(ktx_map_lookup(e, mid, &k, out) == -1, "deleted key absent");
    CHECK(ktx_map_count(e, mid) == 7, "count == 7 after delete");
    k = 100;
    CHECK(ktx_map_delete(e, mid, &k) == -1, "delete absent key -> -1");
    k = 9;
    CHECK(ktx_map_update(e, mid, &k, v) == 0, "insert reuses freed node");

    /* iteration: exactly 8 live keys, sum matches */
    uint32_t iter = 0;
    uint64_t kk, seen = 0, sum = 0;
    CHECK(ktx_map_iter(e, mid, &iter, &kk, out) == -1,
          "iteration rejected without quiescence gate");
    CHECK(ktx_env_quiesce_begin(e) == 0,
          "quiescence gate acquired with no active invocation");
    CHECK(ktx_env_quiesce_begin(e) == -1,
          "quiescence gate is exclusive");
    while (ktx_map_iter(e, mid, &iter, &kk, out) == 0) {
        seen++;
        sum += kk;
    }
    ktx_env_quiesce_end(e);
    CHECK(seen == 8 && sum == 1 + 2 + 4 + 5 + 6 + 7 + 8 + 9,
          "iter enumerates 8 keys (sum %llu)", (unsigned long long)sum);

    /* forced collisions: find 3 keys landing in the same bucket */
    uint64_t ck[3];
    int found = 0;
    uint32_t want = (uint32_t)(ktx_hash64(&(uint64_t){ 1000 }, 8) & 7);
    for (uint64_t c = 1000; found < 3 && c < 100000; c++) {
        if ((ktx_hash64(&c, 8) & 7) == want) ck[found++] = c;
    }
    CHECK(found == 3, "found 3 colliding keys for bucket %u", want);
    struct ktx_map *cm = ktx_env_map_create(e, KTX_MAP_HASH, 8, 16, 8,
                                            "coll", err, sizeof(err));
    int cmid = cm ? (int)cm->id : -1;
    for (int i = 0; i < 3; i++) {
        memset(v, 0x40 + i, 16);
        ktx_map_update(e, cmid, &ck[i], v);
    }
    int ok = 1;
    for (int i = 0; i < 3; i++)
        ok &= (ktx_map_lookup(e, cmid, &ck[i], out) == 0 &&
               out[0] == 0x40 + i);
    CHECK(ok, "3 colliding keys all found in one chain");
    CHECK(ktx_map_delete(e, cmid, &ck[1]) == 0, "unlink middle of chain");
    ok = (ktx_map_lookup(e, cmid, &ck[0], out) == 0) &&
         (ktx_map_lookup(e, cmid, &ck[1], out) == -1) &&
         (ktx_map_lookup(e, cmid, &ck[2], out) == 0);
    CHECK(ok, "chain intact after middle unlink");
    ktx_env_destroy(e);
}

/* ---------- 2. array + percpu harness semantics ---------- */

static void test_array_percpu(void) {
    ktx_env *e = ktx_env_create(2);
    char err[256];
    ktx_env_map_create(e, KTX_MAP_ARRAY, 4, 8, 16, "arr", err, sizeof(err));
    ktx_env_map_create(e, KTX_MAP_PERCPU_ARRAY, 4, 8, 4, "pc", err,
                       sizeof(err));
    int aid = ktx_map_id(e, "arr"), pid = ktx_map_id(e, "pc");
    CHECK(aid >= 0 && pid >= 0, "array + percpu maps created");

    uint32_t idx = 3;
    uint64_t v = 0xabcdef, out = 0;
    CHECK(ktx_map_update(e, aid, &idx, &v) == 0 &&
          ktx_map_lookup(e, aid, &idx, &out) == 0 && out == v,
          "array update/lookup idx 3");
    idx = 16;
    CHECK(ktx_map_update(e, aid, &idx, &v) == -1 &&
          ktx_map_lookup(e, aid, &idx, &out) == -1,
          "array OOB index rejected");
    idx = 0;
    CHECK(ktx_map_delete(e, aid, &idx) == -1, "array delete rejected");

    /* harness percpu update writes every thread's slot */
    idx = 1;
    v = 42;
    ktx_map_update(e, pid, &idx, &v);
    uint64_t o0 = 0, o1 = 0;
    CHECK(ktx_map_lookup_percpu(e, pid, &idx, 0, &o0) == 0 && o0 == 42 &&
          ktx_map_lookup_percpu(e, pid, &idx, 1, &o1) == 0 && o1 == 42,
          "harness percpu update reaches all thread slots");
    CHECK(ktx_map_lookup_percpu(e, pid, &idx, 2, &o0) == -1,
          "percpu lookup with bad thread_idx rejected");
    ktx_env_destroy(e);
}

/* ---------- 3. read-your-writes (internal API) ---------- */

static void test_ryw(void) {
    ktx_env *e = ktx_env_create(1);
    char err[256];
    struct ktx_map *m = ktx_env_map_create(e, KTX_MAP_HASH, 8, 16, 64,
                                           "ryw", err, sizeof(err));
    ktx_thread *t = ktx_thread_create(e, 0);
    int mid = (int)m->id;

    uint64_t K = 0x1111;
    uint8_t vA[16], vB[16], out[16];
    memset(vA, 0xA1, 16);
    memset(vB, 0xB2, 16);

    ktx_tx_begin(t);
    CHECK(ktx_tx_update(t, m, &K, vA) == KTX_OK, "tx update K=vA");
    void *p = NULL;
    int sh = 0;
    CHECK(ktx_tx_lookup(t, m, &K, 0, &p, &sh) == KTX_OK && p &&
          memcmp(p, vA, 16) == 0, "RYW: update-then-lookup sees vA");
    int present = -1;
    CHECK(ktx_tx_delete(t, m, &K, &present) == KTX_OK && present == 1,
          "RYW: delete reports present");
    CHECK(ktx_tx_lookup(t, m, &K, 0, &p, &sh) == KTX_OK && p == NULL,
          "RYW: delete-then-lookup sees NULL");
    CHECK(ktx_tx_update(t, m, &K, vB) == KTX_OK, "tx update K=vB");
    CHECK(ktx_tx_lookup(t, m, &K, 0, &p, &sh) == KTX_OK && p &&
          memcmp(p, vB, 16) == 0, "RYW: latest record wins");
    CHECK(ktx_map_lookup(e, mid, &K, out) == -1,
          "pre-commit: harness cannot see the log");
    CHECK(ktx_tx_commit(t, NULL, 0) == KTX_OK, "commit applies log");
    CHECK(ktx_map_lookup(e, mid, &K, out) == 0 && memcmp(out, vB, 16) == 0,
          "post-commit: harness sees final value vB");

    /* write-through-shadow-pointer */
    uint64_t K2 = 0x2222;
    uint8_t v5[16];
    memset(v5, 0, 16);
    v5[0] = 5;
    ktx_map_update(e, mid, &K2, v5);
    ktx_tx_begin(t);
    CHECK(ktx_tx_lookup(t, m, &K2, 0, &p, &sh) == KTX_OK && p && !sh &&
          ((uint8_t *)p)[0] == 5, "lookup returns arena shadow copy");
    ((uint8_t *)p)[0] = 99;              /* program-store analogue */
    CHECK(ktx_map_lookup(e, mid, &K2, out) == 0 && out[0] == 5,
          "shadow write invisible to harness pre-commit");
    void *p2 = NULL;
    CHECK(ktx_tx_lookup(t, m, &K2, 0, &p2, &sh) == KTX_OK && p2 == p &&
          ((uint8_t *)p2)[0] == 99,
          "second lookup RYW-hits the dirtied shadow");
    CHECK(ktx_tx_commit(t, NULL, 0) == KTX_OK, "commit writes shadow back");
    CHECK(ktx_map_lookup(e, mid, &K2, out) == 0 && out[0] == 99,
          "write-through-pointer visible after commit");

    /* committed delete */
    ktx_tx_begin(t);
    present = -1;
    CHECK(ktx_tx_delete(t, m, &K2, &present) == KTX_OK && present == 1 &&
          ktx_tx_commit(t, NULL, 0) == KTX_OK &&
          ktx_map_lookup(e, mid, &K2, out) == -1,
          "committed delete removes key");

    /* delete of absent key reports absent */
    ktx_tx_begin(t);
    uint64_t K3 = 0x3333;
    present = -1;
    CHECK(ktx_tx_delete(t, m, &K3, &present) == KTX_OK && present == 0 &&
          ktx_tx_commit(t, NULL, 0) == KTX_OK,
          "blind delete of absent key validates and commits");

    ktx_thread_destroy(t);
    ktx_env_destroy(e);
}

/* ---------- 4. abort discards everything (program level) ---------- */

/* map hash 8->16 as map 0.  Writes key 0 = 0x2a.., emits an 8-byte
 * ringbuf message, intends a 4-byte packet write at offset 4, then
 * either exits with verdict 3 (GOOD) or hits an OOB stack store (BAD). */
static const struct ktx_map_desc eff_md = { KTX_MAP_HASH, 8, 16, 64, "eff" };
#define EFF_N 24
static void build_effects_prog(struct ktx_insn *P, int bad) {
    struct ktx_insn T[EFF_N] = {
        KTX_INSN(0x7b, 10, 0, -8, 0),        /*  0 key 0 (r0 == 0)   */
        KTX_INSN(0x7a, 10, 0, -24, 0x2a),    /*  1 val lo            */
        KTX_INSN(0x7a, 10, 0, -16, 0),       /*  2 val hi            */
        KTX_INSN(0x18, 1, 1, 0, 0),          /*  3 lddw r1, map 0    */
        KTX_INSN(0, 0, 0, 0, 0),             /*  4                   */
        KTX_INSN(0xbf, 2, 10, 0, 0),         /*  5 r2 = fp           */
        KTX_INSN(0x07, 2, 0, 0, -8),         /*  6 r2 = &key         */
        KTX_INSN(0xbf, 3, 10, 0, 0),         /*  7 r3 = fp           */
        KTX_INSN(0x07, 3, 0, 0, -24),        /*  8 r3 = &val         */
        KTX_INSN(0xb7, 4, 0, 0, 0),          /*  9 flags 0           */
        KTX_INSN(0x85, 0, 0, 0, 2),          /* 10 map_update        */
        KTX_INSN(0xb7, 1, 0, 0, 0),          /* 11                   */
        KTX_INSN(0xbf, 2, 10, 0, 0),         /* 12                   */
        KTX_INSN(0x07, 2, 0, 0, -24),        /* 13 r2 = &val         */
        KTX_INSN(0xb7, 3, 0, 0, 8),          /* 14 size 8            */
        KTX_INSN(0xb7, 4, 0, 0, 0),          /* 15                   */
        KTX_INSN(0x85, 0, 0, 0, 130),        /* 16 ringbuf_output    */
        KTX_INSN(0xb7, 2, 0, 0, 4),          /* 17 off 4             */
        KTX_INSN(0xbf, 3, 10, 0, 0),         /* 18                   */
        KTX_INSN(0x07, 3, 0, 0, -24),        /* 19 r3 = &val         */
        KTX_INSN(0xb7, 4, 0, 0, 4),          /* 20 len 4             */
        KTX_INSN(0x85, 0, 0, 0, 9),          /* 21 packet_store      */
        KTX_INSN(0xb7, 0, 0, 0, 3),          /* 22 verdict 3         */
        KTX_INSN(0x95, 0, 0, 0, 0),          /* 23 exit              */
    };
    if (bad)                                  /* trap before exit */
        T[22] = (struct ktx_insn)KTX_INSN(0x7b, 10, 0, -520, 0);
    memcpy(P, T, sizeof(T));
}

static void test_abort_discard(void) {
    for (int bad = 0; bad <= 1; bad++) {
        ktx_env *e = ktx_env_create(1);
        struct ktx_insn P[EFF_N];
        build_effects_prog(P, bad);
        uint8_t buf[4096];
        size_t n = build_kbin(buf, sizeof(buf), &eff_md, 1, P, EFF_N, 0);
        char err[256];
        ktx_prog *pg = ktx_prog_load_mem(e, buf, n, NULL, 0, err,
                                         sizeof(err));
        CHECK(pg != NULL, "effects prog (bad=%d) loads (%s)", bad, err);
        ktx_thread *t = ktx_thread_create(e, 0);
        uint8_t pkt[64];
        memset(pkt, 0xEE, sizeof(pkt));
        ktx_result r = ktx_run(t, pg, KTX_MODE_TX, pkt, 64, 0);
        int mid = ktx_map_id(e, "eff");
        uint64_t key = 0;
        uint8_t out[16];
        if (!bad) {
            CHECK(r.status == KTX_OK && r.verdict == 3,
                  "tx commit: status OK verdict 3");
            CHECK(r.log_records == 3,
                  "3 effect records (update+ringbuf+pktwrite), got %u",
                  r.log_records);
            CHECK(ktx_map_lookup(e, mid, &key, out) == 0 && out[0] == 0x2a,
                  "commit applied map update");
            CHECK(ktx_ringbuf_count(e) == 1, "commit applied ringbuf");
            CHECK(pkt[4] == 0x2a && pkt[5] == 0 && pkt[3] == 0xEE,
                  "commit applied deferred packet write");
        } else {
            CHECK(r.status == KTX_ABORT_GUARD &&
                  r.verdict == KTX_VERDICT_PASS,
                  "guard trap after effects -> abort, verdict PASS");
            CHECK(ktx_map_lookup(e, mid, &key, out) == -1,
                  "abort discarded map update");
            CHECK(ktx_ringbuf_count(e) == 0,
                  "abort discarded ringbuf intent");
            CHECK(pkt[4] == 0xEE, "abort discarded packet intent");

            /* Denial/exfiltration adversary: keep every invocation doomed,
             * but attempt all three externally visible effects first. */
            for (int attack = 0; attack < 1000; attack++) {
                memset(pkt, 0xEE, sizeof(pkt));
                r = ktx_run(t, pg, KTX_MODE_TX, pkt, 64, 0);
                if (r.status != KTX_ABORT_GUARD) break;
            }
            CHECK(r.status == KTX_ABORT_GUARD &&
                  ktx_map_lookup(e, mid, &key, out) == -1 &&
                  ktx_ringbuf_count(e) == 0 && pkt[4] == 0xEE,
                  "1000 deliberately doomed invocations exfiltrate no map, ring, or packet effect");

            /* The coarse baseline must retain the same abort semantics;
             * its only intended difference is whole-invocation
             * serialization rather than optimistic concurrency. */
            memset(pkt, 0xEE, sizeof(pkt));
            r = ktx_run(t, pg, KTX_MODE_COARSE, pkt, 64, 0);
            CHECK(r.status == KTX_ABORT_GUARD,
                  "coarse baseline reports the guard abort");
            CHECK(ktx_map_lookup(e, mid, &key, out) == -1 &&
                  ktx_ringbuf_count(e) == 0 && pkt[4] == 0xEE,
                  "coarse baseline is abort-safe across all logged effects");
        }
        /* same program, SFI: effects are direct (bad run tears state —
         * that is E3b's point; here just check the good run) */
        if (!bad) {
            ktx_ringbuf_reset(e);
            ktx_map_delete(e, mid, &key);
            memset(pkt, 0xEE, sizeof(pkt));
            r = ktx_run(t, pg, KTX_MODE_SFI, pkt, 64, 0);
            CHECK(r.status == KTX_OK && r.verdict == 3 &&
                  ktx_map_lookup(e, mid, &key, out) == 0 &&
                  ktx_ringbuf_count(e) == 1 && pkt[4] == 0x2a,
                  "sfi: direct effects applied immediately");
        }
        ktx_thread_destroy(t);
        ktx_prog_free(pg);
        ktx_env_destroy(e);
    }
}

/* ---------- 5. OCC conflict, two threads, manual interleave ---------- */

static void test_occ_conflict(void) {
    ktx_env *e = ktx_env_create(2);
    char err[256];
    struct ktx_map *m = ktx_env_map_create(e, KTX_MAP_HASH, 8, 16, 4096,
                                           "occ", err, sizeof(err));
    ktx_thread *A = ktx_thread_create(e, 0);
    ktx_thread *B = ktx_thread_create(e, 1);
    int mid = (int)m->id;

    uint64_t K = 0x42, K2 = 0x77;
    uint8_t v0[16], v1[16], v2[16], out[16];
    memset(v0, 0x10, 16);
    memset(v1, 0x11, 16);
    memset(v2, 0x12, 16);
    ktx_map_update(e, mid, &K, v0);

    /* A snapshots K; B commits a new K; A must conflict. */
    ktx_tx_begin(A);
    void *p = NULL;
    int sh = 0;
    CHECK(ktx_tx_lookup(A, m, &K, 0, &p, &sh) == KTX_OK && p,
          "A reads K (snapshot + read set)");
    ktx_tx_begin(B);
    CHECK(ktx_tx_update(B, m, &K, v1) == KTX_OK &&
          ktx_tx_commit(B, NULL, 0) == KTX_OK,
          "B commits an update to K");
    CHECK(ktx_tx_update(A, m, &K2, v2) == KTX_OK, "A logs K2 update");
    ktx_status st = ktx_tx_commit(A, NULL, 0);
    CHECK(st == KTX_ABORT_CONFLICT, "A's commit -> ABORT_CONFLICT");
    ktx_tx_abort_reset(A);
    CHECK(ktx_map_lookup(e, mid, &K2, out) == -1,
          "conflicted commit wrote nothing (K2 absent)");
    CHECK(ktx_map_lookup(e, mid, &K, out) == 0 &&
          memcmp(out, v1, 16) == 0, "B's value survives");

    /* read-only fast path: absence must validate too */
    uint64_t KA = 0x5150;
    ktx_tx_begin(A);
    CHECK(ktx_tx_lookup(A, m, &KA, 0, &p, &sh) == KTX_OK && p == NULL,
          "A reads absent KA (miss recorded)");
    ktx_map_update(e, mid, &KA, v1);     /* concurrent insert */
    st = ktx_tx_commit(A, NULL, 0);
    CHECK(st == KTX_ABORT_CONFLICT,
          "read-only commit conflicts on changed absence");
    ktx_tx_abort_reset(A);

    ktx_tx_begin(A);
    uint64_t KB = 0x6160;
    CHECK(ktx_tx_lookup(A, m, &KB, 0, &p, &sh) == KTX_OK && p == NULL &&
          ktx_tx_commit(A, NULL, 0) == KTX_OK,
          "undisturbed read-only commit succeeds");

    /* stripe versions restored after conflict: A can commit again */
    ktx_tx_begin(A);
    CHECK(ktx_tx_update(A, m, &K2, v2) == KTX_OK &&
          ktx_tx_commit(A, NULL, 0) == KTX_OK &&
          ktx_map_lookup(e, mid, &K2, out) == 0,
          "post-conflict retry commits cleanly");

    ktx_thread_destroy(A);
    ktx_thread_destroy(B);
    ktx_env_destroy(e);
}

/* ---------- 6. capacity abort ---------- */

static void test_capacity(void) {
    ktx_env *e = ktx_env_create(1);
    char err[256];
    struct ktx_map *m = ktx_env_map_create(e, KTX_MAP_HASH, 8, 16, 4,
                                           "cap4", err, sizeof(err));
    ktx_thread *t = ktx_thread_create(e, 0);
    int mid = (int)m->id;
    uint8_t v[16], out[16];
    memset(v, 7, 16);
    for (uint64_t k = 1; k <= 4; k++) ktx_map_update(e, mid, &k, v);

    ktx_tx_begin(t);
    uint64_t n1 = 100, n2 = 200;
    CHECK(ktx_tx_update(t, m, &n1, v) == KTX_OK &&
          ktx_tx_update(t, m, &n2, v) == KTX_OK,
          "log two inserts into a full map");
    ktx_status st = ktx_tx_commit(t, NULL, 0);
    CHECK(st == KTX_ABORT_CAPACITY, "commit -> ABORT_CAPACITY");
    ktx_tx_abort_reset(t);
    CHECK(ktx_map_lookup(e, mid, &n1, out) == -1 &&
          ktx_map_lookup(e, mid, &n2, out) == -1 &&
          ktx_map_count(e, mid) == 4,
          "capacity abort left the map untouched");

    /* overwrite of an existing key needs no capacity: still commits */
    ktx_tx_begin(t);
    uint64_t k1 = 1;
    memset(v, 8, 16);
    CHECK(ktx_tx_update(t, m, &k1, v) == KTX_OK &&
          ktx_tx_commit(t, NULL, 0) == KTX_OK &&
          ktx_map_lookup(e, mid, &k1, out) == 0 && out[0] == 8,
          "overwrite commit succeeds on full map");

    /* delete + insert in one tx: transient node available */
    ktx_tx_begin(t);
    uint64_t k2 = 2, n3 = 300;
    int present;
    CHECK(ktx_tx_delete(t, m, &k2, &present) == KTX_OK &&
          ktx_tx_update(t, m, &n3, v) == KTX_OK,
          "log delete(2)+insert(300) on full map");
    st = ktx_tx_commit(t, NULL, 0);
    /* delete frees its node only after unlock, and reservation is
     * conservative: this correctly aborts on capacity. */
    CHECK(st == KTX_ABORT_CAPACITY,
          "delete+insert same-tx on full map -> capacity abort "
          "(conservative reservation, documented)");
    ktx_tx_abort_reset(t);

    /* after a committed delete, the insert fits */
    ktx_tx_begin(t);
    CHECK(ktx_tx_delete(t, m, &k2, &present) == KTX_OK &&
          ktx_tx_commit(t, NULL, 0) == KTX_OK, "commit the delete");
    ktx_tx_begin(t);
    CHECK(ktx_tx_update(t, m, &n3, v) == KTX_OK &&
          ktx_tx_commit(t, NULL, 0) == KTX_OK &&
          ktx_map_lookup(e, mid, &n3, out) == 0,
          "freed capacity allows the insert");

    ktx_thread_destroy(t);
    ktx_env_destroy(e);
}

/* ---------- 7. per-CPU commit correctness ---------- */

static void test_percpu_commit(void) {
    ktx_env *e = ktx_env_create(2);
    char err[256];
    struct ktx_map *m = ktx_env_map_create(e, KTX_MAP_PERCPU_ARRAY, 4, 8, 2,
                                           "pcc", err, sizeof(err));
    ktx_thread *A = ktx_thread_create(e, 0);
    ktx_thread *B = ktx_thread_create(e, 1);
    int mid = (int)m->id;
    uint32_t idx = 0;

    for (int rep = 0; rep < 3; rep++) {
        ktx_tx_begin(A);
        void *p = NULL;
        int sh = 0;
        CHECK(ktx_tx_lookup(A, m, &idx, 0, &p, &sh) == KTX_OK && p,
              "A percpu lookup -> arena shadow (rep %d)", rep);
        (*(uint64_t *)p)++;
        CHECK(ktx_tx_commit(A, NULL, 0) == KTX_OK,
              "A percpu commit (lock-free path)");
    }
    ktx_tx_begin(B);
    void *p = NULL;
    int sh = 0;
    ktx_tx_lookup(B, m, &idx, 0, &p, &sh);
    (*(uint64_t *)p) += 10;
    CHECK(ktx_tx_commit(B, NULL, 0) == KTX_OK, "B percpu commit");

    uint64_t a = 0, b = 0;
    ktx_map_lookup_percpu(e, mid, &idx, 0, &a);
    ktx_map_lookup_percpu(e, mid, &idx, 1, &b);
    CHECK(a == 3 && b == 10,
          "per-thread slices isolated (a=%llu b=%llu)",
          (unsigned long long)a, (unsigned long long)b);

    /* aborted percpu tx leaves the slice untouched */
    ktx_tx_begin(A);
    ktx_tx_lookup(A, m, &idx, 0, &p, &sh);
    (*(uint64_t *)p) += 100;
    ktx_tx_abort_reset(A);
    ktx_map_lookup_percpu(e, mid, &idx, 0, &a);
    CHECK(a == 3, "aborted percpu increment discarded");

    ktx_thread_destroy(A);
    ktx_thread_destroy(B);
    ktx_env_destroy(e);
}

/* ---------- 8. RO-elide validate-only lookups ---------- */

static void test_ro_elide(void) {
    ktx_env *e = ktx_env_create(1);
    struct ktx_map_desc md = { KTX_MAP_HASH, 8, 16, 64, "rom" };
    struct ktx_insn P[] = {
        KTX_INSN(0x7b, 10, 0, -8, 0),        /* 0 key 0              */
        KTX_INSN(0x18, 1, 1, 0, 0),          /* 1 lddw r1, map 0     */
        KTX_INSN(0, 0, 0, 0, 0),             /* 2                    */
        KTX_INSN(0xbf, 2, 10, 0, 0),         /* 3                    */
        KTX_INSN(0x07, 2, 0, 0, -8),         /* 4                    */
        KTX_INSN(0x85, 0, 0, 0, 1),          /* 5 lookup             */
        KTX_INSN(0x15, 0, 0, 1, 0),          /* 6 jeq r0,0,+1        */
        KTX_INSN(0x79, 3, 0, 0, 0),          /* 7 read value         */
        KTX_INSN(0xb7, 0, 0, 0, 2),          /* 8 verdict 2          */
        KTX_INSN(0x95, 0, 0, 0, 0),          /* 9 exit               */
    };
    uint32_t N = sizeof(P) / sizeof(P[0]);
    uint8_t kb[4096], eb[256];
    size_t kn = build_kbin(kb, sizeof(kb), &md, 1, P, N, 0);
    uint8_t iflags[10] = { 0 };
    iflags[0] = KTX_IFLAG_TX_ELIDABLE;       /* stack store elidable */
    uint8_t map_ro[1] = { 1 };
    size_t en = build_elide(eb, sizeof(eb), N,
                            KTX_ELIDE_FLAG_COMPLETE | KTX_ELIDE_FLAG_FUEL,
                            iflags, 1, map_ro);
    char err[256];
    uint8_t bad[256];
    memcpy(bad, eb, en);
    ((struct ktx_elide_hdr *)bad)->flags |= 0x80;
    CHECK(ktx_prog_load_mem(e, kb, kn, bad, en, err, sizeof err) == NULL,
          "sidecar checker rejects unknown header claims");
    memcpy(bad, eb, en);
    ((struct ktx_elide_hdr *)bad)->flags = 0;
    CHECK(ktx_prog_load_mem(e, kb, kn, bad, en, err, sizeof err) == NULL,
          "sidecar checker rejects claims in incomplete certificate");
    memcpy(bad, eb, en);
    bad[sizeof(struct ktx_elide_hdr) + N] = 2;
    CHECK(ktx_prog_load_mem(e, kb, kn, bad, en, err, sizeof err) == NULL,
          "sidecar checker rejects non-Boolean map fact");
    ktx_prog *pg = ktx_prog_load_mem(e, kb, kn, eb, en, err, sizeof(err));
    CHECK(pg != NULL, "ro-elide prog loads (%s)", err);
    if (!pg) { ktx_env_destroy(e); return; }

    /* the sidecar physically changed the decoded stream */
    CHECK(pg->d_guarded[0].handler == H_STXDW_G &&
          pg->d_elided[0].handler == H_STXDW &&
          pg->d_elided[5].handler == H_CALL,
          "elision physically removed the guard from d_elided");
    CHECK(pg->fuel_elidable == 1 && pg->map_ro[0] == 1,
          "sidecar fuel + map_ro bits latched");

    int mid = ktx_map_id(e, "rom");
    uint64_t key = 0;
    uint8_t v[16];
    memset(v, 6, 16);
    ktx_map_update(e, mid, &key, v);
    ktx_thread *t = ktx_thread_create(e, 0);
    uint8_t pkt[64] = { 0 };

    ktx_result rt = ktx_run(t, pg, KTX_MODE_TX, pkt, 64, 0);
    CHECK(rt.status == KTX_OK && rt.verdict == 2 && rt.log_records == 1,
          "TX mode: lookup shadows (1 record)");
    ktx_result re = ktx_run(t, pg, KTX_MODE_TX_ELIDE, pkt, 64, 0);
    CHECK(re.status == KTX_OK && re.verdict == 2 && re.log_records == 0,
          "TX_ELIDE + map_ro: validate-only (0 records)");
    CHECK(re.fuel_used == 0, "fuel elided -> nofuel loop (fuel_used 0)");
    ktx_result rt2 = ktx_run(t, pg, KTX_MODE_TX, pkt, 64, 0);
    CHECK(rt2.fuel_used == 9,
          "TX mode still fueled (9 insns charged, LD_IMM64 pair = 1)");

    ktx_thread_destroy(t);
    ktx_prog_free(pg);
    ktx_env_destroy(e);
}

/* ---------- 9. helper-contract aborts ---------- */

static void test_helper_contracts(void) {
    ktx_env *e = ktx_env_create(1);
    { /* bad map handle tag */
        struct ktx_insn P[] = {
            KTX_INSN(0x18, 1, 0, 0, 0x1234), /* plain imm, not a map */
            KTX_INSN(0, 0, 0, 0, 0),
            KTX_INSN(0xbf, 2, 10, 0, 0),
            KTX_INSN(0x07, 2, 0, 0, -8),
            KTX_INSN(0x85, 0, 0, 0, 1),
            KTX_INSN(0x95, 0, 0, 0, 0),
        };
        uint8_t kb[1024];
        size_t kn = build_kbin(kb, sizeof(kb), NULL, 0, P, 6, 0);
        char err[256];
        ktx_prog *pg = ktx_prog_load_mem(e, kb, kn, NULL, 0, err,
                                         sizeof(err));
        CHECK(pg != NULL, "bad-handle prog loads (%s)", err);
        ktx_thread *t = ktx_thread_create(e, 0);
        uint8_t pkt[64] = { 0 };
        ktx_result rv = ktx_run(t, pg, KTX_MODE_VANILLA, pkt, 64, 0);
        ktx_result rs = ktx_run(t, pg, KTX_MODE_SFI, pkt, 64, 0);
        CHECK(rv.status == KTX_ABORT_HELPER &&
              rs.status == KTX_ABORT_HELPER,
              "bad map handle -> ABORT_HELPER (all modes)");
        ktx_thread_stats st;
        ktx_thread_stats_get(t, &st);
        CHECK(st.aborts_helper == 2, "helper aborts counted");
        ktx_thread_destroy(t);
        ktx_prog_free(pg);
    }
    { /* key pointer outside any region (sfi checks; vanilla trusts) */
        struct ktx_map_desc md = { KTX_MAP_HASH, 8, 16, 64, "hc" };
        struct ktx_insn P[] = {
            KTX_INSN(0x18, 1, 1, 0, 0),
            KTX_INSN(0, 0, 0, 0, 0),
            KTX_INSN(0xb7, 2, 0, 0, 4096),   /* bogus key ptr */
            KTX_INSN(0x85, 0, 0, 0, 1),
            KTX_INSN(0x95, 0, 0, 0, 0),
        };
        uint8_t kb[1024];
        size_t kn = build_kbin(kb, sizeof(kb), &md, 1, P, 5, 0);
        char err[256];
        ktx_prog *pg = ktx_prog_load_mem(e, kb, kn, NULL, 0, err,
                                         sizeof(err));
        CHECK(pg != NULL, "bad-keyptr prog loads (%s)", err);
        ktx_thread *t = ktx_thread_create(e, 0);
        uint8_t pkt[64] = { 0 };
        ktx_result r = ktx_run(t, pg, KTX_MODE_SFI, pkt, 64, 0);
        CHECK(r.status == KTX_ABORT_HELPER,
              "helper arg outside regions -> ABORT_HELPER (sfi)");
        r = ktx_run(t, pg, KTX_MODE_TX, pkt, 64, 0);
        CHECK(r.status == KTX_ABORT_HELPER,
              "helper arg outside regions -> ABORT_HELPER (tx)");
        ktx_thread_destroy(t);
        ktx_prog_free(pg);
    }
    { /* ringbuf oversize returns -1, no abort */
        struct ktx_insn P[] = {
            KTX_INSN(0xb7, 1, 0, 0, 0),
            KTX_INSN(0xbf, 2, 10, 0, 0),
            KTX_INSN(0x07, 2, 0, 0, -8),
            KTX_INSN(0xb7, 3, 0, 0, 600),    /* size 600 > 512 */
            KTX_INSN(0xb7, 4, 0, 0, 0),
            KTX_INSN(0x85, 0, 0, 0, 130),
            KTX_INSN(0x95, 0, 0, 0, 0),      /* verdict = r0 = -1 */
        };
        uint8_t kb[1024];
        size_t kn = build_kbin(kb, sizeof(kb), NULL, 0, P, 7, 0);
        char err[256];
        ktx_prog *pg = ktx_prog_load_mem(e, kb, kn, NULL, 0, err,
                                         sizeof(err));
        ktx_thread *t = ktx_thread_create(e, 0);
        uint8_t pkt[64] = { 0 };
        ktx_result r = ktx_run(t, pg, KTX_MODE_TX, pkt, 64, 0);
        CHECK(r.status == KTX_OK && r.verdict == (uint64_t)(int64_t)-1 &&
              ktx_ringbuf_count(e) == 0,
              "ringbuf size > 512 -> ret -1, no abort, no message");
        ktx_thread_destroy(t);
        ktx_prog_free(pg);
    }
    { /* packet_store_bytes OOB returns -1, no abort */
        struct ktx_insn P[] = {
            KTX_INSN(0xb7, 2, 0, 0, 62),     /* off 62 */
            KTX_INSN(0xbf, 3, 10, 0, 0),
            KTX_INSN(0x07, 3, 0, 0, -8),
            KTX_INSN(0xb7, 4, 0, 0, 4),      /* len 4: 62+4 > 64 */
            KTX_INSN(0x85, 0, 0, 0, 9),
            KTX_INSN(0x95, 0, 0, 0, 0),
        };
        uint8_t kb[1024];
        size_t kn = build_kbin(kb, sizeof(kb), NULL, 0, P, 6, 0);
        char err[256];
        ktx_prog *pg = ktx_prog_load_mem(e, kb, kn, NULL, 0, err,
                                         sizeof(err));
        ktx_thread *t = ktx_thread_create(e, 0);
        uint8_t pkt[64] = { 0 };
        ktx_result r = ktx_run(t, pg, KTX_MODE_SFI, pkt, 64, 0);
        CHECK(r.status == KTX_OK && r.verdict == (uint64_t)(int64_t)-1,
              "packet_store_bytes OOB -> ret -1, no abort");
        ktx_thread_destroy(t);
        ktx_prog_free(pg);
    }
    ktx_env_destroy(e);
}

/* ---------- 10. end-to-end tx increment program ---------- */

static void test_tx_increment_prog(void) {
    ktx_env *e = ktx_env_create(1);
    struct ktx_map_desc md = { KTX_MAP_HASH, 8, 16, 64, "flow" };
    struct ktx_insn P[] = {
        KTX_INSN(0x79, 2, 1, 0, 0),          /*  0 r2 = data         */
        KTX_INSN(0x79, 7, 2, 0, 0),          /*  1 r7 = key from pkt */
        KTX_INSN(0x7b, 10, 7, -8, 0),        /*  2 key to stack      */
        KTX_INSN(0x18, 1, 1, 0, 0),          /*  3 lddw r1, map 0    */
        KTX_INSN(0, 0, 0, 0, 0),             /*  4                   */
        KTX_INSN(0xbf, 2, 10, 0, 0),         /*  5                   */
        KTX_INSN(0x07, 2, 0, 0, -8),         /*  6 r2 = &key         */
        KTX_INSN(0x85, 0, 0, 0, 1),          /*  7 lookup            */
        KTX_INSN(0x15, 0, 0, 5, 0),          /*  8 jeq r0,0 -> 14    */
        KTX_INSN(0x79, 3, 0, 0, 0),          /*  9 r3 = *val         */
        KTX_INSN(0x07, 3, 0, 0, 1),          /* 10 r3++              */
        KTX_INSN(0x7b, 0, 3, 0, 0),          /* 11 write through ptr */
        KTX_INSN(0xb7, 0, 0, 0, 2),          /* 12 verdict 2         */
        KTX_INSN(0x95, 0, 0, 0, 0),          /* 13 exit              */
        KTX_INSN(0x7a, 10, 0, -24, 1),       /* 14 init val = 1      */
        KTX_INSN(0x7a, 10, 0, -16, 0),       /* 15                   */
        KTX_INSN(0x18, 1, 1, 0, 0),          /* 16 lddw r1, map 0    */
        KTX_INSN(0, 0, 0, 0, 0),             /* 17                   */
        KTX_INSN(0xbf, 2, 10, 0, 0),         /* 18                   */
        KTX_INSN(0x07, 2, 0, 0, -8),         /* 19 &key              */
        KTX_INSN(0xbf, 3, 10, 0, 0),         /* 20                   */
        KTX_INSN(0x07, 3, 0, 0, -24),        /* 21 &val              */
        KTX_INSN(0xb7, 4, 0, 0, 0),          /* 22                   */
        KTX_INSN(0x85, 0, 0, 0, 2),          /* 23 update            */
        KTX_INSN(0xb7, 0, 0, 0, 2),          /* 24 verdict 2         */
        KTX_INSN(0x95, 0, 0, 0, 0),          /* 25 exit              */
    };
    uint32_t N = sizeof(P) / sizeof(P[0]);
    uint8_t kb[4096];
    size_t kn = build_kbin(kb, sizeof(kb), &md, 1, P, N, 0);
    char err[256];
    ktx_prog *pg = ktx_prog_load_mem(e, kb, kn, NULL, 0, err, sizeof(err));
    CHECK(pg != NULL, "flow-increment prog loads (%s)", err);
    ktx_thread *t = ktx_thread_create(e, 0);
    uint8_t pkt[64] = { 0 };
    uint64_t flow = 0xfeed;
    memcpy(pkt, &flow, 8);

    for (int i = 0; i < 5; i++) {
        ktx_result r = ktx_run(t, pg, KTX_MODE_TX, pkt, 64, 0);
        CHECK(r.status == KTX_OK && r.verdict == 2,
              "tx increment run %d commits", i);
    }
    int mid = ktx_map_id(e, "flow");
    uint8_t out[16];
    uint64_t cnt = 0;
    CHECK(ktx_map_lookup(e, mid, &flow, out) == 0, "flow key present");
    memcpy(&cnt, out, 8);
    CHECK(cnt == 5, "lookup-or-init + write-through counted 5 (got %llu)",
          (unsigned long long)cnt);

    /* same program agrees in vanilla (fresh key) */
    uint64_t flow2 = 0xbeef;
    memcpy(pkt, &flow2, 8);
    for (int i = 0; i < 3; i++)
        ktx_run(t, pg, KTX_MODE_VANILLA, pkt, 64, 0);
    CHECK(ktx_map_lookup(e, mid, &flow2, out) == 0 &&
          (memcpy(&cnt, out, 8), cnt == 3),
          "vanilla direct path counts 3 (got %llu)",
          (unsigned long long)cnt);

    ktx_thread_destroy(t);
    ktx_prog_free(pg);
    ktx_env_destroy(e);
}

/* ---------- 11. log overflow -> ABORT_HELPER ---------- */

static void test_overflow(void) {
    ktx_env *e = ktx_env_create(1);
    char err[256];
    struct ktx_map *m = ktx_env_map_create(e, KTX_MAP_HASH, 8, 16, 4096,
                                           "ovf", err, sizeof(err));
    ktx_thread *t = ktx_thread_create(e, 0);
    uint8_t v[16];
    memset(v, 1, 16);

    /* record overflow: 512 records fit, 513th aborts */
    ktx_tx_begin(t);
    ktx_status st = KTX_OK;
    int i;
    for (i = 0; i < KTX_MAX_RECORDS + 1 && st == KTX_OK; i++) {
        uint64_t k = 0x9000 + (uint64_t)(i & 0xff);  /* few keys, RYW ok */
        st = ktx_tx_update(t, m, &k, v);
    }
    CHECK(st == KTX_ABORT_HELPER && i == KTX_MAX_RECORDS + 1,
          "record #%d overflows -> ABORT_HELPER", KTX_MAX_RECORDS + 1);
    ktx_tx_abort_reset(t);

    /* RYW overflow: 257 distinct keys */
    ktx_tx_begin(t);
    st = KTX_OK;
    for (i = 0; i < KTX_RYW_SLOTS + 1 && st == KTX_OK; i++) {
        uint64_t k = 0xA000 + (uint64_t)i;
        st = ktx_tx_update(t, m, &k, v);
    }
    CHECK(st == KTX_ABORT_HELPER,
          "distinct key #%d overflows RYW -> ABORT_HELPER",
          KTX_RYW_SLOTS + 1);
    ktx_tx_abort_reset(t);

    ktx_thread_destroy(t);
    ktx_env_destroy(e);
}


/* ---------- shadow diffing (clean lookups are pure reads) ---------- */
static void test_shadow_diff(void) {
    char err[256] = {0};
    ktx_env *e = ktx_env_create(1);
    struct ktx_map *m = ktx_env_map_create(e, KTX_MAP_HASH, 8, 8, 64,
                                           "sd", err, sizeof err);
    uint64_t k = 7, v = 100;
    ktx_map_update(e, (int)m->id, &k, &v);
    uint32_t s = ktx_hash_stripe(m, ktx_hash64(&k, 8));
    ktx_thread *t = ktx_thread_create(e, 0);

    /* (a) lookup without storing: the record is a clean shadow, commit
     *     must take the lock-free read-only path and leave the stripe
     *     version untouched. */
    uint64_t before = atomic_load(&m->ver[s]);
    ktx_tx_begin(t);
    void *p = NULL; int sh = 0;
    CHECK(ktx_tx_lookup(t, m, &k, 0, &p, &sh) == KTX_OK && p,
          "shadow-diff: lookup returns a shadow");
    CHECK(t->nrecs == 1 && t->recs[0].kind == EFF_SHADOW,
          "shadow-diff: lookup logs EFF_SHADOW");
    CHECK(!ktx_shadow_dirty(t, &t->recs[0]),
          "shadow-diff: untouched shadow is clean");
    CHECK(ktx_tx_commit(t, NULL, 0) == KTX_OK, "shadow-diff: clean commit");
    CHECK(atomic_load(&m->ver[s]) == before,
          "shadow-diff: clean commit does not bump the stripe version");

    /* (b) store through the shadow: dirty, written back, version bumps. */
    ktx_tx_begin(t);
    CHECK(ktx_tx_lookup(t, m, &k, 0, &p, &sh) == KTX_OK && p,
          "shadow-diff: second lookup");
    uint64_t nv = 101;
    memcpy(p, &nv, 8);
    CHECK(ktx_shadow_dirty(t, &t->recs[0]),
          "shadow-diff: modified shadow is dirty");
    CHECK(ktx_tx_commit(t, NULL, 0) == KTX_OK, "shadow-diff: dirty commit");
    CHECK(atomic_load(&m->ver[s]) == before + 2,
          "shadow-diff: dirty commit bumps the stripe version");
    uint64_t out = 0;
    ktx_map_lookup(e, (int)m->id, &k, &out);
    CHECK(out == 101, "shadow-diff: dirty value written back (got %llu)",
          (unsigned long long)out);

    /* (c) writing back the same bytes is not a mutation. */
    ktx_tx_begin(t);
    CHECK(ktx_tx_lookup(t, m, &k, 0, &p, &sh) == KTX_OK && p, "third lookup");
    memcpy(p, &nv, 8);                   /* same value */
    CHECK(!ktx_shadow_dirty(t, &t->recs[0]),
          "shadow-diff: same-value store stays clean");
    CHECK(ktx_tx_commit(t, NULL, 0) == KTX_OK, "shadow-diff: idempotent commit");
    CHECK(atomic_load(&m->ver[s]) == before + 2,
          "shadow-diff: same-value store does not bump the version");

    /* (d) with the option off, every shadow is written back. */
    ktx_env_set_opt(e, KTX_OPT_SHADOW_DIFF, 0);
    ktx_tx_begin(t);
    CHECK(ktx_tx_lookup(t, m, &k, 0, &p, &sh) == KTX_OK && p, "fourth lookup");
    CHECK(ktx_tx_commit(t, NULL, 0) == KTX_OK, "shadow-diff-off commit");
    CHECK(atomic_load(&m->ver[s]) == before + 4,
          "shadow-diff off: clean shadow still bumps the version");
    ktx_thread_destroy(t);
    ktx_env_destroy(e);
}

/* ---------- 2PL strawman ---------- */
static void test_twopl(void) {
    /* r0 = lookup(map, key); if null -> update(key, 1) else *v += 1 */
    static const struct ktx_map_desc maps[1] = {
        { KTX_MAP_HASH, 8, 8, 64, "tp" }
    };
    const struct ktx_insn ins[] = {
        KTX_INSN(0x7a, 10, 0, -8, 5),        /*  0 stdw [r10-8], 5 (key)  */
        KTX_INSN(0xbf, 2, 10, 0, 0),         /*  1 mov r2, r10            */
        KTX_INSN(0x07, 2, 0, 0, -8),         /*  2 add r2, -8             */
        KTX_INSN(0x18, 1, 1, 0, 0),          /*  3 lddw r1, map 0         */
        KTX_INSN(0, 0, 0, 0, 0),             /*  4 (second slot)          */
        KTX_INSN(0x85, 0, 0, 0, KTX_HELPER_MAP_LOOKUP),   /*  5 */
        KTX_INSN(0x15, 0, 0, 5, 0),          /*  6 jeq r0, 0, ->12        */
        KTX_INSN(0x79, 3, 0, 0, 0),          /*  7 ldxdw r3, [r0+0]       */
        KTX_INSN(0x07, 3, 0, 0, 1),          /*  8 add r3, 1              */
        KTX_INSN(0x7b, 0, 3, 0, 0),          /*  9 stxdw [r0+0], r3       */
        KTX_INSN(0xb7, 0, 0, 0, 2),          /* 10 mov r0, 2              */
        KTX_INSN(0x95, 0, 0, 0, 0),          /* 11 exit                   */
        KTX_INSN(0x7a, 10, 0, -16, 1),       /* 12 stdw [r10-16], 1       */
        KTX_INSN(0xbf, 2, 10, 0, 0),         /* 13 */
        KTX_INSN(0x07, 2, 0, 0, -8),         /* 14 */
        KTX_INSN(0xbf, 3, 10, 0, 0),         /* 15 */
        KTX_INSN(0x07, 3, 0, 0, -16),        /* 16 */
        KTX_INSN(0xb7, 4, 0, 0, 0),          /* 17 mov r4, 0              */
        KTX_INSN(0x18, 1, 1, 0, 0),          /* 18 lddw r1, map 0         */
        KTX_INSN(0, 0, 0, 0, 0),             /* 19 */
        KTX_INSN(0x85, 0, 0, 0, KTX_HELPER_MAP_UPDATE),   /* 20 */
        KTX_INSN(0xb7, 0, 0, 0, 2),          /* 21 */
        KTX_INSN(0x95, 0, 0, 0, 0),          /* 22 exit                   */
    };
    uint8_t buf[4096];
    size_t n = build_kbin(buf, sizeof buf, maps, 1, ins,
                          (uint32_t)(sizeof ins / sizeof ins[0]), 0);
    char err[256] = {0};
    ktx_env *e = ktx_env_create(1);
    ktx_prog *pg = ktx_prog_load_mem(e, buf, n, NULL, 0, err, sizeof err);
    CHECK(pg != NULL, "2pl prog loads (%s)", err);
    if (!pg) { ktx_env_destroy(e); return; }
    ktx_thread *t = ktx_thread_create(e, 0);
    uint8_t pkt[64] = {0};
    for (int i = 0; i < 4; i++) {
        ktx_result r = ktx_run(t, pg, KTX_MODE_2PL, pkt, sizeof pkt, 0);
        CHECK(r.status == KTX_OK && r.verdict == 2, "2pl run %d commits", i);
    }
    int mid = ktx_map_id(e, "tp");
    uint64_t k = 5, v = 0;
    CHECK(ktx_map_lookup(e, mid, &k, &v) == 0 && v == 4,
          "2pl direct effects visible (got %llu)", (unsigned long long)v);
    ktx_thread_stats st;
    ktx_thread_stats_get(t, &st);
    CHECK(st.commits == 4 && st.aborts_deadlock == 0,
          "2pl: 4 commits, no deadlock aborts");
    for (int i = 0; i < 4; i++) {
        ktx_result r = ktx_run(t, pg, KTX_MODE_P2PL, pkt, sizeof pkt, 0);
        CHECK(r.status == KTX_OK && r.verdict == 2,
              "predeclared 2pl run %d commits", i);
    }
    v = 0;
    CHECK(ktx_map_lookup(e, mid, &k, &v) == 0 && v == 8,
          "predeclared 2pl direct effects visible (got %llu)",
          (unsigned long long)v);
    ktx_thread_stats_get(t, &st);
    CHECK(st.commits == 8 && st.aborts_deadlock == 0,
          "global-order predeclared 2pl cannot deadlock");
    ktx_thread_destroy(t);
    ktx_prog_free(pg);
    ktx_env_destroy(e);
}

/* ---------- attachment-point abort policy ---------- */
static void test_policy(void) {
    /* Program that always traps its guard: store past the stack. */
    const struct ktx_insn ins[] = {
        KTX_INSN(0xbf, 1, 10, 0, 0),         /* mov r1, r10               */
        KTX_INSN(0x07, 1, 0, 0, 4096),       /* add r1, 4096 (out of any
                                              * region)                   */
        KTX_INSN(0x7a, 1, 0, 0, 1),          /* stdw [r1+0], 1 -> trap    */
        KTX_INSN(0xb7, 0, 0, 0, 2),
        KTX_INSN(0x95, 0, 0, 0, 0),
    };
    uint8_t buf[2048];
    size_t n = build_kbin(buf, sizeof buf, NULL, 0, ins,
                          (uint32_t)(sizeof ins / sizeof ins[0]), 0);
    char err[256] = {0};
    ktx_env *e = ktx_env_create(1);
    ktx_prog *pg = ktx_prog_load_mem(e, buf, n, NULL, 0, err, sizeof err);
    CHECK(pg != NULL, "policy prog loads (%s)", err);
    if (!pg) { ktx_env_destroy(e); return; }
    ktx_thread *t = ktx_thread_create(e, 0);
    uint8_t pkt[64] = {0};
    ktx_result r = ktx_run(t, pg, KTX_MODE_TX, pkt, sizeof pkt, 0);
    CHECK(r.status == KTX_ABORT_GUARD && r.verdict == KTX_VERDICT_PASS,
          "default policy: guard abort returns PASS (fails open)");
    ktx_policy closed = { KTX_VERDICT_DROP, 0 };
    r = ktx_run_ex(t, pg, KTX_MODE_TX, pkt, sizeof pkt, 0, &closed);
    CHECK(r.status == KTX_ABORT_GUARD && r.verdict == KTX_VERDICT_DROP,
          "fail-closed policy: guard abort returns DROP");
    ktx_policy retry = { KTX_VERDICT_DROP, 4 };
    ktx_thread_stats_reset(t);
    r = ktx_run_ex(t, pg, KTX_MODE_TX, pkt, sizeof pkt, 0, &retry);
    ktx_thread_stats st;
    ktx_thread_stats_get(t, &st);
    CHECK(st.retries == 0 && st.aborts_guard == 1,
          "retry is not attempted for non-conflict aborts");
    ktx_thread_destroy(t);
    ktx_prog_free(pg);
    ktx_env_destroy(e);
}

int main(void) {
    printf("== test_ktx ==\n");
    test_hash_basics();
    test_array_percpu();
    test_ryw();
    test_abort_discard();
    test_occ_conflict();
    test_capacity();
    test_percpu_commit();
    test_ro_elide();
    test_helper_contracts();
    test_tx_increment_prog();
    test_overflow();
    test_shadow_diff();
    test_twopl();
    test_policy();
    printf("== test_ktx: %d checks, %d failures ==\n", checks, failures);
    return failures ? 1 : 0;
}
