/* test_jit.c — differential test: the JIT must be indistinguishable from
 * the interpreter.
 *
 * For every workload and every execution mode, the same packet stream is
 * replayed twice against two independent, identically initialised
 * environments — one interpreting, one running native code — and we
 * compare, per invocation, the status, the verdict, the fuel charged and
 * the number of log records, and, at the end of the stream, the full
 * contents of every map.  Any divergence is a JIT bug, and there is
 * nowhere for one to hide: the two runs share the helper layer, the
 * commit protocol and the packet generator, so the *only* difference is
 * how the extension body executes.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../ktx/ktx_internal.h"
#include "../bench/trace.h"
#include "../jit/jit.h"

static int failures = 0, checks = 0;
#define CHECK(cond, ...) do { \
        checks++; \
        if (!(cond)) { failures++; printf("FAIL "); printf(__VA_ARGS__); \
                       printf("  [%s:%d]\n", __FILE__, __LINE__); } \
    } while (0)
#include "../include/ktx_format.h"

#define PKT_CAP 2048u

static void init_named_maps(ktx_env *env) {
    int id = ktx_map_id(env, "table");
    if (id >= 0)
        for (uint32_t i = 0; i < 4093; i++) {
            uint64_t s = i;
            uint32_t v = (uint32_t)(tr_splitmix64(&s) % 64);
            ktx_map_update(env, id, &i, &v);
        }
    int bl = ktx_map_id(env, "blocklist");
    if (bl >= 0)
        for (uint32_t k = 0; k < 128; k++) {
            uint64_t key = tr_flow_key(k * 8), one = 1;
            ktx_map_update(env, bl, &key, &one);
        }
    int a = ktx_map_id(env, "acct_a"), b = ktx_map_id(env, "acct_b");
    if (a >= 0 && b >= 0)
        for (uint32_t k = 0; k < 256; k++) {
            uint64_t va = 1000, vb = 0;
            ktx_map_update(env, a, &k, &va);
            ktx_map_update(env, b, &k, &vb);
        }
}

/* Byte-compare every map of two environments. */
static int maps_equal(ktx_env *x, ktx_env *y, char *why, size_t n) {
    if (x->nmaps != y->nmaps) { snprintf(why, n, "map count"); return 0; }
    for (uint32_t i = 0; i < x->nmaps; i++) {
        struct ktx_map *mx = x->maps[i], *my = y->maps[i];
        if (mx->max_entries != my->max_entries) {
            snprintf(why, n, "map %s size", mx->name);
            return 0;
        }
        uint8_t k[64], v1[4096], v2[4096];
        uint32_t it = 0, cnt = 0;
        while (ktx_map_iter(x, (int)i, &it, k, v1) == 0) {
            cnt++;
            if (ktx_map_lookup(y, (int)i, k, v2) != 0) {
                snprintf(why, n, "map %s: key missing in JIT env", mx->name);
                return 0;
            }
            if (memcmp(v1, v2, mx->value_size) != 0) {
                snprintf(why, n, "map %s: value differs", mx->name);
                return 0;
            }
        }
        it = 0;
        uint32_t cnt2 = 0;
        while (ktx_map_iter(y, (int)i, &it, k, v2) == 0) cnt2++;
        if (cnt != cnt2) {
            snprintf(why, n, "map %s: entry count %u vs %u", mx->name,
                     cnt, cnt2);
            return 0;
        }
    }
    return 1;
}

/* Programs whose committed state depends on the wall clock cannot have
 * their final map bytes compared across two runs that happen at
 * different times; their per-invocation status/verdict/fuel/record
 * checks still apply, and those are the ones that would catch a
 * miscompilation. */
static int clock_dependent(const char *prog) {
    return strcmp(prog, "tokenbucket") == 0 ||   /* stores last_ns */
           strcmp(prog, "l4lb") == 0 ||
           strcmp(prog, "policy") == 0;
}

static void run_pair(const char *prog, ktx_mode mode, const char *modename,
                     uint64_t iters, int64_t fuel) {
    char kb[256], el[256], err[512] = {0};
    printf("  [%s/%s]\n", prog, modename);
    snprintf(kb, sizeof kb, "workloads/%s.kbin", prog);
    snprintf(el, sizeof el, "workloads/%s.elide", prog);

    ktx_env *ei = ktx_env_create(1);
    ktx_env *ej = ktx_env_create(1);
    ktx_env_set_opt(ej, KTX_OPT_JIT, 1);
    ktx_prog *pi = ktx_prog_load(ei, kb, el, err, sizeof err);
    ktx_prog *pj = ktx_prog_load(ej, kb, el, err, sizeof err);
    if (!pi || !pj) {
        CHECK(0, "%s/%s: load failed (%s)", prog, modename, err);
        return;
    }
    if (!ktx_prog_is_jitted(pj)) {
        CHECK(0, "%s/%s: program did not compile", prog, modename);
        return;
    }
    init_named_maps(ei);
    init_named_maps(ej);
    ktx_thread *ti = ktx_thread_create(ei, 0);
    ktx_thread *tj = ktx_thread_create(ej, 0);
    uint8_t *bi = malloc(PKT_CAP), *bj = malloc(PKT_CAP);
    uint64_t prng = 0x1234567;
    int bad = 0;
    for (uint64_t i = 0; i < iters && !bad; i++) {
        uint64_t p2 = prng;
        uint32_t fid = (uint32_t)(tr_xorshift64s(&prng) % 1024);
        uint32_t len = tr_fill_packet(bi, PKT_CAP, fid, &prng, 64, 256);
        (void)tr_xorshift64s(&p2);
        uint32_t fid2 = (uint32_t)(tr_xorshift64s(&p2) % 1024);
        (void)fid2;
        memcpy(bj, bi, len);                 /* identical packet bytes */
        ktx_result ri = ktx_run(ti, pi, mode, bi, len, fuel);
        ktx_result rj = ktx_run(tj, pj, mode, bj, len, fuel);
        /* A clock-reading program can take a different branch in the two
         * runs, so its instruction count (and hence fuel charged) is not
         * comparable across them; status, verdict and effects still are. */
        int fuel_cmp = clock_dependent(prog) ? 0
                                             : (ri.fuel_used != rj.fuel_used);
        if (ri.status != rj.status || ri.verdict != rj.verdict || fuel_cmp ||
            ri.log_records != rj.log_records ||
            memcmp(bi, bj, len) != 0) {
            CHECK(0, "%s/%s: divergence at %llu "
                     "(st %d/%d verdict %llu/%llu fuel %llu/%llu recs %u/%u"
                     " pkt %s)",
                  prog, modename, (unsigned long long)i, ri.status, rj.status,
                  (unsigned long long)ri.verdict,
                  (unsigned long long)rj.verdict,
                  (unsigned long long)ri.fuel_used,
                  (unsigned long long)rj.fuel_used,
                  ri.log_records, rj.log_records,
                  memcmp(bi, bj, len) ? "differs" : "same");
            bad = 1;
        }
    }
    char why[128] = {0};
    if (!bad && !clock_dependent(prog)) {
        CHECK(ktx_env_quiesce_begin(ei) == 0 &&
              ktx_env_quiesce_begin(ej) == 0,
              "%s/%s: acquire post-run quiescence", prog, modename);
        CHECK(maps_equal(ei, ej, why, sizeof why),
              "%s/%s: final map state differs (%s)", prog, modename, why);
        ktx_env_quiesce_end(ej);
        ktx_env_quiesce_end(ei);
    }
    ktx_thread_stats si, sj;
    ktx_thread_stats_get(ti, &si);
    ktx_thread_stats_get(tj, &sj);
    if (!bad)
        CHECK(si.commits == sj.commits && si.aborts_guard == sj.aborts_guard
              && si.aborts_fuel == sj.aborts_fuel
              && si.aborts_helper == sj.aborts_helper
              && si.aborts_conflict == sj.aborts_conflict,
              "%s/%s: stats differ", prog, modename);
    free(bi); free(bj);
    ktx_thread_destroy(ti); ktx_thread_destroy(tj);
    ktx_prog_free(pi); ktx_prog_free(pj);
    ktx_env_destroy(ei); ktx_env_destroy(ej);
}

/* ---------- generated opcode-coverage differential ----------
 *
 * The workload programs exercise the opcodes they happen to use.  This
 * generates programs that use *all* of them: every ALU64, ALU32 and jump
 * form in the subset, over random registers and immediates, with stack
 * traffic mixed in, folding the whole register file into r0 at exit so a
 * divergence anywhere becomes a divergence in the verdict.  Compiler
 * output leans on ALU32 and jump32 far more than hand-written assembly
 * does, so this is what makes the JIT safe to point at clang's output.
 */
static const uint8_t ALU64_K[] = { 0x07,0x17,0x27,0x37,0x47,0x57,0x67,0x77,
                                   0x97,0xa7,0xb7,0xc7 };
static const uint8_t ALU64_X[] = { 0x0f,0x1f,0x2f,0x3f,0x4f,0x5f,0x6f,0x7f,
                                   0x9f,0xaf,0xbf,0xcf };
static const uint8_t ALU32_K[] = { 0x04,0x14,0x24,0x34,0x44,0x54,0x64,0x74,
                                   0x94,0xa4,0xb4,0xc4 };
static const uint8_t ALU32_X[] = { 0x0c,0x1c,0x2c,0x3c,0x4c,0x5c,0x6c,0x7c,
                                   0x9c,0xac,0xbc,0xcc };
static const uint8_t JMP_K[]   = { 0x15,0x25,0x35,0x45,0x55,0x65,0x75,
                                   0xa5,0xb5,0xc5,0xd5 };
static const uint8_t JMP_X[]   = { 0x1d,0x2d,0x3d,0x4d,0x5d,0x6d,0x7d,
                                   0xad,0xbd,0xcd,0xdd };
static const uint8_t JMP32_K[] = { 0x16,0x26,0x36,0x46,0x56,0x66,0x76,
                                   0xa6,0xb6,0xc6,0xd6 };
static const uint8_t JMP32_X[] = { 0x1e,0x2e,0x3e,0x4e,0x5e,0x6e,0x7e,
                                   0xae,0xbe,0xce,0xde };

static void fuzz_opcodes(int nprog, int niter) {
    uint64_t rng = 0xC0FFEE;
#define RND (tr_xorshift64s(&rng))
    for (int prog = 0; prog < nprog; prog++) {
        struct ktx_insn ins[512];
        int n = 0;
        /* r7 = packet data; then seed r1..r6, r8, r9 from packet words */
        ins[n++] = (struct ktx_insn)KTX_INSN(0x79, 7, 1, 0, 0);
        for (int r = 1; r <= 9; r++) {
            if (r == 7) continue;
            ins[n++] = (struct ktx_insn)KTX_INSN(0x79, r, 7, (int16_t)(8 * r), 0);
        }
        ins[n++] = (struct ktx_insn)KTX_INSN(0xb7, 0, 0, 0, 0);
        while (n < 300) {
            int pick = (int)(RND % 10);
            int dst = (int)(RND % 10), src = (int)(RND % 10);
            int32_t imm = (int32_t)(uint32_t)RND;
            if (pick == 0)
                ins[n++] = (struct ktx_insn)KTX_INSN(
                    ALU64_K[RND % sizeof ALU64_K], dst, 0, 0, imm);
            else if (pick == 1)
                ins[n++] = (struct ktx_insn)KTX_INSN(
                    ALU64_X[RND % sizeof ALU64_X], dst, src, 0, 0);
            else if (pick == 2)
                ins[n++] = (struct ktx_insn)KTX_INSN(
                    ALU32_K[RND % sizeof ALU32_K], dst, 0, 0, imm);
            else if (pick == 3)
                ins[n++] = (struct ktx_insn)KTX_INSN(
                    ALU32_X[RND % sizeof ALU32_X], dst, src, 0, 0);
            else if (pick == 4) {                       /* negate */
                ins[n++] = (struct ktx_insn)KTX_INSN(
                    (RND & 1) ? 0x87 : 0x84, dst, 0, 0, 0);
            } else if (pick == 5) {                     /* stack round-trip */
                int16_t off = (int16_t)(-8 * (1 + (int)(RND % 60)));
                ins[n++] = (struct ktx_insn)KTX_INSN(0x7b, 10, src, off, 0);
                ins[n++] = (struct ktx_insn)KTX_INSN(0x79, dst, 10, off, 0);
            } else if (pick == 6) {                     /* sub-word stack */
                int16_t off = (int16_t)(-8 * (1 + (int)(RND % 60)));
                ins[n++] = (struct ktx_insn)KTX_INSN(0x63, 10, src, off, 0);
                ins[n++] = (struct ktx_insn)KTX_INSN(0x61, dst, 10, off, 0);
                ins[n++] = (struct ktx_insn)KTX_INSN(0x6b, 10, src, off, 0);
                ins[n++] = (struct ktx_insn)KTX_INSN(0x69, dst, 10, off, 0);
                ins[n++] = (struct ktx_insn)KTX_INSN(0x73, 10, src, off, 0);
                ins[n++] = (struct ktx_insn)KTX_INSN(0x71, dst, 10, off, 0);
            } else if (pick == 7) {                     /* store-immediate */
                int16_t off = (int16_t)(-8 * (1 + (int)(RND % 60)));
                ins[n++] = (struct ktx_insn)KTX_INSN(0x7a, 10, 0, off, imm);
                ins[n++] = (struct ktx_insn)KTX_INSN(0x79, dst, 10, off, 0);
            } else if (pick == 8) {                     /* ld_imm64 */
                ins[n++] = (struct ktx_insn)KTX_INSN(0x18, dst, 0, 0, imm);
                ins[n++] = (struct ktx_insn)KTX_INSN(0, 0, 0, 0,
                                                     (int32_t)(uint32_t)RND);
            } else {                                    /* conditional skip */
                int k = (int)(RND % 4);
                uint8_t op = k == 0 ? JMP_K[RND % sizeof JMP_K]
                           : k == 1 ? JMP_X[RND % sizeof JMP_X]
                           : k == 2 ? JMP32_K[RND % sizeof JMP32_K]
                                    : JMP32_X[RND % sizeof JMP32_X];
                int isx = (k == 1 || k == 3);
                ins[n++] = (struct ktx_insn)KTX_INSN(op, dst, isx ? src : 0,
                                                     1, isx ? 0 : imm);
                ins[n++] = (struct ktx_insn)KTX_INSN(0xb7, dst, 0, 0, imm);
            }
        }
        /* fold every register into r0, then exit */
        ins[n++] = (struct ktx_insn)KTX_INSN(0xbf, 0, 1, 0, 0);
        for (int r = 2; r <= 9; r++)
            ins[n++] = (struct ktx_insn)KTX_INSN(0xaf, 0, r, 0, 0);
        ins[n++] = (struct ktx_insn)KTX_INSN(0x95, 0, 0, 0, 0);

        uint8_t buf[8192];
        struct ktx_kbin_hdr h = { KTX_KBIN_MAGIC_LE, KTX_KBIN_VERSION,
                                  (uint32_t)n, 0, 128 };
        memcpy(buf, &h, sizeof h);
        memcpy(buf + sizeof h, ins, (size_t)n * sizeof ins[0]);
        size_t blen = sizeof h + (size_t)n * sizeof ins[0];

        char err[512] = {0};
        ktx_env *ei = ktx_env_create(1), *ej = ktx_env_create(1);
        ktx_env_set_opt(ej, KTX_OPT_JIT, 1);
        ktx_prog *pi = ktx_prog_load_mem(ei, buf, blen, NULL, 0, err, sizeof err);
        ktx_prog *pj = ktx_prog_load_mem(ej, buf, blen, NULL, 0, err, sizeof err);
        if (!pi || !pj) { CHECK(0, "fuzz prog %d load: %s", prog, err);
                          ktx_env_destroy(ei); ktx_env_destroy(ej); continue; }
        CHECK(ktx_prog_is_jitted(pj), "fuzz prog %d compiles", prog);
        ktx_thread *ti = ktx_thread_create(ei, 0), *tj = ktx_thread_create(ej, 0);
        uint8_t pkt[PKT_CAP];
        uint64_t pr = 0x5EED + (uint64_t)prog;
        int bad = 0;
        for (int it = 0; it < niter && !bad; it++) {
            uint32_t len = tr_fill_packet(pkt, PKT_CAP,
                                          (uint32_t)(tr_xorshift64s(&pr) % 64),
                                          &pr, 128, 256);
            ktx_result ri = ktx_run(ti, pi, KTX_MODE_VANILLA, pkt, len, 0);
            ktx_result rj = ktx_run(tj, pj, KTX_MODE_VANILLA, pkt, len, 0);
            ktx_result gi = ktx_run(ti, pi, KTX_MODE_SFI, pkt, len, 0);
            ktx_result gj = ktx_run(tj, pj, KTX_MODE_SFI, pkt, len, 0);
            if (ri.status != rj.status || ri.verdict != rj.verdict ||
                gi.status != gj.status || gi.verdict != gj.verdict ||
                gi.fuel_used != gj.fuel_used) {
                CHECK(0, "fuzz prog %d iter %d: %llu/%llu (st %d/%d), "
                         "guarded %llu/%llu (st %d/%d fuel %llu/%llu)",
                      prog, it, (unsigned long long)ri.verdict,
                      (unsigned long long)rj.verdict, ri.status, rj.status,
                      (unsigned long long)gi.verdict,
                      (unsigned long long)gj.verdict, gi.status, gj.status,
                      (unsigned long long)gi.fuel_used,
                      (unsigned long long)gj.fuel_used);
                bad = 1;
            }
        }
        if (!bad) CHECK(1, "fuzz prog %d agrees over %d packets", prog, niter);
        ktx_thread_destroy(ti); ktx_thread_destroy(tj);
        ktx_prog_free(pi); ktx_prog_free(pj);
        ktx_env_destroy(ei); ktx_env_destroy(ej);
    }
#undef RND
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("== test_jit ==\n");
    if (!ktx_jit_available()) {
        printf("== test_jit: JIT unavailable on this platform, skipped ==\n");
        return 0;
    }
    static const char *progs[] = {
        "pktcount", "flowstats", "tokenbucket", "maglev", "ctnat",
        "ctnat_reader", "pktrewrite", "atomic_demo", "atomic_reader",
        "loopy", "firewall", "flowstats_c", "l4lb", "policy"
    };
    static const struct { ktx_mode m; const char *n; } modes[] = {
        { KTX_MODE_VANILLA, "vanilla" }, { KTX_MODE_SFI, "sfi" },
        { KTX_MODE_TX, "tx" }, { KTX_MODE_TX_ELIDE, "tx-elide" },
        { KTX_MODE_2PL, "2pl" },
        { KTX_MODE_P2PL, "p2pl" },
        { KTX_MODE_COARSE, "coarse" }
    };
    for (size_t p = 0; p < sizeof progs / sizeof progs[0]; p++)
        for (size_t m = 0; m < sizeof modes / sizeof modes[0]; m++)
            run_pair(progs[p], modes[m].m, modes[m].n, 20000, 65536);
    fuzz_opcodes(24, 200);
    /* fuel-abort paths: a budget tight enough to trap mid-program */
    for (size_t p = 0; p < sizeof progs / sizeof progs[0]; p++)
        run_pair(progs[p], KTX_MODE_TX, "tx(low-fuel)", 20000, 24);
    printf("== test_jit: %d checks, %d failures ==\n", checks, failures);
    return failures ? 1 : 0;
}
