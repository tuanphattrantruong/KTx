/* test_vm.c — VM unit tests: golden encoding vectors (DESIGN §1.1),
 * ALU/JMP semantics, guard traps, fuel accounting, decode validation,
 * d_vanilla vs d_guarded behavioral equivalence.
 * Self-sufficient: programs are built with KTX_INSN and loaded via
 * ktx_prog_load_mem (no dependency on tools/asm.py).
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

/* ---------- kbin image builder ---------- */

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

static ktx_prog *load_prog(ktx_env *e, const struct ktx_map_desc *maps,
                           uint32_t n_maps, const struct ktx_insn *ins,
                           uint32_t n_insns, char *errbuf, size_t errlen) {
    uint8_t buf[8192];
    size_t n = build_kbin(buf, sizeof(buf), maps, n_maps, ins, n_insns, 0);
    if (!n) return NULL;
    return ktx_prog_load_mem(e, buf, n, NULL, 0, errbuf, errlen);
}

/* Run a mapless program once on a fresh thread. */
static ktx_result run1(ktx_env *e, const struct ktx_insn *ins, uint32_t n,
                       ktx_mode mode, uint8_t *pkt, uint32_t plen,
                       int64_t fuel) {
    ktx_result res = { KTX_ABORT_HELPER, 2, 0, 0 };
    char err[256];
    ktx_prog *p = load_prog(e, NULL, 0, ins, n, err, sizeof(err));
    if (!p) {
        printf("  (load failed: %s)\n", err);
        return res;
    }
    ktx_thread *t = ktx_thread_create(e, 0);
    res = ktx_run(t, p, mode, pkt, plen, fuel);
    ktx_thread_destroy(t);
    ktx_prog_free(p);
    return res;
}

/* Expect load failure. */
static int expect_reject(ktx_env *e, const struct ktx_map_desc *maps,
                         uint32_t n_maps, const struct ktx_insn *ins,
                         uint32_t n_insns) {
    char err[256] = "";
    ktx_prog *p = load_prog(e, maps, n_maps, ins, n_insns, err, sizeof(err));
    if (p) {
        ktx_prog_free(p);
        return 0;
    }
    return err[0] != 0;                  /* message must be present */
}

/* ---------- 1. golden encoding vectors ---------- */

static void test_golden(void) {
    struct { struct ktx_insn in; uint8_t exp[8]; const char *name; } G[] = {
        { KTX_INSN(0xb7, 1, 0, 0, 7),
          { 0xb7, 0x01, 0, 0, 0x07, 0, 0, 0 }, "mov r1, 7" },
        { KTX_INSN(0x0f, 2, 3, 0, 0),
          { 0x0f, 0x32, 0, 0, 0, 0, 0, 0 }, "add r2, r3" },
        { KTX_INSN(0x61, 0, 1, 16, 0),
          { 0x61, 0x10, 0x10, 0, 0, 0, 0, 0 }, "ldxw r0, [r1+16]" },
        { KTX_INSN(0x15, 0, 0, 5, 0),
          { 0x15, 0x00, 0x05, 0, 0, 0, 0, 0 }, "jeq r0, 0, +5" },
        { KTX_INSN(0x85, 0, 0, 0, 1),
          { 0x85, 0x00, 0, 0, 0x01, 0, 0, 0 }, "call 1" },
        { KTX_INSN(0x95, 0, 0, 0, 0),
          { 0x95, 0, 0, 0, 0, 0, 0, 0 }, "exit" },
        { KTX_INSN(0x7b, 10, 7, -8, 0),
          { 0x7b, 0x7a, 0xf8, 0xff, 0, 0, 0, 0 }, "stxdw [r10-8], r7" },
        { KTX_INSN(0x18, 1, 1, 0, 0),
          { 0x18, 0x11, 0, 0, 0, 0, 0, 0 }, "lddw r1, map 0 (slot 1)" },
        { KTX_INSN(0, 0, 0, 0, 0),
          { 0, 0, 0, 0, 0, 0, 0, 0 }, "lddw r1, map 0 (slot 2)" },
    };
    for (size_t i = 0; i < sizeof(G) / sizeof(G[0]); i++)
        CHECK(memcmp(&G[i].in, G[i].exp, 8) == 0,
              "golden bytes: %s", G[i].name);
}

/* ---------- 2. ALU semantics ---------- */

static void test_alu(ktx_env *e) {
    uint8_t pkt[64] = { 0 };

    { /* div by zero -> dst = 0 (64-bit X form) */
        struct ktx_insn P[] = {
            KTX_INSN(0xb7, 0, 0, 0, 42),
            KTX_INSN(0xb7, 1, 0, 0, 0),
            KTX_INSN(0x3f, 0, 1, 0, 0),      /* div r0, r1 */
            KTX_INSN(0x95, 0, 0, 0, 0),
        };
        ktx_result r = run1(e, P, 4, KTX_MODE_VANILLA, pkt, 64, 0);
        CHECK(r.status == KTX_OK && r.verdict == 0, "div64 by zero -> 0");
    }
    { /* mod by zero -> dst unchanged */
        struct ktx_insn P[] = {
            KTX_INSN(0xb7, 0, 0, 0, 42),
            KTX_INSN(0xb7, 1, 0, 0, 0),
            KTX_INSN(0x9f, 0, 1, 0, 0),      /* mod r0, r1 */
            KTX_INSN(0x95, 0, 0, 0, 0),
        };
        ktx_result r = run1(e, P, 4, KTX_MODE_VANILLA, pkt, 64, 0);
        CHECK(r.status == KTX_OK && r.verdict == 42,
              "mod64 by zero -> unchanged");
    }
    { /* div32 by zero and mod32 by zero */
        struct ktx_insn P[] = {
            KTX_INSN(0xb7, 0, 0, 0, 7),
            KTX_INSN(0x34, 0, 0, 0, 0),      /* div32 r0, 0 -> 0 */
            KTX_INSN(0x07, 0, 0, 0, 9),      /* r0 = 9 */
            KTX_INSN(0x94, 0, 0, 0, 0),      /* mod32 r0, 0 -> unchanged */
            KTX_INSN(0x95, 0, 0, 0, 0),
        };
        ktx_result r = run1(e, P, 5, KTX_MODE_VANILLA, pkt, 64, 0);
        CHECK(r.status == KTX_OK && r.verdict == 9,
              "div32/mod32 by zero semantics");
    }
    { /* shift masking: lsh by 64 is masked to 0, by 65 to 1 */
        struct ktx_insn P[] = {
            KTX_INSN(0xb7, 0, 0, 0, 1),
            KTX_INSN(0x67, 0, 0, 0, 64),     /* lsh r0, 64 -> no-op */
            KTX_INSN(0x67, 0, 0, 0, 65),     /* lsh r0, 65 -> <<1 */
            KTX_INSN(0x95, 0, 0, 0, 0),
        };
        ktx_result r = run1(e, P, 4, KTX_MODE_VANILLA, pkt, 64, 0);
        CHECK(r.status == KTX_OK && r.verdict == 2,
              "shift amounts masked & 63");
    }
    { /* lsh32 masks & 31 */
        struct ktx_insn P[] = {
            KTX_INSN(0xb7, 0, 0, 0, 3),
            KTX_INSN(0x64, 0, 0, 0, 33),     /* lsh32 r0, 33 -> <<1 */
            KTX_INSN(0x95, 0, 0, 0, 0),
        };
        ktx_result r = run1(e, P, 3, KTX_MODE_VANILLA, pkt, 64, 0);
        CHECK(r.status == KTX_OK && r.verdict == 6, "lsh32 masked & 31");
    }
    { /* ALU32 zero-extends: high 32 bits cleared */
        struct ktx_insn P[] = {
            KTX_INSN(0x18, 0, 0, 0, (int32_t)0x00000005),  /* lddw */
            KTX_INSN(0, 0, 0, 0, (int32_t)0xffffffff),     /* hi=ffffffff */
            KTX_INSN(0x04, 0, 0, 0, 1),      /* add32 r0, 1 -> 6, zext */
            KTX_INSN(0x95, 0, 0, 0, 0),
        };
        ktx_result r = run1(e, P, 4, KTX_MODE_VANILLA, pkt, 64, 0);
        CHECK(r.status == KTX_OK && r.verdict == 6, "ALU32 zero-extends");
    }
    { /* mov32 from reg zero-extends */
        struct ktx_insn P[] = {
            KTX_INSN(0x18, 1, 0, 0, (int32_t)0x000000ff),
            KTX_INSN(0, 0, 0, 0, (int32_t)0xdeadbeef),
            KTX_INSN(0xbc, 0, 1, 0, 0),      /* mov32 r0, r1 */
            KTX_INSN(0x95, 0, 0, 0, 0),
        };
        ktx_result r = run1(e, P, 4, KTX_MODE_VANILLA, pkt, 64, 0);
        CHECK(r.status == KTX_OK && r.verdict == 0xff,
              "mov32 zero-extends");
    }
    { /* neg + arsh */
        struct ktx_insn P[] = {
            KTX_INSN(0xb7, 0, 0, 0, 5),
            KTX_INSN(0x87, 0, 0, 0, 0),      /* neg r0 -> -5 */
            KTX_INSN(0xc7, 0, 0, 0, 1),      /* arsh r0, 1 -> -3 */
            KTX_INSN(0x95, 0, 0, 0, 0),
        };
        ktx_result r = run1(e, P, 4, KTX_MODE_VANILLA, pkt, 64, 0);
        CHECK(r.status == KTX_OK && r.verdict == (uint64_t)(int64_t)-3,
              "neg64 + arsh64 signed semantics");
    }
    { /* lddw full 64-bit immediate */
        struct ktx_insn P[] = {
            KTX_INSN(0x18, 0, 0, 0, (int32_t)0x9abcdef0),
            KTX_INSN(0, 0, 0, 0, (int32_t)0x12345678),
            KTX_INSN(0x95, 0, 0, 0, 0),
        };
        ktx_result r = run1(e, P, 3, KTX_MODE_VANILLA, pkt, 64, 0);
        CHECK(r.status == KTX_OK && r.verdict == 0x123456789abcdef0ULL,
              "LD_IMM64 loads 64-bit value");
    }
}

/* ---------- 3. jumps ---------- */

static void test_jumps(ktx_env *e) {
    uint8_t pkt[64] = { 0 };

    { /* unsigned jgt on -1 (huge) */
        struct ktx_insn P[] = {
            KTX_INSN(0xb7, 0, 0, 0, 1),
            KTX_INSN(0xb7, 1, 0, 0, -1),
            KTX_INSN(0x25, 1, 0, 1, 5),      /* jgt r1, 5, +1 (taken) */
            KTX_INSN(0xb7, 0, 0, 0, 0),
            KTX_INSN(0x95, 0, 0, 0, 0),
        };
        ktx_result r = run1(e, P, 5, KTX_MODE_VANILLA, pkt, 64, 0);
        CHECK(r.status == KTX_OK && r.verdict == 1,
              "jgt is unsigned (-1 > 5)");
    }
    { /* signed jsgt: -1 > -5 taken */
        struct ktx_insn P[] = {
            KTX_INSN(0xb7, 0, 0, 0, 1),
            KTX_INSN(0xb7, 1, 0, 0, -1),
            KTX_INSN(0x65, 1, 0, 1, -5),     /* jsgt r1, -5, +1 */
            KTX_INSN(0xb7, 0, 0, 0, 0),
            KTX_INSN(0x95, 0, 0, 0, 0),
        };
        ktx_result r = run1(e, P, 5, KTX_MODE_VANILLA, pkt, 64, 0);
        CHECK(r.status == KTX_OK && r.verdict == 1,
              "jsgt is signed (-1 > -5)");
    }
    { /* jmp32 compares low 32 bits only */
        struct ktx_insn P[] = {
            KTX_INSN(0xb7, 0, 0, 0, 1),
            KTX_INSN(0x18, 1, 0, 0, (int32_t)0x00000005),
            KTX_INSN(0, 0, 0, 0, (int32_t)0xffffffff),
            KTX_INSN(0x16, 1, 0, 1, 5),      /* jeq32 r1, 5, +1 (taken) */
            KTX_INSN(0xb7, 0, 0, 0, 0),
            KTX_INSN(0x95, 0, 0, 0, 0),
        };
        ktx_result r = run1(e, P, 6, KTX_MODE_VANILLA, pkt, 64, 0);
        CHECK(r.status == KTX_OK && r.verdict == 1,
              "jeq32 compares low 32 bits");
    }
    { /* backward jump: loop 5 times */
        struct ktx_insn P[] = {
            KTX_INSN(0xb7, 0, 0, 0, 0),
            KTX_INSN(0xb7, 1, 0, 0, 5),
            KTX_INSN(0x07, 0, 0, 0, 1),      /* L: add r0, 1 */
            KTX_INSN(0x17, 1, 0, 0, 1),      /* sub r1, 1 */
            KTX_INSN(0x55, 1, 0, -3, 0),     /* jne r1, 0, L */
            KTX_INSN(0x95, 0, 0, 0, 0),
        };
        ktx_result r = run1(e, P, 6, KTX_MODE_VANILLA, pkt, 64, 0);
        CHECK(r.status == KTX_OK && r.verdict == 5,
              "backward jump loop (5 iters)");
    }
    { /* jset */
        struct ktx_insn P[] = {
            KTX_INSN(0xb7, 0, 0, 0, 1),
            KTX_INSN(0xb7, 1, 0, 0, 0x0c),
            KTX_INSN(0x45, 1, 0, 1, 0x04),   /* jset r1, 4, +1 (taken) */
            KTX_INSN(0xb7, 0, 0, 0, 0),
            KTX_INSN(0x95, 0, 0, 0, 0),
        };
        ktx_result r = run1(e, P, 5, KTX_MODE_VANILLA, pkt, 64, 0);
        CHECK(r.status == KTX_OK && r.verdict == 1, "jset bit test");
    }
}

/* ---------- 4. guards ---------- */

static void test_guards(ktx_env *e) {
    { /* out-of-bounds stack store traps in sfi */
        struct ktx_insn P[] = {
            KTX_INSN(0x7b, 10, 0, -520, 0),  /* stxdw [r10-520], r0 */
            KTX_INSN(0xb7, 0, 0, 0, 3),
            KTX_INSN(0x95, 0, 0, 0, 0),
        };
        uint8_t pkt[64] = { 0 };
        ktx_result r = run1(e, P, 3, KTX_MODE_SFI, pkt, 64, 0);
        CHECK(r.status == KTX_ABORT_GUARD && r.verdict == KTX_VERDICT_PASS,
              "OOB stack store -> ABORT_GUARD, verdict PASS");
    }
    { /* in-bounds stack store+load works in sfi and vanilla */
        struct ktx_insn P[] = {
            KTX_INSN(0xb7, 1, 0, 0, 77),
            KTX_INSN(0x7b, 10, 1, -8, 0),    /* stxdw [r10-8], r1 */
            KTX_INSN(0x79, 0, 10, -8, 0),    /* ldxdw r0, [r10-8] */
            KTX_INSN(0x95, 0, 0, 0, 0),
        };
        uint8_t pkt[64] = { 0 };
        ktx_result rv = run1(e, P, 4, KTX_MODE_VANILLA, pkt, 64, 0);
        ktx_result rs = run1(e, P, 4, KTX_MODE_SFI, pkt, 64, 0);
        CHECK(rv.status == KTX_OK && rv.verdict == 77 &&
              rs.status == KTX_OK && rs.verdict == 77,
              "stack spill/reload ok in vanilla+sfi");
    }
    { /* ctx is read-only: write traps in sfi */
        struct ktx_insn P[] = {
            KTX_INSN(0x62, 1, 0, 16, 99),    /* stw [r1+16], 99 */
            KTX_INSN(0xb7, 0, 0, 0, 2),
            KTX_INSN(0x95, 0, 0, 0, 0),
        };
        uint8_t pkt[64] = { 0 };
        ktx_result r = run1(e, P, 3, KTX_MODE_SFI, pkt, 64, 0);
        CHECK(r.status == KTX_ABORT_GUARD, "ctx write -> ABORT_GUARD (sfi)");
    }
    { /* direct packet store: OK in vanilla/sfi, trapped in tx */
        struct ktx_insn P[] = {
            KTX_INSN(0x79, 2, 1, 0, 0),      /* ldxdw r2, [r1+0] = data */
            KTX_INSN(0x72, 2, 0, 0, 0x55),   /* stb [r2+0], 0x55 */
            KTX_INSN(0xb7, 0, 0, 0, 2),
            KTX_INSN(0x95, 0, 0, 0, 0),
        };
        uint8_t pkt1[64] = { 0 }, pkt2[64] = { 0 }, pkt3[64] = { 0 };
        ktx_result rv = run1(e, P, 4, KTX_MODE_VANILLA, pkt1, 64, 0);
        ktx_result rs = run1(e, P, 4, KTX_MODE_SFI, pkt2, 64, 0);
        ktx_result rt = run1(e, P, 4, KTX_MODE_TX, pkt3, 64, 0);
        CHECK(rv.status == KTX_OK && pkt1[0] == 0x55,
              "direct pkt store ok in vanilla");
        CHECK(rs.status == KTX_OK && pkt2[0] == 0x55,
              "direct pkt store ok in sfi");
        CHECK(rt.status == KTX_ABORT_GUARD && pkt3[0] == 0,
              "direct pkt store in tx -> ABORT_GUARD, pkt untouched");
    }
    { /* out-of-bounds packet read traps in sfi */
        struct ktx_insn P[] = {
            KTX_INSN(0x79, 2, 1, 0, 0),
            KTX_INSN(0x71, 0, 2, 64, 0),     /* ldxb r0, [r2+64] (OOB) */
            KTX_INSN(0x95, 0, 0, 0, 0),
        };
        uint8_t pkt[64] = { 0 };
        ktx_result r = run1(e, P, 3, KTX_MODE_SFI, pkt, 64, 0);
        CHECK(r.status == KTX_ABORT_GUARD, "OOB pkt read -> ABORT_GUARD");
    }
    { /* map-value region: in-bounds store ok, OOB store traps (sfi) */
        struct ktx_map_desc md = { KTX_MAP_HASH, 8, 16, 64, "gmap" };
        struct ktx_insn P[] = {
            KTX_INSN(0x7b, 10, 0, -8, 0),    /* key 0 on stack (r0=0) */
            KTX_INSN(0x18, 1, 1, 0, 0),      /* lddw r1, map 0 */
            KTX_INSN(0, 0, 0, 0, 0),
            KTX_INSN(0xbf, 2, 10, 0, 0),     /* r2 = r10 */
            KTX_INSN(0x07, 2, 0, 0, -8),     /* r2 -= 8 */
            KTX_INSN(0x85, 0, 0, 0, 1),      /* call map_lookup */
            KTX_INSN(0x55, 0, 0, 1, 0),      /* jne r0, 0, +1 */
            KTX_INSN(0x95, 0, 0, 0, 0),      /* miss: verdict 0 */
            KTX_INSN(0x7a, 0, 0, 8, 1),      /* stdw [r0+8], 1 (in) */
            KTX_INSN(0xb7, 0, 0, 0, 7),
            KTX_INSN(0x95, 0, 0, 0, 0),
        };
        struct ktx_insn BAD[sizeof(P) / sizeof(P[0])];
        memcpy(BAD, P, sizeof(P));
        BAD[8] = (struct ktx_insn)KTX_INSN(0x7a, 0, 0, 24, 1); /* OOB */

        uint8_t buf[4096];
        size_t n = build_kbin(buf, sizeof(buf), &md, 1, P,
                              sizeof(P) / sizeof(P[0]), 0);
        char err[256];
        ktx_prog *pg = ktx_prog_load_mem(e, buf, n, NULL, 0, err,
                                         sizeof(err));
        CHECK(pg != NULL, "map-guard program loads (%s)", err);
        size_t n2 = build_kbin(buf, sizeof(buf), &md, 1, BAD,
                               sizeof(P) / sizeof(P[0]), 0);
        ktx_prog *pb = ktx_prog_load_mem(e, buf, n2, NULL, 0, err,
                                         sizeof(err));
        CHECK(pb != NULL, "map-guard OOB program loads (%s)", err);
        if (pg && pb) {
            int mid = ktx_map_id(e, "gmap");
            uint64_t key = 0;
            uint8_t val[16] = { 0 };
            ktx_map_update(e, mid, &key, val);
            uint8_t pkt[64] = { 0 };
            ktx_thread *t = ktx_thread_create(e, 0);
            ktx_result r1 = ktx_run(t, pg, KTX_MODE_SFI, pkt, 64, 0);
            CHECK(r1.status == KTX_OK && r1.verdict == 7,
                  "in-bounds mapval store ok (sfi)");
            ktx_result r2 = ktx_run(t, pb, KTX_MODE_SFI, pkt, 64, 0);
            CHECK(r2.status == KTX_ABORT_GUARD,
                  "OOB mapval store -> ABORT_GUARD (sfi)");
            ktx_thread_destroy(t);
        }
        if (pg) ktx_prog_free(pg);
        if (pb) ktx_prog_free(pb);
    }
}

/* ---------- 5. fuel ---------- */

static void test_fuel(ktx_env *e) {
    uint8_t pkt[64] = { 0 };
    struct ktx_insn P[] = {                  /* exactly 5 instructions */
        KTX_INSN(0xb7, 0, 0, 0, 1),
        KTX_INSN(0xb7, 1, 0, 0, 2),
        KTX_INSN(0xb7, 2, 0, 0, 3),
        KTX_INSN(0xb7, 0, 0, 0, 9),
        KTX_INSN(0x95, 0, 0, 0, 0),
    };
    ktx_result ok = run1(e, P, 5, KTX_MODE_SFI, pkt, 64, 5);
    CHECK(ok.status == KTX_OK && ok.verdict == 9 && ok.fuel_used == 5,
          "fuel == n_insns completes (fuel_used=%llu)",
          (unsigned long long)ok.fuel_used);
    ktx_result ab = run1(e, P, 5, KTX_MODE_SFI, pkt, 64, 4);
    CHECK(ab.status == KTX_ABORT_FUEL && ab.verdict == KTX_VERDICT_PASS,
          "fuel == n_insns-1 -> ABORT_FUEL at exact budget");
    ktx_result dv = run1(e, P, 5, KTX_MODE_VANILLA, pkt, 64, 1);
    CHECK(dv.status == KTX_OK && dv.fuel_used == 0,
          "vanilla ignores fuel (nofuel loop)");

    { /* infinite loop burns the whole budget */
        struct ktx_insn L[] = {
            KTX_INSN(0x05, 0, 0, -1, 0),     /* ja self */
        };
        ktx_result r = run1(e, L, 1, KTX_MODE_SFI, pkt, 64, 100);
        CHECK(r.status == KTX_ABORT_FUEL && r.fuel_used == 100,
              "infinite loop -> ABORT_FUEL after exactly fuel insns");
    }
    { /* fuel <= 0 selects the default 65536 */
        struct ktx_insn L[] = {              /* 20000-iteration loop */
            KTX_INSN(0xb7, 1, 0, 0, 20000),
            KTX_INSN(0x17, 1, 0, 0, 1),
            KTX_INSN(0x55, 1, 0, -2, 0),
            KTX_INSN(0xb7, 0, 0, 0, 4),
            KTX_INSN(0x95, 0, 0, 0, 0),
        };
        ktx_result r = run1(e, L, 5, KTX_MODE_SFI, pkt, 64, 0);
        CHECK(r.status == KTX_OK && r.verdict == 4 &&
              r.fuel_used == 3 + 2 * 20000,
              "default fuel 65536 covers 40k-insn run (used=%llu)",
              (unsigned long long)r.fuel_used);
    }
}

/* ---------- 6. decode validation ---------- */

static void test_decode_rejects(ktx_env *e) {
    { /* unknown opcode */
        struct ktx_insn P[] = { KTX_INSN(0xff, 0, 0, 0, 0),
                                KTX_INSN(0x95, 0, 0, 0, 0) };
        CHECK(expect_reject(e, NULL, 0, P, 2), "reject unknown opcode 0xff");
    }
    { /* write to r10 */
        struct ktx_insn P[] = { KTX_INSN(0xb7, 10, 0, 0, 5),
                                KTX_INSN(0x95, 0, 0, 0, 0) };
        CHECK(expect_reject(e, NULL, 0, P, 2), "reject mov to r10");
    }
    { /* ldx into r10 */
        struct ktx_insn P[] = { KTX_INSN(0x79, 10, 1, 0, 0),
                                KTX_INSN(0x95, 0, 0, 0, 0) };
        CHECK(expect_reject(e, NULL, 0, P, 2), "reject ldxdw into r10");
    }
    { /* jump target out of range */
        struct ktx_insn P[] = { KTX_INSN(0x15, 0, 0, 10, 0),
                                KTX_INSN(0x95, 0, 0, 0, 0) };
        CHECK(expect_reject(e, NULL, 0, P, 2), "reject OOB jump target");
    }
    { /* program falls off the end */
        struct ktx_insn P[] = { KTX_INSN(0xb7, 0, 0, 0, 0) };
        CHECK(expect_reject(e, NULL, 0, P, 1),
              "reject program not ending in exit/ja");
    }
    { /* LD_IMM64 missing second slot */
        struct ktx_insn P[] = { KTX_INSN(0x18, 0, 0, 0, 1) };
        CHECK(expect_reject(e, NULL, 0, P, 1),
              "reject truncated LD_IMM64");
    }
    { /* LD_IMM64 second slot not all-zero */
        struct ktx_insn P[] = { KTX_INSN(0x18, 0, 0, 0, 1),
                                KTX_INSN(0, 1, 0, 0, 0),
                                KTX_INSN(0x95, 0, 0, 0, 0) };
        CHECK(expect_reject(e, NULL, 0, P, 3),
              "reject LD_IMM64 with dirty second slot");
    }
    { /* jump into the middle of LD_IMM64 */
        struct ktx_insn P[] = { KTX_INSN(0x05, 0, 0, 1, 0),
                                KTX_INSN(0x18, 0, 0, 0, 1),
                                KTX_INSN(0, 0, 0, 0, 0),
                                KTX_INSN(0x95, 0, 0, 0, 0) };
        CHECK(expect_reject(e, NULL, 0, P, 4),
              "reject jump into LD_IMM64 pair");
    }
    { /* map index out of range */
        struct ktx_map_desc md = { KTX_MAP_HASH, 8, 16, 64, "dmap" };
        struct ktx_insn P[] = { KTX_INSN(0x18, 1, 1, 0, 2),
                                KTX_INSN(0, 0, 0, 0, 0),
                                KTX_INSN(0x95, 0, 0, 0, 0) };
        CHECK(expect_reject(e, &md, 1, P, 3),
              "reject map index >= n_maps");
    }
    { /* unknown helper id */
        struct ktx_insn P[] = { KTX_INSN(0x85, 0, 0, 0, 99),
                                KTX_INSN(0x95, 0, 0, 0, 0) };
        CHECK(expect_reject(e, NULL, 0, P, 2), "reject unknown helper 99");
    }
    { /* truncated kbin / bad magic */
        struct ktx_insn P[] = { KTX_INSN(0x95, 0, 0, 0, 0) };
        uint8_t buf[4096];
        size_t n = build_kbin(buf, sizeof(buf), NULL, 0, P, 1, 0);
        char err[256] = "";
        ktx_prog *p = ktx_prog_load_mem(e, buf, n - 3, NULL, 0, err,
                                        sizeof(err));
        CHECK(p == NULL && err[0], "reject truncated kbin");
        if (p) ktx_prog_free(p);
        buf[0] = 'X';
        err[0] = 0;
        p = ktx_prog_load_mem(e, buf, n, NULL, 0, err, sizeof(err));
        CHECK(p == NULL && err[0], "reject bad magic");
        if (p) ktx_prog_free(p);
    }
}

/* ---------- 7. vanilla vs guarded behavioral equivalence ---------- */

static void test_equivalence(ktx_env *e) {
    struct ktx_insn P[] = {
        KTX_INSN(0x79, 2, 1, 0, 0),          /* r2 = data */
        KTX_INSN(0x61, 3, 1, 16, 0),         /* r3 = len */
        KTX_INSN(0x7b, 10, 3, -8, 0),        /* spill len */
        KTX_INSN(0x79, 4, 10, -8, 0),        /* reload */
        KTX_INSN(0x71, 5, 2, 0, 0),          /* pkt[0] */
        KTX_INSN(0x71, 0, 2, 63, 0),         /* pkt[63] */
        KTX_INSN(0x0f, 0, 5, 0, 0),          /* r0 += r5 */
        KTX_INSN(0x0f, 0, 4, 0, 0),          /* r0 += r4 */
        KTX_INSN(0x95, 0, 0, 0, 0),
    };
    uint8_t pkt[64];
    for (int i = 0; i < 64; i++) pkt[i] = (uint8_t)(i * 7 + 3);
    uint64_t expect = (uint64_t)pkt[0] + pkt[63] + 64;
    ktx_result rv = run1(e, P, 9, KTX_MODE_VANILLA, pkt, 64, 0);
    ktx_result rs = run1(e, P, 9, KTX_MODE_SFI, pkt, 64, 0);
    CHECK(rv.status == KTX_OK && rs.status == KTX_OK &&
          rv.verdict == expect && rs.verdict == expect,
          "d_vanilla and d_guarded agree (verdict %llu)",
          (unsigned long long)expect);
    CHECK(rv.fuel_used == 0 && rs.fuel_used == 9,
          "fuel accounting: vanilla 0, sfi 9 (got %llu)",
          (unsigned long long)rs.fuel_used);
}

/* ---------- 8. stats counters ---------- */

static void test_stats(ktx_env *e) {
    struct ktx_insn OK_P[] = { KTX_INSN(0xb7, 0, 0, 0, 2),
                               KTX_INSN(0x95, 0, 0, 0, 0) };
    struct ktx_insn BAD_P[] = { KTX_INSN(0x7b, 10, 0, -520, 0),
                                KTX_INSN(0x95, 0, 0, 0, 0) };
    char err[256];
    ktx_prog *pok = load_prog(e, NULL, 0, OK_P, 2, err, sizeof(err));
    ktx_prog *pbad = load_prog(e, NULL, 0, BAD_P, 2, err, sizeof(err));
    ktx_thread *t = ktx_thread_create(e, 0);
    uint8_t pkt[64] = { 0 };
    ktx_thread_stats_reset(t);
    ktx_run(t, pok, KTX_MODE_SFI, pkt, 64, 0);
    ktx_run(t, pok, KTX_MODE_SFI, pkt, 64, 0);
    ktx_run(t, pbad, KTX_MODE_SFI, pkt, 64, 0);
    ktx_run(t, pok, KTX_MODE_SFI, pkt, 64, 1);   /* fuel abort */
    ktx_thread_stats st;
    ktx_thread_stats_get(t, &st);
    CHECK(st.commits == 2 && st.aborts_guard == 1 && st.aborts_fuel == 1 &&
          st.aborts_helper == 0,
          "thread stats: 2 commits, 1 guard, 1 fuel");
    ktx_thread_stats_reset(t);
    ktx_thread_stats_get(t, &st);
    CHECK(st.commits == 0 && st.aborts_guard == 0, "stats reset to zero");
    ktx_thread_destroy(t);
    ktx_prog_free(pok);
    ktx_prog_free(pbad);
}

int main(void) {
    printf("== test_vm ==\n");
    test_golden();

    ktx_env *e = ktx_env_create(2);
    if (!e) {
        printf("FAIL ktx_env_create\n");
        return 1;
    }
    test_alu(e);
    test_jumps(e);
    test_guards(e);
    test_fuel(e);
    test_decode_rejects(e);
    test_equivalence(e);
    test_stats(e);
    ktx_env_destroy(e);

    printf("== test_vm: %d checks, %d failures ==\n", checks, failures);
    return failures ? 1 : 0;
}
