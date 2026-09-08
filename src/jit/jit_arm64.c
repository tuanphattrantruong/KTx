/* jit_arm64.c — a straightforward template compiler from the KTx decoded
 * instruction stream to AArch64 machine code.
 *
 * Register file
 *   r0..r9   -> x19..x28   (callee-saved: survive helper calls untouched)
 *   r10      -> a frame slot, materialised on demand (it is read-only and
 *               only ever used as a stack base)
 *   fuel     -> x29        (fuelled variant only; the *only* difference
 *                           between the two variants is the fuel check)
 *   ex       -> a frame slot
 *   temps    -> x9..x17    (caller-saved; never live across a call)
 *
 * Frame (48 B): [sp+0]=ex, [sp+8]=r10, [sp+16..]=scratch.
 *
 * This is deliberately a *template* compiler, not an optimising one: one
 * fixed sequence per instruction, no register allocation beyond the fixed
 * map, no peepholes.  It is fast enough to make the body cost realistic
 * and simple enough to be checked against the interpreter instruction by
 * instruction (see bin/test_jit).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include "jit.h"
#include "../ktx/ktx_internal.h"

#if defined(__APPLE__)
#include <libkern/OSCacheControl.h>
#include <pthread.h>
#endif

#if !defined(__aarch64__) && !defined(__arm64__)
int ktx_jit_available(void) { return 0; }
ktx_jitfn ktx_jit_compile(const ktx_dinsn *c, uint32_t n, int f,
                          size_t *sz, size_t *eb, char *err, size_t el) {
    (void)c; (void)n; (void)f; (void)sz; (void)eb;
    if (err && el) snprintf(err, el, "JIT: unsupported architecture");
    return NULL;
}
void ktx_jit_free(ktx_jitfn fn, size_t sz) { (void)fn; (void)sz; }
#else

/* ------------------------------------------------------------------ */
/* buffer                                                              */
/* ------------------------------------------------------------------ */
typedef struct {
    uint32_t *buf;
    uint32_t  n, cap;
    int       oom;
} emit_t;

static void em(emit_t *e, uint32_t w) {
    if (e->n == e->cap) {
        uint32_t nc = e->cap ? e->cap * 2 : 1024;
        uint32_t *nb = realloc(e->buf, (size_t)nc * 4);
        if (!nb) { e->oom = 1; return; }
        e->buf = nb;
        e->cap = nc;
    }
    e->buf[e->n++] = w;
}

/* register numbers */
#define XZR 31
#define SP  31
static const uint8_t R[11] = { 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 0xff };
#define XFUEL 29
#define T0 9
#define T1 10
#define T2 11
#define T3 12
#define T4 13
#define T5 14
#define T6 15
#define T7 16
#define T8 17

#define EX_SLOT   0     /* [sp+0]  ktx_exec *  */
#define R10_SLOT  8     /* [sp+8]  eBPF r10    */
#define FRAME     48

/* ------------------------------------------------------------------ */
/* instruction encoders                                                */
/* ------------------------------------------------------------------ */
static void movz(emit_t *e, int rd, uint16_t imm, int hw) {
    em(e, 0xD2800000u | ((uint32_t)hw << 21) | ((uint32_t)imm << 5) | rd);
}
static void movk(emit_t *e, int rd, uint16_t imm, int hw) {
    em(e, 0xF2800000u | ((uint32_t)hw << 21) | ((uint32_t)imm << 5) | rd);
}
static void mov_imm64(emit_t *e, int rd, uint64_t v) {
    if (v == 0) { movz(e, rd, 0, 0); return; }
    int first = 1;
    for (int h = 0; h < 4; h++) {
        uint16_t part = (uint16_t)((v >> (16 * h)) & 0xffff);
        if (!part && !(first && h == 3)) continue;
        if (first) { movz(e, rd, part, h); first = 0; }
        else movk(e, rd, part, h);
    }
    if (first) movz(e, rd, 0, 0);
}
/* ADD/SUB immediate (12-bit, optionally << 12) */
static int addsub_imm(emit_t *e, int sf, int sub, int setflags, int rd,
                      int rn, uint64_t imm) {
    uint32_t base = (sub ? 0x51000000u : 0x11000000u)
                    | (sf ? 0x80000000u : 0u)
                    | (setflags ? 0x20000000u : 0u);
    if (imm <= 0xfff) {
        em(e, base | ((uint32_t)imm << 10) | (rn << 5) | rd);
        return 1;
    }
    if ((imm & 0xfff) == 0 && (imm >> 12) <= 0xfff) {
        em(e, base | (1u << 22) | ((uint32_t)(imm >> 12) << 10) | (rn << 5) | rd);
        return 1;
    }
    return 0;
}
static void add_reg(emit_t *e, int sf, int rd, int rn, int rm) {
    em(e, (sf ? 0x8B000000u : 0x0B000000u) | (rm << 16) | (rn << 5) | rd);
}
static void sub_reg(emit_t *e, int sf, int rd, int rn, int rm) {
    em(e, (sf ? 0xCB000000u : 0x4B000000u) | (rm << 16) | (rn << 5) | rd);
}
static void subs_reg(emit_t *e, int sf, int rd, int rn, int rm) {
    em(e, (sf ? 0xEB000000u : 0x6B000000u) | (rm << 16) | (rn << 5) | rd);
}
static void ands_reg(emit_t *e, int sf, int rd, int rn, int rm) {
    em(e, (sf ? 0xEA000000u : 0x6A000000u) | (rm << 16) | (rn << 5) | rd);
}
static void orr_reg(emit_t *e, int sf, int rd, int rn, int rm) {
    em(e, (sf ? 0xAA000000u : 0x2A000000u) | (rm << 16) | (rn << 5) | rd);
}
static void and_reg(emit_t *e, int sf, int rd, int rn, int rm) {
    em(e, (sf ? 0x8A000000u : 0x0A000000u) | (rm << 16) | (rn << 5) | rd);
}
static void eor_reg(emit_t *e, int sf, int rd, int rn, int rm) {
    em(e, (sf ? 0xCA000000u : 0x4A000000u) | (rm << 16) | (rn << 5) | rd);
}
static void mov_reg(emit_t *e, int sf, int rd, int rm) {
    orr_reg(e, sf, rd, XZR, rm);
}
static void mul(emit_t *e, int sf, int rd, int rn, int rm) {
    em(e, (sf ? 0x9B000000u : 0x1B000000u) | (rm << 16) | (31u << 10)
          | (rn << 5) | rd);
}
static void msub(emit_t *e, int sf, int rd, int rn, int rm, int ra) {
    em(e, (sf ? 0x9B008000u : 0x1B008000u) | (rm << 16) | (ra << 10)
          | (rn << 5) | rd);
}
static void udiv(emit_t *e, int sf, int rd, int rn, int rm) {
    em(e, (sf ? 0x9AC00800u : 0x1AC00800u) | (rm << 16) | (rn << 5) | rd);
}
static void shiftv(emit_t *e, int sf, int op, int rd, int rn, int rm) {
    /* op: 0 lsl, 1 lsr, 2 asr */
    uint32_t o = 0x2000u + (uint32_t)op * 0x400u;
    em(e, (sf ? 0x9AC00000u : 0x1AC00000u) | o | (rm << 16) | (rn << 5) | rd);
}
static void ldr_x(emit_t *e, int rt, int rn, uint32_t off) {   /* off bytes */
    em(e, 0xF9400000u | ((off / 8) << 10) | (rn << 5) | rt);
}
static void str_x(emit_t *e, int rt, int rn, uint32_t off) {
    em(e, 0xF9000000u | ((off / 8) << 10) | (rn << 5) | rt);
}
static void ldr_w(emit_t *e, int rt, int rn, uint32_t off) {
    em(e, 0xB9400000u | ((off / 4) << 10) | (rn << 5) | rt);
}
static void str_w(emit_t *e, int rt, int rn, uint32_t off) {
    em(e, 0xB9000000u | ((off / 4) << 10) | (rn << 5) | rt);
}
static void ldrb_(emit_t *e, int rt, int rn, uint32_t off) {
    em(e, 0x39400000u | (off << 10) | (rn << 5) | rt);
}
static void strb_(emit_t *e, int rt, int rn, uint32_t off) {
    em(e, 0x39000000u | (off << 10) | (rn << 5) | rt);
}
static void ldrh_(emit_t *e, int rt, int rn, uint32_t off) {
    em(e, 0x79400000u | ((off / 2) << 10) | (rn << 5) | rt);
}
static void strh_(emit_t *e, int rt, int rn, uint32_t off) {
    em(e, 0x79000000u | ((off / 2) << 10) | (rn << 5) | rt);
}
static void stp_pre(emit_t *e, int t1, int t2, int rn, int off) {
    em(e, 0xA9800000u | (((uint32_t)((off / 8) & 0x7f)) << 15) | (t2 << 10)
          | (rn << 5) | t1);
}
static void ldp_post(emit_t *e, int t1, int t2, int rn, int off) {
    em(e, 0xA8C00000u | (((uint32_t)((off / 8) & 0x7f)) << 15) | (t2 << 10)
          | (rn << 5) | t1);
}
static void stp_off(emit_t *e, int t1, int t2, int rn, int off) {
    em(e, 0xA9000000u | (((uint32_t)((off / 8) & 0x7f)) << 15) | (t2 << 10)
          | (rn << 5) | t1);
}
static void ldp_off(emit_t *e, int t1, int t2, int rn, int off) {
    em(e, 0xA9400000u | (((uint32_t)((off / 8) & 0x7f)) << 15) | (t2 << 10)
          | (rn << 5) | t1);
}
static void blr(emit_t *e, int rn)  { em(e, 0xD63F0000u | (rn << 5)); }
static void ret_(emit_t *e)         { em(e, 0xD65F03C0u); }
static uint32_t here(emit_t *e)     { return e->n; }
static void b_placeholder(emit_t *e){ em(e, 0x14000000u); }
static void bcond_placeholder(emit_t *e, int cond) {
    em(e, 0x54000000u | (uint32_t)cond);
}
static void patch_b(emit_t *e, uint32_t at, uint32_t target) {
    int32_t d = (int32_t)target - (int32_t)at;
    e->buf[at] = 0x14000000u | ((uint32_t)d & 0x03ffffffu);
}
static void patch_bcond(emit_t *e, uint32_t at, uint32_t target) {
    int32_t d = (int32_t)target - (int32_t)at;
    e->buf[at] = (e->buf[at] & 0xff00001fu) | (((uint32_t)d & 0x7ffffu) << 5);
}

/* condition codes */
enum { C_EQ = 0, C_NE = 1, C_HS = 2, C_LO = 3, C_MI = 4, C_PL = 5,
       C_HI = 8, C_LS = 9, C_GE = 10, C_LT = 11, C_GT = 12, C_LE = 13 };

/* ------------------------------------------------------------------ */
/* compile                                                             */
/* ------------------------------------------------------------------ */
struct fix { uint32_t at; uint32_t target_insn; int is_cond; };

/* offsets into ktx_exec, taken from the C struct so they cannot drift */
#define OFF_REGS      ((uint32_t)offsetof(ktx_exec, regs))
#define OFF_FUEL      ((uint32_t)offsetof(ktx_exec, fuel))
#define OFF_STATUS    ((uint32_t)offsetof(ktx_exec, status))
#define OFF_R0OUT     ((uint32_t)offsetof(ktx_exec, r0_out))
#define OFF_TX        ((uint32_t)offsetof(ktx_exec, tx))
#define OFF_REGIONS   ((uint32_t)offsetof(ktx_exec, regions))
#define OFF_NREGIONS  ((uint32_t)offsetof(ktx_exec, nregions))
#define OFF_TH        ((uint32_t)offsetof(ktx_exec, th))
#define OFF_PKT       ((uint32_t)offsetof(ktx_exec, pkt))
#define OFF_PKTLEN    ((uint32_t)offsetof(ktx_exec, pkt_len))
#define REGION_SZ     ((uint32_t)sizeof(ktx_region))

/* Restore the callee-saved file and return; x0 already holds the status. */
static void emit_epilogue(emit_t *e) {
    addsub_imm(e, 1, 0, 0, SP, SP, FRAME);
    ldp_off(e, 21, 22, SP, 16);
    ldp_off(e, 23, 24, SP, 32);
    ldp_off(e, 25, 26, SP, 48);
    ldp_off(e, 27, 28, SP, 64);
    ldp_off(e, 29, 30, SP, 80);
    ldp_post(e, 19, 20, SP, 96);
    ret_(e);
}

/* Load eBPF r10 (frame pointer) into a temp. */
static void get_r10(emit_t *e, int rt) { ldr_x(e, rt, SP, R10_SLOT); }
static void get_ex(emit_t *e, int rt)  { ldr_x(e, rt, SP, EX_SLOT); }

/* Inline SFI bounds guard on address in `ra` for `size` bytes.
 * Branches to the guard-abort trampoline when no region grants it. */
static void emit_guard(emit_t *e, int ra, uint32_t size, int write,
                       struct fix *fixes, int *nfix, uint32_t abort_id) {
    get_ex(e, T1);
    ldr_w(e, T2, T1, OFF_NREGIONS);              /* w11 = nregions   */
    if (!addsub_imm(e, 1, 0, 0, T3, T1, OFF_REGIONS)) {
        mov_imm64(e, T4, OFF_REGIONS);
        add_reg(e, 1, T3, T1, T4);               /* x12 = &regions[0] */
    }
    movz(e, T4, 0, 0);                           /* w13 = i          */
    uint32_t loop = here(e);
    subs_reg(e, 0, XZR, T4, T2);                 /* cmp i, n          */
    uint32_t to_fail1 = here(e); bcond_placeholder(e, C_HS);
    ldr_x(e, T5, T3, 0);                         /* base              */
    ldr_x(e, T6, T3, 8);                         /* end               */
    subs_reg(e, 1, T7, ra, T5);                  /* off = a - base    */
    uint32_t to_next1 = here(e); bcond_placeholder(e, C_LO); /* a<base */
    sub_reg(e, 1, T8, T6, T5);                   /* rlen              */
    subs_reg(e, 1, XZR, T7, T8);                 /* cmp off, rlen     */
    uint32_t to_next2 = here(e); bcond_placeholder(e, C_HS);
    sub_reg(e, 1, T8, T8, T7);                   /* rlen - off        */
    mov_imm64(e, T5, size);
    subs_reg(e, 1, XZR, T8, T5);
    uint32_t to_next3 = here(e); bcond_placeholder(e, C_LO);
    uint32_t to_next4 = 0;
    if (write) {
        ldrb_(e, T5, T3, 16);                    /* region.rw         */
        subs_reg(e, 0, XZR, T5, XZR);
        to_next4 = here(e); bcond_placeholder(e, C_EQ);
    }
    uint32_t to_ok = here(e); b_placeholder(e);
    uint32_t next = here(e);
    if (!addsub_imm(e, 1, 0, 0, T3, T3, REGION_SZ)) {
        mov_imm64(e, T5, REGION_SZ);
        add_reg(e, 1, T3, T3, T5);
    }
    addsub_imm(e, 0, 0, 0, T4, T4, 1);
    uint32_t back = here(e); b_placeholder(e);
    patch_b(e, back, loop);
    uint32_t fail = here(e);
    fixes[(*nfix)++] = (struct fix){ here(e), abort_id, 0 };
    b_placeholder(e);
    uint32_t ok = here(e);
    patch_bcond(e, to_fail1, fail);
    patch_bcond(e, to_next1, next);
    patch_bcond(e, to_next2, next);
    patch_bcond(e, to_next3, next);
    if (write) patch_bcond(e, to_next4, next);
    patch_b(e, to_ok, ok);
}

/* Effective address of a memory op into T0: base register + signed off. */
static void emit_addr(emit_t *e, int base_r, int32_t off) {
    int base = (base_r == 10) ? T2 : R[base_r];
    if (base_r == 10) get_r10(e, T2);
    if (off == 0) { mov_reg(e, 1, T0, base); return; }
    uint64_t mag = (off < 0) ? (uint64_t)(-(int64_t)off) : (uint64_t)off;
    if (addsub_imm(e, 1, off < 0, 0, T0, base, mag)) return;
    mov_imm64(e, T1, (uint64_t)(int64_t)off);
    add_reg(e, 1, T0, base, T1);
}

ktx_jitfn ktx_jit_compile(const ktx_dinsn *code, uint32_t n, int use_fuel,
                          size_t *code_bytes, size_t *emit_bytes,
                          char *err, size_t errlen) {
    if (err && errlen) err[0] = 0;
    emit_t E = { NULL, 0, 0, 0 };
    emit_t *e = &E;
    uint32_t *ipos = calloc(n + 1, sizeof(uint32_t));
    struct fix *fixes = calloc(16u * n + 64, sizeof(struct fix));
    if (!ipos || !fixes) { free(ipos); free(fixes); return NULL; }
    int nfix = 0;
    /* pseudo instruction ids for the trampolines */
    const uint32_t ABORT_GUARD = n + 1, ABORT_FUEL = n + 2,
                   ABORT_HELPER_ID = n + 3, EXIT_ID = n + 4;

#define FIXB(target) do { fixes[nfix++] = (struct fix){ here(e), (target), 0 }; \
                          b_placeholder(e); } while (0)
#define FIXBC(cond, target) do { \
        fixes[nfix++] = (struct fix){ here(e), (target), 1 }; \
        bcond_placeholder(e, (cond)); } while (0)

    /* ---------------- prologue ---------------- */
    stp_pre(e, 19, 20, SP, -96);                 /* save x19..x30       */
    stp_off(e, 21, 22, SP, 16);
    stp_off(e, 23, 24, SP, 32);
    stp_off(e, 25, 26, SP, 48);
    stp_off(e, 27, 28, SP, 64);
    stp_off(e, 29, 30, SP, 80);
    /* frame for our own slots */
    addsub_imm(e, 1, 1, 0, SP, SP, FRAME);
    str_x(e, 0, SP, EX_SLOT);                    /* ex                */
    /* load the eBPF register file */
    for (int i = 0; i < 10; i++)
        ldr_x(e, R[i], 0, OFF_REGS + (uint32_t)i * 8);
    ldr_x(e, T0, 0, OFF_REGS + 80);              /* r10               */
    str_x(e, T0, SP, R10_SLOT);
    if (use_fuel) ldr_x(e, XFUEL, 0, OFF_FUEL);

    /* ---------------- body ---------------- */
    for (uint32_t pc = 0; pc < n; pc++) {
        ipos[pc] = here(e);
        const ktx_dinsn *d = &code[pc];
        int dst = d->dst, src = d->src;
        /* r10 (the frame pointer) lives in a frame slot, not a machine
         * register, so any *read* of it materialises into a temp.  It can
         * never be a destination: the decoder rejects writes to r10. */
        int rd = (dst <= 9) ? R[dst] : -1;
        int srcr;
        (void)srcr;
#define RS(t) (src <= 9 ? R[src] : (get_r10(e, (t)), (t)))
#define RDJ(t) (dst <= 9 ? R[dst] : (get_r10(e, (t)), (t)))

        if (use_fuel && d->handler != H_NOP) {
            addsub_imm(e, 1, 1, 1, XFUEL, XFUEL, 1);     /* subs fuel,1 */
            FIXBC(C_MI, ABORT_FUEL);
        }

#define KIMM64 ((uint64_t)(int64_t)d->imm)
#define NEEDK(t) do { mov_imm64(e, (t), KIMM64); } while (0)
#define SRC_OR_K(t) (d->handler & 1 ? 0 : 0)   /* unused; explicit below */

        switch (d->handler) {
        case H_NOP: break;

        /* ---- ALU64 ---- */
        case H_ADD64_K: { uint64_t m = (d->imm < 0) ? (uint64_t)(-(int64_t)d->imm)
                                                    : (uint64_t)d->imm;
            if (!addsub_imm(e, 1, d->imm < 0, 0, rd, rd, m)) {
                NEEDK(T0); add_reg(e, 1, rd, rd, T0); } break; }
        case H_ADD64_X: add_reg(e, 1, rd, rd, RS(T4)); break;
        case H_SUB64_K: { uint64_t m = (d->imm < 0) ? (uint64_t)(-(int64_t)d->imm)
                                                    : (uint64_t)d->imm;
            if (!addsub_imm(e, 1, d->imm >= 0, 0, rd, rd, m)) {
                NEEDK(T0); sub_reg(e, 1, rd, rd, T0); } break; }
        case H_SUB64_X: sub_reg(e, 1, rd, rd, RS(T4)); break;
        case H_MUL64_K: NEEDK(T0); mul(e, 1, rd, rd, T0); break;
        case H_MUL64_X: mul(e, 1, rd, rd, RS(T4)); break;
        case H_DIV64_K: NEEDK(T0); udiv(e, 1, rd, rd, T0); break;
        case H_DIV64_X: udiv(e, 1, rd, rd, RS(T4)); break;
        case H_MOD64_K: NEEDK(T0); udiv(e, 1, T1, rd, T0);
                        msub(e, 1, rd, T1, T0, rd); break;
        case H_MOD64_X: srcr = RS(T4); udiv(e, 1, T1, rd, srcr);
                        msub(e, 1, rd, T1, srcr, rd); break;
        case H_OR64_K:  NEEDK(T0); orr_reg(e, 1, rd, rd, T0); break;
        case H_OR64_X:  orr_reg(e, 1, rd, rd, RS(T4)); break;
        case H_AND64_K: NEEDK(T0); and_reg(e, 1, rd, rd, T0); break;
        case H_AND64_X: and_reg(e, 1, rd, rd, RS(T4)); break;
        case H_XOR64_K: NEEDK(T0); eor_reg(e, 1, rd, rd, T0); break;
        case H_XOR64_X: eor_reg(e, 1, rd, rd, RS(T4)); break;
        case H_LSH64_K: mov_imm64(e, T0, (uint64_t)((uint32_t)d->imm & 63));
                        shiftv(e, 1, 0, rd, rd, T0); break;
        case H_LSH64_X: shiftv(e, 1, 0, rd, rd, RS(T4)); break;
        case H_RSH64_K: mov_imm64(e, T0, (uint64_t)((uint32_t)d->imm & 63));
                        shiftv(e, 1, 1, rd, rd, T0); break;
        case H_RSH64_X: shiftv(e, 1, 1, rd, rd, RS(T4)); break;
        case H_ARSH64_K: mov_imm64(e, T0, (uint64_t)((uint32_t)d->imm & 63));
                        shiftv(e, 1, 2, rd, rd, T0); break;
        case H_ARSH64_X: shiftv(e, 1, 2, rd, rd, RS(T4)); break;
        case H_NEG64:   sub_reg(e, 1, rd, XZR, rd); break;
        case H_MOV64_K: mov_imm64(e, rd, KIMM64); break;
        case H_MOV64_X: mov_reg(e, 1, rd, RS(T4)); break;

        /* ---- ALU32 (write to W zero-extends) ---- */
        case H_ADD32_K: NEEDK(T0); add_reg(e, 0, rd, rd, T0); break;
        case H_ADD32_X: add_reg(e, 0, rd, rd, RS(T4)); break;
        case H_SUB32_K: NEEDK(T0); sub_reg(e, 0, rd, rd, T0); break;
        case H_SUB32_X: sub_reg(e, 0, rd, rd, RS(T4)); break;
        case H_MUL32_K: NEEDK(T0); mul(e, 0, rd, rd, T0); break;
        case H_MUL32_X: mul(e, 0, rd, rd, RS(T4)); break;
        case H_DIV32_K: NEEDK(T0); udiv(e, 0, rd, rd, T0); break;
        case H_DIV32_X: udiv(e, 0, rd, rd, RS(T4)); break;
        case H_MOD32_K: NEEDK(T0); udiv(e, 0, T1, rd, T0);
                        msub(e, 0, rd, T1, T0, rd); break;
        case H_MOD32_X: srcr = RS(T4); udiv(e, 0, T1, rd, srcr);
                        msub(e, 0, rd, T1, srcr, rd); break;
        case H_OR32_K:  NEEDK(T0); orr_reg(e, 0, rd, rd, T0); break;
        case H_OR32_X:  orr_reg(e, 0, rd, rd, RS(T4)); break;
        case H_AND32_K: NEEDK(T0); and_reg(e, 0, rd, rd, T0); break;
        case H_AND32_X: and_reg(e, 0, rd, rd, RS(T4)); break;
        case H_XOR32_K: NEEDK(T0); eor_reg(e, 0, rd, rd, T0); break;
        case H_XOR32_X: eor_reg(e, 0, rd, rd, RS(T4)); break;
        case H_LSH32_K: mov_imm64(e, T0, (uint64_t)((uint32_t)d->imm & 31));
                        shiftv(e, 0, 0, rd, rd, T0); break;
        case H_LSH32_X: shiftv(e, 0, 0, rd, rd, RS(T4)); break;
        case H_RSH32_K: mov_imm64(e, T0, (uint64_t)((uint32_t)d->imm & 31));
                        shiftv(e, 0, 1, rd, rd, T0); break;
        case H_RSH32_X: shiftv(e, 0, 1, rd, rd, RS(T4)); break;
        case H_ARSH32_K: mov_imm64(e, T0, (uint64_t)((uint32_t)d->imm & 31));
                        shiftv(e, 0, 2, rd, rd, T0); break;
        case H_ARSH32_X: shiftv(e, 0, 2, rd, rd, RS(T4)); break;
        case H_NEG32:   sub_reg(e, 0, rd, XZR, rd); break;
        case H_MOV32_K: mov_imm64(e, T0, (uint64_t)(uint32_t)d->imm);
                        mov_reg(e, 0, rd, T0); break;
        case H_MOV32_X: mov_reg(e, 0, rd, RS(T4)); break;

        /* ---- jumps ---- */
        case H_JA: FIXB((uint32_t)((int32_t)pc + 1 + d->off)); break;
#define JCC(sf_, cond_, isk_, use_and_) do { \
            /* both operands are reads, so either may be r10 */ \
            uint32_t tgt = (uint32_t)((int32_t)pc + 1 + d->off); \
            if (isk_) { mov_imm64(e, T0, (sf_) ? KIMM64 \
                                               : (uint64_t)(uint32_t)d->imm); \
                        if (use_and_) ands_reg(e, sf_, XZR, rd, T0); \
                        else subs_reg(e, sf_, XZR, rd, T0); } \
            else { if (use_and_) ands_reg(e, sf_, XZR, rd, RS(T4)); \
                   else subs_reg(e, sf_, XZR, rd, RS(T4)); } \
            FIXBC(cond_, tgt); } while (0)
        case H_JEQ_K:  JCC(1, C_EQ, 1, 0); break;
        case H_JEQ_X:  JCC(1, C_EQ, 0, 0); break;
        case H_JNE_K:  JCC(1, C_NE, 1, 0); break;
        case H_JNE_X:  JCC(1, C_NE, 0, 0); break;
        case H_JGT_K:  JCC(1, C_HI, 1, 0); break;
        case H_JGT_X:  JCC(1, C_HI, 0, 0); break;
        case H_JGE_K:  JCC(1, C_HS, 1, 0); break;
        case H_JGE_X:  JCC(1, C_HS, 0, 0); break;
        case H_JLT_K:  JCC(1, C_LO, 1, 0); break;
        case H_JLT_X:  JCC(1, C_LO, 0, 0); break;
        case H_JLE_K:  JCC(1, C_LS, 1, 0); break;
        case H_JLE_X:  JCC(1, C_LS, 0, 0); break;
        case H_JSGT_K: JCC(1, C_GT, 1, 0); break;
        case H_JSGT_X: JCC(1, C_GT, 0, 0); break;
        case H_JSGE_K: JCC(1, C_GE, 1, 0); break;
        case H_JSGE_X: JCC(1, C_GE, 0, 0); break;
        case H_JSLT_K: JCC(1, C_LT, 1, 0); break;
        case H_JSLT_X: JCC(1, C_LT, 0, 0); break;
        case H_JSLE_K: JCC(1, C_LE, 1, 0); break;
        case H_JSLE_X: JCC(1, C_LE, 0, 0); break;
        case H_JSET_K: JCC(1, C_NE, 1, 1); break;
        case H_JSET_X: JCC(1, C_NE, 0, 1); break;
        case H_JEQ32_K:  JCC(0, C_EQ, 1, 0); break;
        case H_JEQ32_X:  JCC(0, C_EQ, 0, 0); break;
        case H_JNE32_K:  JCC(0, C_NE, 1, 0); break;
        case H_JNE32_X:  JCC(0, C_NE, 0, 0); break;
        case H_JGT32_K:  JCC(0, C_HI, 1, 0); break;
        case H_JGT32_X:  JCC(0, C_HI, 0, 0); break;
        case H_JGE32_K:  JCC(0, C_HS, 1, 0); break;
        case H_JGE32_X:  JCC(0, C_HS, 0, 0); break;
        case H_JLT32_K:  JCC(0, C_LO, 1, 0); break;
        case H_JLT32_X:  JCC(0, C_LO, 0, 0); break;
        case H_JLE32_K:  JCC(0, C_LS, 1, 0); break;
        case H_JLE32_X:  JCC(0, C_LS, 0, 0); break;
        case H_JSGT32_K: JCC(0, C_GT, 1, 0); break;
        case H_JSGT32_X: JCC(0, C_GT, 0, 0); break;
        case H_JSGE32_K: JCC(0, C_GE, 1, 0); break;
        case H_JSGE32_X: JCC(0, C_GE, 0, 0); break;
        case H_JSLT32_K: JCC(0, C_LT, 1, 0); break;
        case H_JSLT32_X: JCC(0, C_LT, 0, 0); break;
        case H_JSLE32_K: JCC(0, C_LE, 1, 0); break;
        case H_JSLE32_X: JCC(0, C_LE, 0, 0); break;
        case H_JSET32_K: JCC(0, C_NE, 1, 1); break;
        case H_JSET32_X: JCC(0, C_NE, 0, 1); break;
#undef JCC

        case H_LD_IMM64:
            mov_imm64(e, rd, d->imm64);
            pc++;                                /* skip the H_NOP slot */
            ipos[pc] = here(e);
            break;

        /* ---- helper call ---- */
        case H_CALL: {
            get_ex(e, T1);
            if (!addsub_imm(e, 1, 0, 0, T2, T1, OFF_REGS)) {
                mov_imm64(e, T3, OFF_REGS); add_reg(e, 1, T2, T1, T3);
            }
            for (int i = 0; i <= 5; i++)
                str_x(e, R[i], T2, (uint32_t)i * 8);
            get_r10(e, T3);
            str_x(e, T3, T2, 80);
            mov_reg(e, 1, 0, T1);                /* x0 = ex             */
            mov_reg(e, 1, 1, T2);                /* x1 = ex->regs       */
            mov_imm64(e, 2, (uint64_t)(uint32_t)d->imm);
            mov_imm64(e, T7, (uint64_t)(uintptr_t)ktx_helper_call);
            blr(e, T7);
            mov_reg(e, 1, R[0], 0);              /* r0 = return value   */
            get_ex(e, T1);
            ldr_w(e, T2, T1, OFF_STATUS);
            subs_reg(e, 0, XZR, T2, XZR);
            FIXBC(C_NE, ABORT_HELPER_ID);
            break;
        }

        case H_EXIT: FIXB(EXIT_ID); break;

        /* ---- memory ---- */
#define LD(sz_, ldop_, guard_) do { \
            emit_addr(e, src, d->off); \
            if (guard_) emit_guard(e, T0, sz_, 0, fixes, &nfix, ABORT_GUARD); \
            ldop_; } while (0)
        case H_LDXB:    LD(1, ldrb_(e, rd, T0, 0), 0); break;
        case H_LDXB_G:  LD(1, ldrb_(e, rd, T0, 0), 1); break;
        case H_LDXH:    LD(2, ldrh_(e, rd, T0, 0), 0); break;
        case H_LDXH_G:  LD(2, ldrh_(e, rd, T0, 0), 1); break;
        case H_LDXW:    LD(4, ldr_w(e, rd, T0, 0), 0); break;
        case H_LDXW_G:  LD(4, ldr_w(e, rd, T0, 0), 1); break;
        case H_LDXDW:   LD(8, ldr_x(e, rd, T0, 0), 0); break;
        case H_LDXDW_G: LD(8, ldr_x(e, rd, T0, 0), 1); break;
#undef LD
#define STR_(sz_, stop_, guard_) do { \
            emit_addr(e, dst, d->off); \
            if (guard_) emit_guard(e, T0, sz_, 1, fixes, &nfix, ABORT_GUARD); \
            stop_; } while (0)
        case H_STXB:    STR_(1, strb_(e, RS(T4), T0, 0), 0); break;
        case H_STXB_G:  STR_(1, strb_(e, RS(T4), T0, 0), 1); break;
        case H_STXH:    STR_(2, strh_(e, RS(T4), T0, 0), 0); break;
        case H_STXH_G:  STR_(2, strh_(e, RS(T4), T0, 0), 1); break;
        case H_STXW:    STR_(4, str_w(e, RS(T4), T0, 0), 0); break;
        case H_STXW_G:  STR_(4, str_w(e, RS(T4), T0, 0), 1); break;
        case H_STXDW:   STR_(8, str_x(e, RS(T4), T0, 0), 0); break;
        case H_STXDW_G: STR_(8, str_x(e, RS(T4), T0, 0), 1); break;
        case H_STB:  STR_(1, (mov_imm64(e, T3, KIMM64), strb_(e, T3, T0, 0)), 0); break;
        case H_STB_G:STR_(1, (mov_imm64(e, T3, KIMM64), strb_(e, T3, T0, 0)), 1); break;
        case H_STH:  STR_(2, (mov_imm64(e, T3, KIMM64), strh_(e, T3, T0, 0)), 0); break;
        case H_STH_G:STR_(2, (mov_imm64(e, T3, KIMM64), strh_(e, T3, T0, 0)), 1); break;
        case H_STW:  STR_(4, (mov_imm64(e, T3, KIMM64), str_w(e, T3, T0, 0)), 0); break;
        case H_STW_G:STR_(4, (mov_imm64(e, T3, KIMM64), str_w(e, T3, T0, 0)), 1); break;
        case H_STDW: STR_(8, (mov_imm64(e, T3, KIMM64), str_x(e, T3, T0, 0)), 0); break;
        case H_STDW_G:STR_(8,(mov_imm64(e, T3, KIMM64), str_x(e, T3, T0, 0)), 1); break;
#undef STR_

        default:
            if (err && errlen)
                snprintf(err, errlen, "JIT: unsupported handler %u at %u",
                         d->handler, pc);
            free(E.buf); free(ipos); free(fixes);
            return NULL;
        }
#undef RS
#undef RDJ
    }

    /* ---------------- trampolines ---------------- */
    uint32_t pos_exit = here(e);
    {   /* EXIT: r0_out = r0; if (tx) commit; return status */
        get_ex(e, T1);
        str_x(e, R[0], T1, OFF_R0OUT);
        if (use_fuel) str_x(e, XFUEL, T1, OFF_FUEL);
        ldrb_(e, T2, T1, OFF_TX);
        subs_reg(e, 0, XZR, T2, XZR);
        uint32_t skip = here(e); bcond_placeholder(e, C_EQ);
        ldr_x(e, 0, T1, OFF_TH);                 /* x0 = ex->th        */
        ldr_x(e, 1, T1, OFF_PKT);                /* x1 = ex->pkt       */
        ldr_w(e, 2, T1, OFF_PKTLEN);             /* w2 = ex->pkt_len   */
        mov_imm64(e, T7, (uint64_t)(uintptr_t)ktx_tx_commit);
        blr(e, T7);
        subs_reg(e, 0, XZR, 0, XZR);
        uint32_t ok = here(e); bcond_placeholder(e, C_EQ);
        /* commit failed: ex->status = ret; return ret */
        get_ex(e, T1);
        str_w(e, 0, T1, OFF_STATUS);
        uint32_t to_ret = here(e); b_placeholder(e);
        patch_bcond(e, skip, here(e));
        patch_bcond(e, ok, here(e));
        movz(e, 0, 0, 0);                        /* KTX_OK             */
        patch_b(e, to_ret, here(e));
        /* epilogue */
        emit_epilogue(e);
    }
    uint32_t pos_guard = here(e);
    {   get_ex(e, T1);
        movz(e, T2, KTX_ABORT_GUARD, 0);
        str_w(e, T2, T1, OFF_STATUS);
        if (use_fuel) str_x(e, XFUEL, T1, OFF_FUEL);
        mov_reg(e, 1, 0, T2);
        emit_epilogue(e);
    }
    uint32_t pos_fuel = here(e);
    {   get_ex(e, T1);
        movz(e, T2, KTX_ABORT_FUEL, 0);
        str_w(e, T2, T1, OFF_STATUS);
        mov_imm64(e, T3, (uint64_t)(int64_t)-1);
        str_x(e, T3, T1, OFF_FUEL);
        mov_reg(e, 1, 0, T2);
        emit_epilogue(e);
    }
    uint32_t pos_helper = here(e);
    {   get_ex(e, T1);
        ldr_w(e, 0, T1, OFF_STATUS);             /* return ex->status  */
        if (use_fuel) str_x(e, XFUEL, T1, OFF_FUEL);
        emit_epilogue(e);
    }

    /* ---------------- patch ---------------- */
    for (int i = 0; i < nfix; i++) {
        uint32_t t = fixes[i].target_insn;
        uint32_t at = fixes[i].at;
        uint32_t tgt;
        if (t == ABORT_GUARD) tgt = pos_guard;
        else if (t == ABORT_FUEL) tgt = pos_fuel;
        else if (t == ABORT_HELPER_ID) tgt = pos_helper;
        else if (t == EXIT_ID) tgt = pos_exit;
        else if (t < n) tgt = ipos[t];
        else {
            if (err && errlen) snprintf(err, errlen, "JIT: bad branch target");
            free(E.buf); free(ipos); free(fixes); return NULL;
        }
        if (fixes[i].is_cond) patch_bcond(e, at, tgt);
        else patch_b(e, at, tgt);
    }
    free(ipos);
    free(fixes);
    if (E.oom) { free(E.buf); return NULL; }

    /* ---------------- publish ---------------- */
    size_t bytes = (size_t)E.n * 4;
    size_t pages = (bytes + 16383) & ~(size_t)16383;
    int flags = MAP_PRIVATE | MAP_ANON;
#if defined(MAP_JIT)
    flags |= MAP_JIT;
#endif
    void *mem = mmap(NULL, pages, PROT_READ | PROT_WRITE | PROT_EXEC,
                     flags, -1, 0);
    if (mem == MAP_FAILED) {
        mem = mmap(NULL, pages, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANON, -1, 0);
        if (mem == MAP_FAILED) {
            if (err && errlen) snprintf(err, errlen, "JIT: mmap failed");
            free(E.buf);
            return NULL;
        }
    }
#if defined(__APPLE__)
    pthread_jit_write_protect_np(0);
#endif
    memcpy(mem, E.buf, bytes);
#if defined(__APPLE__)
    pthread_jit_write_protect_np(1);
    sys_icache_invalidate(mem, bytes);
#else
    __builtin___clear_cache((char *)mem, (char *)mem + bytes);
#endif
    if (mprotect(mem, pages, PROT_READ | PROT_EXEC) != 0) {
        /* MAP_JIT pages are already RX-capable; ignore failures there. */
    }
    free(E.buf);
    if (code_bytes) *code_bytes = pages;
    if (emit_bytes) *emit_bytes = bytes;
    return (ktx_jitfn)mem;
}

void ktx_jit_free(ktx_jitfn fn, size_t code_bytes) {
    if (fn) munmap((void *)fn, code_bytes ? code_bytes : 16384);
}

int ktx_jit_available(void) { return 1; }

#endif /* aarch64 */
