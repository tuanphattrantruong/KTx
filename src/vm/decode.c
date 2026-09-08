/* decode.c — translate raw eBPF instruction slots into pre-decoded
 * ktx_dinsn arrays (DESIGN §1.4).  Every memory op exists in guarded and
 * unguarded variants; the chosen variant depends on the decode target:
 *   KTX_DECODE_VANILLA — all unguarded
 *   KTX_DECODE_GUARDED — all guarded
 *   KTX_DECODE_ELIDED  — guarded unless the sidecar tx bit says elidable
 * All validation (unknown opcodes, r10 writes, jump targets, LD_IMM64
 * pairing, map indices, helper ids) happens here, at load time.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../ktx/ktx_internal.h"

/* op-nibble (>>4) indexed handler tables; 0 = invalid. */
static const uint16_t alu64_k[13] = {
    H_ADD64_K, H_SUB64_K, H_MUL64_K, H_DIV64_K, H_OR64_K, H_AND64_K,
    H_LSH64_K, H_RSH64_K, H_NEG64,   H_MOD64_K, H_XOR64_K, H_MOV64_K,
    H_ARSH64_K
};
static const uint16_t alu64_x[13] = {
    H_ADD64_X, H_SUB64_X, H_MUL64_X, H_DIV64_X, H_OR64_X, H_AND64_X,
    H_LSH64_X, H_RSH64_X, 0,         H_MOD64_X, H_XOR64_X, H_MOV64_X,
    H_ARSH64_X
};
static const uint16_t alu32_k[13] = {
    H_ADD32_K, H_SUB32_K, H_MUL32_K, H_DIV32_K, H_OR32_K, H_AND32_K,
    H_LSH32_K, H_RSH32_K, H_NEG32,   H_MOD32_K, H_XOR32_K, H_MOV32_K,
    H_ARSH32_K
};
static const uint16_t alu32_x[13] = {
    H_ADD32_X, H_SUB32_X, H_MUL32_X, H_DIV32_X, H_OR32_X, H_AND32_X,
    H_LSH32_X, H_RSH32_X, 0,         H_MOD32_X, H_XOR32_X, H_MOV32_X,
    H_ARSH32_X
};
/* Conditional jumps, op nibble 1..13 (JA/CALL/EXIT handled separately). */
static const uint16_t jmp_k[14] = {
    0, H_JEQ_K, H_JGT_K, H_JGE_K, H_JSET_K, H_JNE_K, H_JSGT_K, H_JSGE_K,
    0, 0, H_JLT_K, H_JLE_K, H_JSLT_K, H_JSLE_K
};
static const uint16_t jmp_x[14] = {
    0, H_JEQ_X, H_JGT_X, H_JGE_X, H_JSET_X, H_JNE_X, H_JSGT_X, H_JSGE_X,
    0, 0, H_JLT_X, H_JLE_X, H_JSLT_X, H_JSLE_X
};
static const uint16_t jmp32_k[14] = {
    0, H_JEQ32_K, H_JGT32_K, H_JGE32_K, H_JSET32_K, H_JNE32_K, H_JSGT32_K,
    H_JSGE32_K, 0, 0, H_JLT32_K, H_JLE32_K, H_JSLT32_K, H_JSLE32_K
};
static const uint16_t jmp32_x[14] = {
    0, H_JEQ32_X, H_JGT32_X, H_JGE32_X, H_JSET32_X, H_JNE32_X, H_JSGT32_X,
    H_JSGE32_X, 0, 0, H_JLT32_X, H_JLE32_X, H_JSLT32_X, H_JSLE32_X
};

/* size bits -> pair index {B,H,W,DW} = {0,1,2,3} */
static int size_index(uint8_t code) {
    switch (code & KTX_SIZE_MASK) {
    case KTX_SIZE_B:  return 0;
    case KTX_SIZE_H:  return 1;
    case KTX_SIZE_W:  return 2;
    default:          return 3;   /* KTX_SIZE_DW */
    }
}

static int valid_helper(int32_t id) {
    return id == KTX_HELPER_MAP_LOOKUP || id == KTX_HELPER_MAP_UPDATE ||
           id == KTX_HELPER_MAP_DELETE || id == KTX_HELPER_KTIME_GET_NS ||
           id == KTX_HELPER_GET_PRANDOM_U32 ||
           id == KTX_HELPER_PKT_STORE_BYTES ||
           id == KTX_HELPER_RINGBUF_OUTPUT;
}

int ktx_decode(const struct ktx_insn *ins, uint32_t n, uint32_t n_maps,
               const uint8_t *iflags, int variant,
               ktx_dinsn *out, char *err, size_t errlen) {
#define DEC_ERR(i, ...) do { \
        if (err && errlen) { \
            int _k = snprintf(err, errlen, "insn %u: ", (i)); \
            if (_k >= 0 && (size_t)_k < errlen) \
                snprintf(err + _k, errlen - (size_t)_k, __VA_ARGS__); \
        } \
        return -1; \
    } while (0)

    if (n == 0) DEC_ERR(0u, "empty program");

    /* second slots of LD_IMM64 (jump targets must not land past-end;
     * landing on the H_NOP slot itself is rejected like the kernel). */
    uint8_t *is_pair2 = calloc(n, 1);
    if (!is_pair2) DEC_ERR(0u, "out of memory");
#define DEC_FAIL(i, ...) do { free(is_pair2); DEC_ERR(i, __VA_ARGS__); } while (0)

    for (uint32_t i = 0; i < n; i++) {
        const struct ktx_insn *in = &ins[i];
        uint8_t code = in->code;
        uint8_t dst = (uint8_t)(in->regs & 0x0f);
        uint8_t src = (uint8_t)((in->regs >> 4) & 0x0f);
        uint8_t cls = code & KTX_CLASS_MASK;
        ktx_dinsn *d = &out[i];
        d->handler = H_NOP;
        d->dst = dst;
        d->src = src;
        d->off = in->off;
        d->imm = in->imm;
        d->imm64 = 0;

        switch (cls) {
        case KTX_CLASS_LD: {
            if (code != KTX_OP_LD_IMM64)
                DEC_FAIL(i, "unknown opcode 0x%02x", code);
            if (i + 1 >= n)
                DEC_FAIL(i, "LD_IMM64 truncated (missing second slot)");
            const struct ktx_insn *hi = &ins[i + 1];
            if (hi->code != 0 || hi->regs != 0 || hi->off != 0)
                DEC_FAIL(i, "LD_IMM64 second slot not all-zero");
            if (dst > 9)
                DEC_FAIL(i, "write to read-only r%u", dst);
            if (in->off != 0)
                DEC_FAIL(i, "LD_IMM64 off must be 0");
            if (src == 0) {
                d->imm64 = (uint64_t)(uint32_t)in->imm |
                           ((uint64_t)(uint32_t)hi->imm << 32);
            } else if (src == KTX_PSEUDO_MAP_FD) {
                if (hi->imm != 0)
                    DEC_FAIL(i, "map ref: high imm must be 0");
                if (in->imm < 0 || (uint32_t)in->imm >= n_maps)
                    DEC_FAIL(i, "map index %d out of range (n_maps=%u)",
                             in->imm, n_maps);
                d->imm64 = KTX_MAP_HANDLE((uint32_t)in->imm);
            } else {
                DEC_FAIL(i, "LD_IMM64 src_reg %u unsupported", src);
            }
            d->handler = H_LD_IMM64;
            d->src = 0;
            ktx_dinsn *d2 = &out[i + 1];
            memset(d2, 0, sizeof(*d2));
            d2->handler = H_NOP;
            is_pair2[i + 1] = 1;
            i++;                          /* consume second slot */
            break;
        }

        case KTX_CLASS_ALU:
        case KTX_CLASS_ALU64: {
            uint32_t op = (uint32_t)(code & KTX_ALUOP_MASK) >> 4;
            int is64 = (cls == KTX_CLASS_ALU64);
            int isx = (code & KTX_SRC_MASK) != 0;
            if (op > 12)
                DEC_FAIL(i, "unknown opcode 0x%02x", code);
            if (dst > 9)
                DEC_FAIL(i, "write to read-only r%u", dst);
            if (in->off != 0)
                DEC_FAIL(i, "ALU off must be 0");
            uint16_t h;
            if (op == 8) {                /* NEG: K form only */
                if (isx || src != 0 || in->imm != 0)
                    DEC_FAIL(i, "NEG must have src=0 imm=0");
                h = is64 ? H_NEG64 : H_NEG32;
            } else if (isx) {
                if (src > 10)
                    DEC_FAIL(i, "bad src reg r%u", src);
                if (in->imm != 0)
                    DEC_FAIL(i, "ALU-X imm must be 0");
                h = is64 ? alu64_x[op] : alu32_x[op];
            } else {
                if (src != 0)
                    DEC_FAIL(i, "ALU-K src reg must be 0");
                h = is64 ? alu64_k[op] : alu32_k[op];
            }
            if (!h) DEC_FAIL(i, "unknown opcode 0x%02x", code);
            d->handler = h;
            break;
        }

        case KTX_CLASS_JMP:
        case KTX_CLASS_JMP32: {
            uint32_t op = (uint32_t)(code & KTX_ALUOP_MASK) >> 4;
            int is32 = (cls == KTX_CLASS_JMP32);
            int isx = (code & KTX_SRC_MASK) != 0;
            if (code == KTX_OP_CALL) {
                if (dst != 0 || src != 0 || in->off != 0)
                    DEC_FAIL(i, "CALL regs/off must be 0");
                if (!valid_helper(in->imm))
                    DEC_FAIL(i, "unknown helper id %d", in->imm);
                d->handler = H_CALL;
                break;
            }
            if (code == KTX_OP_EXIT) {
                if (dst != 0 || src != 0 || in->off != 0 || in->imm != 0)
                    DEC_FAIL(i, "EXIT operands must be 0");
                d->handler = H_EXIT;
                break;
            }
            if (op == 0) {                /* JA: JMP class, K only */
                if (is32 || isx)
                    DEC_FAIL(i, "unknown opcode 0x%02x", code);
                if (dst != 0 || src != 0 || in->imm != 0)
                    DEC_FAIL(i, "JA operands must be 0");
                d->handler = H_JA;
                break;
            }
            if (op > 13 || op == 8 || op == 9)
                DEC_FAIL(i, "unknown opcode 0x%02x", code);
            if (dst > 10)
                DEC_FAIL(i, "bad dst reg r%u", dst);
            uint16_t h;
            if (isx) {
                if (src > 10)
                    DEC_FAIL(i, "bad src reg r%u", src);
                if (in->imm != 0)
                    DEC_FAIL(i, "JMP-X imm must be 0");
                h = is32 ? jmp32_x[op] : jmp_x[op];
            } else {
                if (src != 0)
                    DEC_FAIL(i, "JMP-K src reg must be 0");
                h = is32 ? jmp32_k[op] : jmp_k[op];
            }
            if (!h) DEC_FAIL(i, "unknown opcode 0x%02x", code);
            d->handler = h;
            break;
        }

        case KTX_CLASS_LDX: {
            if ((code & KTX_MODE_MASK) != KTX_MODE_MEM)
                DEC_FAIL(i, "unknown opcode 0x%02x", code);
            if (dst > 9)
                DEC_FAIL(i, "write to read-only r%u", dst);
            if (src > 10)
                DEC_FAIL(i, "bad src reg r%u", src);
            if (in->imm != 0)
                DEC_FAIL(i, "LDX imm must be 0");
            d->handler = (uint16_t)(H_LDXB + 2 * size_index(code));
            break;
        }

        case KTX_CLASS_STX: {
            if ((code & KTX_MODE_MASK) != KTX_MODE_MEM)
                DEC_FAIL(i, "unknown opcode 0x%02x", code);
            if (dst > 10)
                DEC_FAIL(i, "bad dst reg r%u", dst);
            if (src > 10)
                DEC_FAIL(i, "bad src reg r%u", src);
            if (in->imm != 0)
                DEC_FAIL(i, "STX imm must be 0");
            d->handler = (uint16_t)(H_STXB + 2 * size_index(code));
            break;
        }

        case KTX_CLASS_ST: {
            if ((code & KTX_MODE_MASK) != KTX_MODE_MEM)
                DEC_FAIL(i, "unknown opcode 0x%02x", code);
            if (dst > 10)
                DEC_FAIL(i, "bad dst reg r%u", dst);
            if (src != 0)
                DEC_FAIL(i, "ST src reg must be 0");
            d->handler = (uint16_t)(H_STB + 2 * size_index(code));
            break;
        }

        default:
            DEC_FAIL(i, "unknown opcode 0x%02x", code);
        }

        /* guard variant selection for memory ops */
        if (d->handler >= H_LDXB && d->handler <= H_STDW_G) {
            int guarded;
            switch (variant) {
            case KTX_DECODE_VANILLA: guarded = 0; break;
            case KTX_DECODE_GUARDED: guarded = 1; break;
            case KTX_DECODE_AUDIT:
                /* keep the guard, remember that it was certified */
                guarded = 1;
                d->certified = (uint8_t)(iflags &&
                                (iflags[i] & KTX_IFLAG_TX_ELIDABLE));
                break;
            default:                 /* KTX_DECODE_ELIDED */
                guarded = !(iflags &&
                            (iflags[i] & KTX_IFLAG_TX_ELIDABLE));
                break;
            }
            if (guarded) d->handler = (uint16_t)(d->handler + 1);
        }
    }

    /* jump-target validation + termination structure */
    for (uint32_t i = 0; i < n; i++) {
        uint16_t h = out[i].handler;
        int is_jump = (h == H_JA) ||
                      (h >= H_JEQ_K && h <= H_JSLE32_X);
        if (is_jump) {
            int64_t t = (int64_t)i + 1 + out[i].off;
            if (t < 0 || t >= (int64_t)n)
                DEC_FAIL(i, "jump target %lld out of range", (long long)t);
            if (is_pair2[t])
                DEC_FAIL(i, "jump into the middle of LD_IMM64");
        }
    }
    /* the last slot must not fall off the end */
    {
        uint16_t h = out[n - 1].handler;
        if (h != H_EXIT && h != H_JA)
            DEC_FAIL(n - 1, "program may fall off the end "
                            "(last insn must be exit or ja)");
    }

    free(is_pair2);
    return 0;
#undef DEC_FAIL
#undef DEC_ERR
}
