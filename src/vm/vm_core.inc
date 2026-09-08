/* vm_core.inc — interpreter switch body, included twice by vm.c:
 *   once as vm_exec_nofuel (VM_FUEL undefined)
 *   once as vm_exec_fuel   (VM_FUEL defined)
 * VM_FN names the emitted function.  DESIGN §1.4.
 *
 * Conventions:
 *  - pc advances by 1 at the bottom of the loop; jump handlers add off,
 *    so target = pc + 1 + off (offsets relative to the NEXT insn).
 *  - LD_IMM64 consumes two slots (adds an extra pc++), charging 1 fuel.
 *  - decode guarantees: jump targets in range, program cannot fall off
 *    the end, r10 never written, helper ids valid.
 */

ktx_status VM_FN(ktx_exec *ex)
{
    const ktx_dinsn *code = ex->code;
    uint64_t *r = ex->regs;
    uint32_t pc = 0;

#ifdef VM_FUEL
    int64_t fuel = ex->fuel;
#define VM_RET(st) do { ex->fuel = fuel; return (st); } while (0)
#define FUEL_CHECK() \
    do { if (--fuel < 0) { ex->fuel = -1; ex->status = KTX_ABORT_FUEL; \
                           return KTX_ABORT_FUEL; } } while (0)
#else
#define VM_RET(st) return (st)
#define FUEL_CHECK() do { } while (0)
#endif

#ifdef VM_AUDIT
/* Audit build: a guard that fires on an access the analyzer certified is
 * a proven-wrong fact.  Only this instantiation pays for the check. */
#define GUARD(a_, sz_, wr_) \
    do { if (di->certified) ex->th->stats.elide_audited++; \
         if (!ktx_guard_ok(ex, (a_), (sz_), (wr_))) { \
             if (di->certified) ex->th->stats.elide_faults++; \
             ex->status = KTX_ABORT_GUARD; VM_RET(KTX_ABORT_GUARD); \
         } } while (0)
#else
#define GUARD(a_, sz_, wr_) \
    do { if (!ktx_guard_ok(ex, (a_), (sz_), (wr_))) { \
             ex->status = KTX_ABORT_GUARD; VM_RET(KTX_ABORT_GUARD); \
         } } while (0)
#endif

    for (;;) {
        const ktx_dinsn *di = &code[pc];
        FUEL_CHECK();
        switch (di->handler) {
        case H_NOP:
            break;

        /* ------------- ALU64 ------------- */
        case H_ADD64_K: r[di->dst] += (uint64_t)(int64_t)di->imm; break;
        case H_ADD64_X: r[di->dst] += r[di->src]; break;
        case H_SUB64_K: r[di->dst] -= (uint64_t)(int64_t)di->imm; break;
        case H_SUB64_X: r[di->dst] -= r[di->src]; break;
        case H_MUL64_K: r[di->dst] *= (uint64_t)(int64_t)di->imm; break;
        case H_MUL64_X: r[di->dst] *= r[di->src]; break;
        case H_DIV64_K: {
            uint64_t k = (uint64_t)(int64_t)di->imm;
            r[di->dst] = k ? r[di->dst] / k : 0;
            break;
        }
        case H_DIV64_X: {
            uint64_t s = r[di->src];
            r[di->dst] = s ? r[di->dst] / s : 0;
            break;
        }
        case H_OR64_K:  r[di->dst] |= (uint64_t)(int64_t)di->imm; break;
        case H_OR64_X:  r[di->dst] |= r[di->src]; break;
        case H_AND64_K: r[di->dst] &= (uint64_t)(int64_t)di->imm; break;
        case H_AND64_X: r[di->dst] &= r[di->src]; break;
        case H_LSH64_K: r[di->dst] <<= ((uint32_t)di->imm & 63); break;
        case H_LSH64_X: r[di->dst] <<= (r[di->src] & 63); break;
        case H_RSH64_K: r[di->dst] >>= ((uint32_t)di->imm & 63); break;
        case H_RSH64_X: r[di->dst] >>= (r[di->src] & 63); break;
        case H_NEG64:   r[di->dst] = 0 - r[di->dst]; break;
        case H_MOD64_K: {
            uint64_t k = (uint64_t)(int64_t)di->imm;
            if (k) r[di->dst] %= k;      /* mod by 0: dst unchanged */
            break;
        }
        case H_MOD64_X: {
            uint64_t s = r[di->src];
            if (s) r[di->dst] %= s;
            break;
        }
        case H_XOR64_K: r[di->dst] ^= (uint64_t)(int64_t)di->imm; break;
        case H_XOR64_X: r[di->dst] ^= r[di->src]; break;
        case H_MOV64_K: r[di->dst] = (uint64_t)(int64_t)di->imm; break;
        case H_MOV64_X: r[di->dst] = r[di->src]; break;
        case H_ARSH64_K:
            r[di->dst] = (uint64_t)((int64_t)r[di->dst] >>
                                    ((uint32_t)di->imm & 63));
            break;
        case H_ARSH64_X:
            r[di->dst] = (uint64_t)((int64_t)r[di->dst] >>
                                    (r[di->src] & 63));
            break;

        /* ------------- ALU32 (zero-extends) ------------- */
        case H_ADD32_K:
            r[di->dst] = (uint32_t)((uint32_t)r[di->dst] +
                                    (uint32_t)di->imm);
            break;
        case H_ADD32_X:
            r[di->dst] = (uint32_t)((uint32_t)r[di->dst] +
                                    (uint32_t)r[di->src]);
            break;
        case H_SUB32_K:
            r[di->dst] = (uint32_t)((uint32_t)r[di->dst] -
                                    (uint32_t)di->imm);
            break;
        case H_SUB32_X:
            r[di->dst] = (uint32_t)((uint32_t)r[di->dst] -
                                    (uint32_t)r[di->src]);
            break;
        case H_MUL32_K:
            r[di->dst] = (uint32_t)((uint32_t)r[di->dst] *
                                    (uint32_t)di->imm);
            break;
        case H_MUL32_X:
            r[di->dst] = (uint32_t)((uint32_t)r[di->dst] *
                                    (uint32_t)r[di->src]);
            break;
        case H_DIV32_K: {
            uint32_t k = (uint32_t)di->imm;
            r[di->dst] = k ? (uint32_t)r[di->dst] / k : 0;
            break;
        }
        case H_DIV32_X: {
            uint32_t s = (uint32_t)r[di->src];
            r[di->dst] = s ? (uint32_t)r[di->dst] / s : 0;
            break;
        }
        case H_OR32_K:
            r[di->dst] = (uint32_t)((uint32_t)r[di->dst] |
                                    (uint32_t)di->imm);
            break;
        case H_OR32_X:
            r[di->dst] = (uint32_t)((uint32_t)r[di->dst] |
                                    (uint32_t)r[di->src]);
            break;
        case H_AND32_K:
            r[di->dst] = (uint32_t)((uint32_t)r[di->dst] &
                                    (uint32_t)di->imm);
            break;
        case H_AND32_X:
            r[di->dst] = (uint32_t)((uint32_t)r[di->dst] &
                                    (uint32_t)r[di->src]);
            break;
        case H_LSH32_K:
            r[di->dst] = (uint32_t)((uint32_t)r[di->dst] <<
                                    ((uint32_t)di->imm & 31));
            break;
        case H_LSH32_X:
            r[di->dst] = (uint32_t)((uint32_t)r[di->dst] <<
                                    ((uint32_t)r[di->src] & 31));
            break;
        case H_RSH32_K:
            r[di->dst] = (uint32_t)r[di->dst] >> ((uint32_t)di->imm & 31);
            break;
        case H_RSH32_X:
            r[di->dst] = (uint32_t)r[di->dst] >>
                         ((uint32_t)r[di->src] & 31);
            break;
        case H_NEG32:
            r[di->dst] = (uint32_t)(0u - (uint32_t)r[di->dst]);
            break;
        case H_MOD32_K: {
            uint32_t k = (uint32_t)di->imm;
            r[di->dst] = k ? (uint32_t)r[di->dst] % k
                           : (uint32_t)r[di->dst];
            break;
        }
        case H_MOD32_X: {
            uint32_t s = (uint32_t)r[di->src];
            r[di->dst] = s ? (uint32_t)r[di->dst] % s
                           : (uint32_t)r[di->dst];
            break;
        }
        case H_XOR32_K:
            r[di->dst] = (uint32_t)((uint32_t)r[di->dst] ^
                                    (uint32_t)di->imm);
            break;
        case H_XOR32_X:
            r[di->dst] = (uint32_t)((uint32_t)r[di->dst] ^
                                    (uint32_t)r[di->src]);
            break;
        case H_MOV32_K: r[di->dst] = (uint32_t)di->imm; break;
        case H_MOV32_X: r[di->dst] = (uint32_t)r[di->src]; break;
        case H_ARSH32_K:
            r[di->dst] = (uint32_t)((int32_t)(uint32_t)r[di->dst] >>
                                    ((uint32_t)di->imm & 31));
            break;
        case H_ARSH32_X:
            r[di->dst] = (uint32_t)((int32_t)(uint32_t)r[di->dst] >>
                                    ((uint32_t)r[di->src] & 31));
            break;

        /* ------------- JMP (64-bit compares) ------------- */
#define KOP ((uint64_t)(int64_t)di->imm)
#define CJ(cond_) do { if (cond_) pc += di->off; } while (0)
        case H_JA:     pc += di->off; break;
        case H_JEQ_K:  CJ(r[di->dst] == KOP); break;
        case H_JEQ_X:  CJ(r[di->dst] == r[di->src]); break;
        case H_JGT_K:  CJ(r[di->dst] > KOP); break;
        case H_JGT_X:  CJ(r[di->dst] > r[di->src]); break;
        case H_JGE_K:  CJ(r[di->dst] >= KOP); break;
        case H_JGE_X:  CJ(r[di->dst] >= r[di->src]); break;
        case H_JSET_K: CJ(r[di->dst] & KOP); break;
        case H_JSET_X: CJ(r[di->dst] & r[di->src]); break;
        case H_JNE_K:  CJ(r[di->dst] != KOP); break;
        case H_JNE_X:  CJ(r[di->dst] != r[di->src]); break;
        case H_JSGT_K: CJ((int64_t)r[di->dst] > (int64_t)di->imm); break;
        case H_JSGT_X: CJ((int64_t)r[di->dst] > (int64_t)r[di->src]); break;
        case H_JSGE_K: CJ((int64_t)r[di->dst] >= (int64_t)di->imm); break;
        case H_JSGE_X: CJ((int64_t)r[di->dst] >= (int64_t)r[di->src]); break;
        case H_JLT_K:  CJ(r[di->dst] < KOP); break;
        case H_JLT_X:  CJ(r[di->dst] < r[di->src]); break;
        case H_JLE_K:  CJ(r[di->dst] <= KOP); break;
        case H_JLE_X:  CJ(r[di->dst] <= r[di->src]); break;
        case H_JSLT_K: CJ((int64_t)r[di->dst] < (int64_t)di->imm); break;
        case H_JSLT_X: CJ((int64_t)r[di->dst] < (int64_t)r[di->src]); break;
        case H_JSLE_K: CJ((int64_t)r[di->dst] <= (int64_t)di->imm); break;
        case H_JSLE_X: CJ((int64_t)r[di->dst] <= (int64_t)r[di->src]); break;

        /* ------------- JMP32 (32-bit compares) ------------- */
#define D32 ((uint32_t)r[di->dst])
#define S32 ((uint32_t)r[di->src])
#define K32 ((uint32_t)di->imm)
        case H_JEQ32_K:  CJ(D32 == K32); break;
        case H_JEQ32_X:  CJ(D32 == S32); break;
        case H_JGT32_K:  CJ(D32 > K32); break;
        case H_JGT32_X:  CJ(D32 > S32); break;
        case H_JGE32_K:  CJ(D32 >= K32); break;
        case H_JGE32_X:  CJ(D32 >= S32); break;
        case H_JSET32_K: CJ(D32 & K32); break;
        case H_JSET32_X: CJ(D32 & S32); break;
        case H_JNE32_K:  CJ(D32 != K32); break;
        case H_JNE32_X:  CJ(D32 != S32); break;
        case H_JSGT32_K: CJ((int32_t)D32 > (int32_t)K32); break;
        case H_JSGT32_X: CJ((int32_t)D32 > (int32_t)S32); break;
        case H_JSGE32_K: CJ((int32_t)D32 >= (int32_t)K32); break;
        case H_JSGE32_X: CJ((int32_t)D32 >= (int32_t)S32); break;
        case H_JLT32_K:  CJ(D32 < K32); break;
        case H_JLT32_X:  CJ(D32 < S32); break;
        case H_JLE32_K:  CJ(D32 <= K32); break;
        case H_JLE32_X:  CJ(D32 <= S32); break;
        case H_JSLT32_K: CJ((int32_t)D32 < (int32_t)K32); break;
        case H_JSLT32_X: CJ((int32_t)D32 < (int32_t)S32); break;
        case H_JSLE32_K: CJ((int32_t)D32 <= (int32_t)K32); break;
        case H_JSLE32_X: CJ((int32_t)D32 <= (int32_t)S32); break;
#undef KOP
#undef CJ
#undef D32
#undef S32
#undef K32

        /* ------------- CALL / EXIT / LD_IMM64 ------------- */
        case H_CALL:
            r[0] = ktx_helper_call(ex, r, di->imm);
            if (ex->status != KTX_OK) VM_RET(ex->status);
            break;

        case H_EXIT:
            ex->r0_out = r[0];
            if (ex->tx) {
                ktx_status cst = ktx_tx_commit(ex->th, ex->pkt,
                                               ex->pkt_len);
                if (cst != KTX_OK) { ex->status = cst; VM_RET(cst); }
            }
            VM_RET(KTX_OK);

        case H_LD_IMM64:
            r[di->dst] = di->imm64;
            pc++;                        /* skip the H_NOP second slot */
            break;

        /* ------------- loads ------------- */
#define LDX_BODY(T) do { \
            T v_; \
            memcpy(&v_, (const void *)(uintptr_t) \
                       (r[di->src] + (uint64_t)(int64_t)di->off), \
                   sizeof(T)); \
            r[di->dst] = v_; \
        } while (0)
#define LDXG_BODY(T) do { \
            uint64_t a_ = r[di->src] + (uint64_t)(int64_t)di->off; \
            GUARD(a_, sizeof(T), 0); \
            T v_; \
            memcpy(&v_, (const void *)(uintptr_t)a_, sizeof(T)); \
            r[di->dst] = v_; \
        } while (0)
        case H_LDXB:    LDX_BODY(uint8_t);  break;
        case H_LDXB_G:  LDXG_BODY(uint8_t); break;
        case H_LDXH:    LDX_BODY(uint16_t); break;
        case H_LDXH_G:  LDXG_BODY(uint16_t); break;
        case H_LDXW:    LDX_BODY(uint32_t); break;
        case H_LDXW_G:  LDXG_BODY(uint32_t); break;
        case H_LDXDW:   LDX_BODY(uint64_t); break;
        case H_LDXDW_G: LDXG_BODY(uint64_t); break;
#undef LDX_BODY
#undef LDXG_BODY

        /* ------------- register stores ------------- */
#define STX_BODY(T) do { \
            T v_ = (T)r[di->src]; \
            memcpy((void *)(uintptr_t) \
                       (r[di->dst] + (uint64_t)(int64_t)di->off), \
                   &v_, sizeof(T)); \
        } while (0)
#define STXG_BODY(T) do { \
            uint64_t a_ = r[di->dst] + (uint64_t)(int64_t)di->off; \
            GUARD(a_, sizeof(T), 1); \
            T v_ = (T)r[di->src]; \
            memcpy((void *)(uintptr_t)a_, &v_, sizeof(T)); \
        } while (0)
        case H_STXB:    STX_BODY(uint8_t);  break;
        case H_STXB_G:  STXG_BODY(uint8_t); break;
        case H_STXH:    STX_BODY(uint16_t); break;
        case H_STXH_G:  STXG_BODY(uint16_t); break;
        case H_STXW:    STX_BODY(uint32_t); break;
        case H_STXW_G:  STXG_BODY(uint32_t); break;
        case H_STXDW:   STX_BODY(uint64_t); break;
        case H_STXDW_G: STXG_BODY(uint64_t); break;
#undef STX_BODY
#undef STXG_BODY

        /* ------------- immediate stores ------------- */
#define ST_BODY(T) do { \
            T v_ = (T)(int64_t)di->imm; \
            memcpy((void *)(uintptr_t) \
                       (r[di->dst] + (uint64_t)(int64_t)di->off), \
                   &v_, sizeof(T)); \
        } while (0)
#define STG_BODY(T) do { \
            uint64_t a_ = r[di->dst] + (uint64_t)(int64_t)di->off; \
            GUARD(a_, sizeof(T), 1); \
            T v_ = (T)(int64_t)di->imm; \
            memcpy((void *)(uintptr_t)a_, &v_, sizeof(T)); \
        } while (0)
        case H_STB:     ST_BODY(uint8_t);  break;
        case H_STB_G:   STG_BODY(uint8_t); break;
        case H_STH:     ST_BODY(uint16_t); break;
        case H_STH_G:   STG_BODY(uint16_t); break;
        case H_STW:     ST_BODY(uint32_t); break;
        case H_STW_G:   STG_BODY(uint32_t); break;
        case H_STDW:    ST_BODY(uint64_t); break;
        case H_STDW_G:  STG_BODY(uint64_t); break;
#undef ST_BODY
#undef STG_BODY

        default:
            /* decode never emits unknown handlers; defensive */
            ex->status = KTX_ABORT_HELPER;
            VM_RET(KTX_ABORT_HELPER);
        }
        pc++;
    }

#undef GUARD
#undef VM_RET
#undef FUEL_CHECK
}
