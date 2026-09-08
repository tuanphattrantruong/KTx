/* vm.c — instantiates the interpreter core twice (fuel / nofuel) and
 * implements ktx_run: region-table setup, mode -> (decoded array, fuel
 * loop) mapping, tx begin/commit/abort orchestration, stats.
 */
#include <string.h>

#include "../ktx/ktx_internal.h"
#include "../jit/jit.h"

/* --- two interpreter instantiations (DESIGN §1.4) --- */
#define VM_FN vm_exec_nofuel
#include "vm_core.inc"
#undef VM_FN

#define VM_FUEL 1
#define VM_FN vm_exec_fuel
#include "vm_core.inc"
#undef VM_FN
#undef VM_FUEL

static int invocation_enter(struct ktx_env *e) {
    uint32_t s = atomic_load_explicit(&e->quiesce_state, memory_order_acquire);
    for (;;) {
        if (s & KTX_QUIESCE_WRITER || (s & ~KTX_QUIESCE_WRITER) ==
                                       KTX_QUIESCE_WRITER - 1)
            return -1;
        if (atomic_compare_exchange_weak_explicit(
                &e->quiesce_state, &s, s + 1, memory_order_acquire,
                memory_order_relaxed))
            return 0;
    }
}

static void invocation_exit(struct ktx_env *e) {
    atomic_fetch_sub_explicit(&e->quiesce_state, 1, memory_order_release);
}

#define VM_FUEL 1
#define VM_AUDIT 1
#define VM_FN vm_exec_audit
#include "vm_core.inc"
#undef VM_FN
#undef VM_AUDIT
#undef VM_FUEL

/* One execution attempt.  Returns the raw status; the caller applies
 * attachment-point policy (default verdict, retry). */
static ktx_status run_once(ktx_thread *t, ktx_prog *p, ktx_mode mode,
                           uint8_t *pkt, uint32_t pkt_len, int64_t fuel,
                           uint64_t *verdict_out, uint32_t *nrecs_out,
                           uint64_t *fuel_used_out) {
    ktx_exec ex;
    ex.code = NULL;
    ex.n = p->n_insns;
    ex.th = t;
    ex.env = t->env;
    ex.prog = p;
    ex.pkt = pkt;
    ex.pkt_len = pkt_len;
    ex.status = KTX_OK;
    ex.r0_out = 0;
    ex.fuel = fuel;
    ex.nheld = 0;
    ex.nheld_maps = 0;
    ex.twopl = 0;
    ex.p2pl = 0;
    ex.audit = 0;
    int coarse = 0;

    /* context + registers */
    ex.ctx.data = (uint64_t)(uintptr_t)pkt;
    ex.ctx.data_end = ex.ctx.data + pkt_len;
    ex.ctx.len = pkt_len;
    ex.ctx._pad = 0;
    memset(ex.regs, 0, sizeof(ex.regs));
    uint64_t fp = (uint64_t)(uintptr_t)(t->stack + KTX_STACK_BYTES);
    ex.regs[10] = fp;                     /* frame pointer (read-only) */
    ex.regs[1] = (uint64_t)(uintptr_t)&ex.ctx;

    /* mode mapping */
    int use_fuel, tx;
    switch (mode) {
    case KTX_MODE_VANILLA:
        ex.code = p->d_vanilla; use_fuel = 0; tx = 0;
        ex.check_args = 0; ex.ro_elide = 0;
        break;
    case KTX_MODE_SFI:
        ex.code = p->d_guarded; use_fuel = 1; tx = 0;
        ex.check_args = 1; ex.ro_elide = 0;
        break;
    case KTX_MODE_TX:
        ex.code = p->d_guarded; use_fuel = 1; tx = 1;
        ex.check_args = 1; ex.ro_elide = 0;
        break;
    case KTX_MODE_TX_ELIDE:
        ex.code = p->d_elided;
        use_fuel = p->fuel_elidable ? 0 : 1;
        tx = 1;
        ex.check_args = 1; ex.ro_elide = 1;
        break;
    case KTX_MODE_TX_AUDIT:
        ex.code = p->d_audit; use_fuel = 1; tx = 1;
        ex.check_args = 1; ex.ro_elide = 0; ex.audit = 1;
        break;
    case KTX_MODE_2PL:
        /* Same instrumentation as sfi (guards + fuel, direct effects);
         * the difference is that helpers take stripe locks and hold them
         * to exit (twopl.c). */
        ex.code = p->d_guarded; use_fuel = 1; tx = 0;
        ex.check_args = 1; ex.ro_elide = 0; ex.twopl = 1;
        break;
    case KTX_MODE_COARSE:
        /* Abort-safe coarse baseline: unlike the eager 2PL strawman, it
         * retains the redo log, but serializes the whole invocation under
         * one environment-wide lock.  This is the strongest simple
         * baseline for applications willing to give up concurrency. */
        ex.code = p->d_guarded; use_fuel = 1; tx = 1; coarse = 1;
        ex.check_args = 1; ex.ro_elide = 0;
        break;
    case KTX_MODE_P2PL:
        /* A fairer pessimistic baseline than lazy key locking: the declared
         * program-map set is acquired in a global order before any effect. */
        ex.code = p->d_guarded; use_fuel = 1; tx = 0; ex.p2pl = 1;
        ex.check_args = 1; ex.ro_elide = 0;
        break;
    default:
        return KTX_ABORT_HELPER;
    }
    ex.tx = (uint8_t)tx;
    if (invocation_enter(t->env) != 0) return KTX_ABORT_HELPER;

    /* region table: slot 0 stack RW, slot 1 ctx RO, slot 2 packet
     * (RW in direct modes, RO in tx modes — packet writes must go
     * through packet_store_bytes). */
    ex.regions[0].base = fp - KTX_STACK_BYTES;
    ex.regions[0].end  = fp;
    ex.regions[0].rw   = 1;
    ex.regions[1].base = (uint64_t)(uintptr_t)&ex.ctx;
    ex.regions[1].end  = ex.regions[1].base + sizeof(struct ktx_ctx);
    ex.regions[1].rw   = 0;
    ex.regions[2].base = ex.ctx.data;
    ex.regions[2].end  = ex.ctx.data_end;
    ex.regions[2].rw   = tx ? 0 : 1;
    ex.nregions = 3;

    /* Native code for this stream, when the program was JIT-compiled at
     * load time.  The JIT compiles the same decoded stream, calls the
     * same helper ABI and the same commit protocol, so switching between
     * these two lines changes exactly one thing: whether the extension
     * *body* is interpreted or native. */
    void *jf = NULL;
    switch (mode) {
    case KTX_MODE_VANILLA:  jf = p->jit_vanilla; break;
    case KTX_MODE_TX_ELIDE: jf = p->jit_elided;  break;
    case KTX_MODE_TX_AUDIT: jf = NULL;  break;   /* audit is interpreted */
    default:                jf = p->jit_guarded; break;
    }

    if (coarse) {
        for (;;) {
            uint32_t expected = 0;
            if (atomic_compare_exchange_weak_explicit(
                    &t->env->coarse_lock, &expected, 1,
                    memory_order_acquire, memory_order_relaxed))
                break;
        }
    }
    if (ex.p2pl) ktx_p2pl_acquire_all(&ex);
    if (tx) ktx_tx_begin(t);

    ktx_status st;
    if (jf)              st = ((ktx_jitfn)jf)(&ex);
    else if (ex.audit)   st = vm_exec_audit(&ex);
    else if (use_fuel)   st = vm_exec_fuel(&ex);
    else                 st = vm_exec_nofuel(&ex);

    /* 2PL: locks are released at exit whether the invocation finished or
     * was stopped mid-flight.  Releasing is not undoing: whatever the
     * invocation already wrote stays written (measured in E3b). */
    if (ex.twopl) ktx_2pl_release_all(&ex);
    if (ex.p2pl) ktx_p2pl_release_all(&ex);
    if (coarse)
        atomic_store_explicit(&t->env->coarse_lock, 0, memory_order_release);
    invocation_exit(t->env);

    *nrecs_out = tx ? t->nrecs : 0;
    if (use_fuel) {
        int64_t rem = ex.fuel;
        if (rem < 0) rem = 0;
        *fuel_used_out = (uint64_t)(fuel - rem);
    } else {
        *fuel_used_out = 0;
    }
    *verdict_out = (st == KTX_OK) ? ex.r0_out : 0;
    if (st != KTX_OK && tx) ktx_tx_abort_reset(t);
    return st;
}

static void count_abort(ktx_thread *t, ktx_status st) {
    switch (st) {
    case KTX_ABORT_GUARD:    t->stats.aborts_guard++; break;
    case KTX_ABORT_FUEL:     t->stats.aborts_fuel++; break;
    case KTX_ABORT_HELPER:   t->stats.aborts_helper++; break;
    case KTX_ABORT_CONFLICT: t->stats.aborts_conflict++; break;
    case KTX_ABORT_CAPACITY: t->stats.aborts_capacity++; break;
    case KTX_ABORT_DEADLOCK: t->stats.aborts_deadlock++; break;
    default: break;
    }
}

ktx_result ktx_run_ex(ktx_thread *t, ktx_prog *p, ktx_mode mode,
                      uint8_t *pkt, uint32_t pkt_len, int64_t fuel,
                      const ktx_policy *pol) {
    ktx_result res = { KTX_OK, KTX_VERDICT_PASS, 0, 0 };
    if (!t || !p || t->env != p->env) {
        res.status = KTX_ABORT_HELPER;
        if (t) t->stats.aborts_helper++;
        return res;
    }
    if (fuel <= 0) fuel = KTX_DEFAULT_FUEL;
    uint64_t dflt = pol ? pol->default_verdict : KTX_VERDICT_PASS;
    uint32_t retries = pol ? pol->max_retries : 0;

    ktx_status st;
    uint64_t verdict = 0, fuel_used = 0;
    uint32_t nrecs = 0;
    for (;;) {
        st = run_once(t, p, mode, pkt, pkt_len, fuel, &verdict, &nrecs,
                      &fuel_used);
        /* Retry is only meaningful, and only *safe*, for transactional
         * modes: an aborted transaction left no effects, so re-executing
         * on the same packet is indistinguishable from a first attempt.
         * Direct-effect modes cannot retry for exactly that reason. */
        if (st != KTX_ABORT_CONFLICT || retries == 0 ||
            (mode != KTX_MODE_TX && mode != KTX_MODE_TX_ELIDE))
            break;
        count_abort(t, st);
        t->stats.retries++;
        retries--;
    }

    res.status = st;
    res.log_records = nrecs;
    res.fuel_used = fuel_used;
    if (st == KTX_OK) {
        res.verdict = verdict;
        t->stats.commits++;
    } else {
        res.verdict = dflt;               /* attachment-point policy */
        count_abort(t, st);
    }
    return res;
}

ktx_result ktx_run(ktx_thread *t, ktx_prog *p, ktx_mode mode,
                   uint8_t *pkt, uint32_t pkt_len, int64_t fuel) {
    const ktx_policy pol = { KTX_VERDICT_PASS, 0 };
    return ktx_run_ex(t, p, mode, pkt, pkt_len, fuel, &pol);
}

uint64_t ktx_thread_last_commit_seq(const ktx_thread *t) {
    return t ? t->last_commit_seq : 0;
}

uint64_t ktx_thread_memory(void) { return sizeof(struct ktx_thread) +
                                          KTX_ARENA_BYTES; }

uint64_t ktx_prog_memory(const ktx_prog *p) {
    if (!p) return 0;
    uint64_t per = (uint64_t)p->n_insns * sizeof(ktx_dinsn);
    return sizeof(struct ktx_prog) + 3 * per;   /* vanilla + guarded + elided */
}
