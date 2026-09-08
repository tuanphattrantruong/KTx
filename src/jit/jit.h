/* jit.h — arm64 template JIT for the KTx instruction subset.
 *
 * Why a JIT exists in this prototype: the interpreter is a 30-1400 ns
 * denominator, large enough to hide the transactional contract's fixed
 * cost.  The JIT removes that denominator.  It compiles the *same*
 * pre-decoded instruction stream the interpreter executes (vanilla,
 * guarded, or sidecar-elided), calls the *same* C helper ABI and commit
 * protocol, and therefore isolates exactly one variable: whether the
 * extension body runs interpreted or as native code.
 *
 * Guard elision is physically real here in the strongest sense: an
 * elided access compiles to a bare load or store with no bounds-check
 * instructions emitted at all, and a program with a proven fuel bound is
 * compiled with no fuel counter.
 */
#ifndef KTX_JIT_H
#define KTX_JIT_H

#include <stddef.h>
#include <stdint.h>

#include "../ktx/ktx_internal.h"

typedef ktx_status (*ktx_jitfn)(ktx_exec *ex);

/* Compile `n` pre-decoded instructions.  use_fuel selects the fuelled
 * variant.  Returns a callable function, or NULL with a message in err
 * (unsupported handler, allocation failure, branch out of range). */
/* code_bytes receives the mapped size (pass it back to ktx_jit_free);
 * emit_bytes, if non-NULL, receives the number of instruction bytes
 * actually emitted, which is the figure to report. */
ktx_jitfn ktx_jit_compile(const ktx_dinsn *code, uint32_t n, int use_fuel,
                          size_t *code_bytes, size_t *emit_bytes,
                          char *err, size_t errlen);
void ktx_jit_free(ktx_jitfn fn, size_t code_bytes);
/* 1 when this build/platform can produce executable pages. */
int ktx_jit_available(void);

#endif /* KTX_JIT_H */
