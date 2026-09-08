/* engine.c -> bin/ktxengine : E13, engine calibration.
 *
 * A reviewer's fair question about any prototype's overhead numbers is
 * whether the baseline is a strawman.  This harness answers it without an
 * external dependency: three helper-free kernels, each expressed twice —
 * once as eBPF bytecode (run by our interpreter and by our JIT) and once
 * as the equivalent C, compiled by clang -O2 in this same binary — and
 * timed by literally the same loop.  The ratio of JIT to C is how much
 * engine quality separates our compiled bodies from a real compiler's,
 * and it is the number to keep in mind when reading every JIT-relative
 * overhead elsewhere in the paper.
 */
#include <inttypes.h>
#include <mach/mach_time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ktx.h"
#include "ktx_format.h"
#include "trace.h"

#ifdef KTX_WITH_UBPF
#include <stdbool.h>
#include "ubpf.h"
#endif

#define PKT_CAP 2048u
#define BATCH 32u

/* ---- C equivalents of the three kernels -------------------------------- */
__attribute__((noinline))
static uint64_t c_bytesum(const uint8_t *d) {
    uint64_t s = 0;
    for (uint32_t i = 0; i < 256; i++) s += d[i];
    return s;
}
__attribute__((noinline))
static uint64_t c_hash(const uint8_t *d) {
    uint64_t h;
    memcpy(&h, d + 16, 8);
    for (uint32_t i = 0; i < 64; i++) {
        h ^= h >> 30; h *= 0xBF58476D1CE4E5B9ULL;
        h ^= h >> 27; h *= 0x94D049BB133111EBULL;
        h ^= h >> 31;
    }
    return h;
}
__attribute__((noinline))
static uint64_t c_stride(const uint8_t *d) {
    uint64_t x = 0;
    for (uint32_t i = 0; i < 256; i += 8) {
        uint64_t v;
        memcpy(&v, d + i, 8);
        x ^= v;
    }
    return x;
}

static int cmp_d(const void *a, const void *b) {
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}

static double p50(double *v, size_t n) {
    qsort(v, n, sizeof *v, cmp_d);
    return v[(n - 1) / 2];
}

int main(int argc, char **argv) {
    tr_qos_perf();
    const char *out = NULL, *dir = "workloads";
    uint64_t iters = 200000, warm = 20000, seed = 42;
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i]; const char *v = (i + 1 < argc) ? argv[i+1] : NULL;
#define ARG(n) (strcmp(a, n) == 0 && v && ++i)
        if (ARG("--out")) out = v;
        else if (ARG("--iters")) iters = strtoull(v, NULL, 0);
        else if (ARG("--warmup")) warm = strtoull(v, NULL, 0);
        else if (ARG("--seed")) seed = strtoull(v, NULL, 0);
        else if (ARG("--workloads-dir")) dir = v;
        else { fprintf(stderr, "usage: ktxengine [--iters N] --out F.json\n");
               return 2; }
#undef ARG
    }
    if (!out) { fprintf(stderr, "ktxengine: --out required\n"); return 2; }

    static const char *kern[3] = { "k_bytesum", "k_hash", "k_stride" };
    uint64_t (*cfn[3])(const uint8_t *) = { c_bytesum, c_hash, c_stride };
    /* [kernel][ktx-interp, ktx-jit, native C, ubpf-interp, ubpf-jit] */
    double res[3][5] = {{0}};
    uint64_t sink = 0;

    uint8_t *pkt = malloc(PKT_CAP);
    uint64_t prng = seed;
    uint32_t len = tr_fill_packet(pkt, PKT_CAP, 1, &prng, 256, 256);

    for (int k = 0; k < 3; k++) {
        char kb[512];
        snprintf(kb, sizeof kb, "%s/%s.kbin", dir, kern[k]);
        for (int arm = 0; arm < 2; arm++) {
            char err[512] = {0};
            ktx_env *env = ktx_env_create(1);
            if (arm == 1) ktx_env_set_opt(env, KTX_OPT_JIT, 1);
            ktx_prog *pg = ktx_prog_load(env, kb, NULL, err, sizeof err);
            if (!pg) { fprintf(stderr, "load %s: %s\n", kb, err); return 1; }
            if (arm == 1 && !ktx_prog_is_jitted(pg)) {
                fprintf(stderr, "%s: JIT unavailable\n", kb); return 1;
            }
            ktx_thread *th = ktx_thread_create(env, 0);
            for (uint64_t i = 0; i < warm; i++)
                sink += ktx_run(th, pg, KTX_MODE_VANILLA, pkt, len, 0).verdict;
            uint64_t nb = iters / BATCH;
            double *s = malloc(sizeof(double) * nb);
            for (uint64_t b = 0; b < nb; b++) {
                uint64_t t0 = mach_absolute_time();
                for (uint32_t j = 0; j < BATCH; j++)
                    sink += ktx_run(th, pg, KTX_MODE_VANILLA, pkt, len, 0).verdict;
                uint64_t t1 = mach_absolute_time();
                s[b] = tr_ticks_to_ns(t1 - t0) / BATCH;
            }
            res[k][arm] = p50(s, nb);
            free(s);
            ktx_thread_destroy(th); ktx_prog_free(pg); ktx_env_destroy(env);
        }
        /* native C, same timing loop */
        for (uint64_t i = 0; i < warm; i++) sink += cfn[k](pkt);
        uint64_t nb = iters / BATCH;
        double *s = malloc(sizeof(double) * nb);
        for (uint64_t b = 0; b < nb; b++) {
            uint64_t t0 = mach_absolute_time();
            for (uint32_t j = 0; j < BATCH; j++) sink += cfn[k](pkt);
            uint64_t t1 = mach_absolute_time();
            s[b] = tr_ticks_to_ns(t1 - t0) / BATCH;
        }
        res[k][2] = p50(s, nb);
        free(s);

#ifdef KTX_WITH_UBPF
        /* The same instruction bytes, run by an external eBPF runtime.
         * ubpf is handed a ktx_ctx-shaped block so the identical bytecode
         * works, with its own bounds checking disabled so that what we
         * time is an unguarded body---the same thing our \mvan mode is.
         * That choice favours ubpf, which is the conservative direction
         * for a calibration of our own engines. */
        {
            char kb2[512];
            snprintf(kb2, sizeof kb2, "%s/%s.kbin", dir, kern[k]);
            FILE *bf = fopen(kb2, "rb");
            if (bf) {
                static uint8_t img[1 << 16];
                size_t n2 = fread(img, 1, sizeof img, bf);
                fclose(bf);
                struct ktx_kbin_hdr h;
                memcpy(&h, img, sizeof h);
                size_t coff = sizeof h + (size_t)h.n_maps * 48;
                void *code = img + coff;
                uint32_t clen = (uint32_t)(n2 - coff);
                struct ktx_ctx uctx;
                uctx.data = (uint64_t)(uintptr_t)pkt;
                uctx.data_end = uctx.data + len;
                uctx.len = len; uctx._pad = 0;
                for (int mode = 0; mode < 2; mode++) {
                    struct ubpf_vm *vm = ubpf_create();
                    char *err = NULL;
                    ubpf_toggle_bounds_check(vm, false);
                    uint32_t prev = 0;
                    ubpf_set_instruction_limit(vm, 1u << 24, &prev);
                    if (ubpf_load(vm, code, clen, &err) < 0) {
                        fprintf(stderr, "ubpf load %s: %s\n", kern[k],
                                err ? err : "?");
                        free(err); ubpf_destroy(vm); break;
                    }
                    ubpf_jit_fn jf = NULL;
                    if (mode == 1) {
                        jf = ubpf_compile(vm, &err);
                        if (!jf) {
                            fprintf(stderr, "ubpf jit %s: %s\n", kern[k],
                                    err ? err : "?");
                            free(err); ubpf_destroy(vm); break;
                        }
                    }
                    uint64_t rv = 0;
                    for (uint64_t i2 = 0; i2 < warm; i2++) {
                        if (jf) sink += jf(&uctx, sizeof uctx);
                        else { ubpf_exec(vm, &uctx, sizeof uctx, &rv);
                               sink += rv; }
                    }
                    uint64_t nb2 = iters / BATCH;
                    double *s2 = malloc(sizeof(double) * nb2);
                    for (uint64_t b = 0; b < nb2; b++) {
                        uint64_t t0 = mach_absolute_time();
                        for (uint32_t j = 0; j < BATCH; j++) {
                            if (jf) sink += jf(&uctx, sizeof uctx);
                            else { ubpf_exec(vm, &uctx, sizeof uctx, &rv);
                                   sink += rv; }
                        }
                        uint64_t t1 = mach_absolute_time();
                        s2[b] = tr_ticks_to_ns(t1 - t0) / BATCH;
                    }
                    res[k][3 + mode] = p50(s2, nb2);
                    free(s2);
                    ubpf_destroy(vm);
                }
            }
        }
#endif
    }

    FILE *f = fopen(out, "w");
    if (!f) { perror("fopen"); return 1; }
    fprintf(f, "{\n  \"experiment\": \"e13_engine\",\n  ");
    tr_write_meta(f, seed, argc, argv, (int)BATCH);
    fprintf(f, ",\n  \"runs\": [\n");
    for (int k = 0; k < 3; k++)
        fprintf(f, "    { \"kernel\": \"%s\", \"metrics\": { "
                   "\"interp_ns\": %.3f, \"jit_ns\": %.3f, "
                   "\"native_c_ns\": %.3f, \"ubpf_interp_ns\": %.3f, "
                   "\"ubpf_jit_ns\": %.3f,\n"
                   "        \"jit_speedup_over_interp\": %.3f, "
                   "\"jit_vs_native_c\": %.3f, "
                   "\"interp_vs_ubpf_interp\": %.3f, "
                   "\"jit_vs_ubpf_jit\": %.3f } }%s\n",
                kern[k], res[k][0], res[k][1], res[k][2], res[k][3],
                res[k][4], res[k][0] / res[k][1], res[k][1] / res[k][2],
                res[k][3] > 0 ? res[k][0] / res[k][3] : 0.0,
                res[k][4] > 0 ? res[k][1] / res[k][4] : 0.0,
                k == 2 ? "" : ",");
    fprintf(f, "  ],\n  \"sink\": %" PRIu64 "\n}\n", sink);
    fclose(f);
    for (int k = 0; k < 3; k++)
        fprintf(stderr, "ktxengine: %-10s ktx-interp %8.1f  ktx-jit %7.1f  "
                        "C %6.1f  ubpf-interp %8.1f  ubpf-jit %7.1f\n",
                kern[k], res[k][0], res[k][1], res[k][2], res[k][3],
                res[k][4]);
    free(pkt);
    return 0;
}
