/* trace.h - packet/Zipf/PRNG generation + run-metadata JSON helpers.
 * Header-only; shared by src/bench/bench.c and src/bench/torn.c.
 * (DESIGN.md sections 2.3, 7, 8.)
 *
 * Deliberately independent of ktx.h: this header only generates traces and
 * writes metadata; the harnesses own all runtime interaction.
 */
#ifndef KTX_TRACE_H
#define KTX_TRACE_H

#include <math.h>
#include <mach/mach_time.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysctl.h>
#include <time.h>

/* ---- PRNG ---------------------------------------------------------------- */

static inline uint64_t tr_splitmix64(uint64_t *s) {
    uint64_t z = (*s += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

/* xorshift64* -- state must be nonzero. */
static inline uint64_t tr_xorshift64s(uint64_t *s) {
    uint64_t x = *s;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    *s = x;
    return x * 0x2545F4914F6CDD1DULL;
}

/* Per-thread seed derivation (DESIGN 12): splitmix64(seed ^ (tid+1)). */
static inline uint64_t tr_thread_seed(uint64_t seed, int tid) {
    uint64_t s = seed ^ (uint64_t)(tid + 1);
    uint64_t v = tr_splitmix64(&s);
    return v ? v : 0x9E3779B97F4A7C15ULL; /* xorshift state must be nonzero */
}

/* ---- Zipf sampler (precomputed CDF + binary search; theta=0 -> uniform) -- */

typedef struct {
    double *cdf;      /* cdf[i] = P(key <= i), length n */
    uint32_t n;
} tr_zipf;

static inline int tr_zipf_init(tr_zipf *z, uint32_t nkeys, double theta) {
    if (nkeys == 0) return -1;
    z->n = nkeys;
    z->cdf = (double *)malloc(sizeof(double) * nkeys);
    if (!z->cdf) return -1;
    double acc = 0.0;
    for (uint32_t i = 0; i < nkeys; i++) {
        acc += (theta == 0.0) ? 1.0 : pow((double)(i + 1), -theta);
        z->cdf[i] = acc;
    }
    for (uint32_t i = 0; i < nkeys; i++) z->cdf[i] /= acc;
    z->cdf[nkeys - 1] = 1.0;
    return 0;
}

static inline void tr_zipf_free(tr_zipf *z) {
    free(z->cdf);
    z->cdf = NULL;
}

static inline uint32_t tr_zipf_sample(const tr_zipf *z, uint64_t *prng) {
    double u = (double)(tr_xorshift64s(prng) >> 11) *
               (1.0 / 9007199254740992.0); /* [0,1) */
    uint32_t lo = 0, hi = z->n - 1;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        if (z->cdf[mid] < u) lo = mid + 1; else hi = mid;
    }
    return lo;
}

/* ---- trace packet layout (DESIGN 7) -------------------------------------- */
/* u32 src_ip@0 (flow id), u32 dst_ip@4, u16 sport@8, u16 dport@10,
 * u8 proto@12, u8 pad[3], u64 flow_key@16, TLV area from @24
 * ({u8 type, u8 len, bytes}, type 0 terminates), rest random payload. */

static inline uint64_t tr_flow_key(uint32_t flow_id) {
    uint64_t s = (uint64_t)flow_id ^ 0xC0FFEE0DDF00DULL;
    return tr_splitmix64(&s);
}

/* Fill pkt (capacity cap bytes) for flow_id; returns packet length drawn
 * uniform in [len_min, len_max] (clamped to cap). */
static inline uint32_t tr_fill_packet(uint8_t *pkt, uint32_t cap,
                                      uint32_t flow_id, uint64_t *prng,
                                      uint32_t len_min, uint32_t len_max) {
    if (len_max < len_min) len_max = len_min;
    uint32_t span = len_max - len_min + 1;
    uint32_t len = len_min + (uint32_t)(tr_xorshift64s(prng) % span);
    if (len > cap) len = cap;

    uint64_t r = tr_xorshift64s(prng);
    memcpy(pkt + 0, &flow_id, 4);                 /* src_ip = flow id */
    uint32_t dst = (uint32_t)r;
    memcpy(pkt + 4, &dst, 4);
    uint16_t sport = (uint16_t)(r >> 32), dport = (uint16_t)(r >> 48);
    memcpy(pkt + 8, &sport, 2);
    memcpy(pkt + 10, &dport, 2);
    pkt[12] = (r >> 16 & 1) ? 6 : 17;             /* tcp/udp */
    pkt[13] = pkt[14] = pkt[15] = 0;
    uint64_t fk = tr_flow_key(flow_id);
    memcpy(pkt + 16, &fk, 8);

    /* valid TLV area from @24: {u8 type in 1..7, u8 len, bytes}, 0-term */
    uint32_t off = 24;
    while (off + 3 <= len) {
        uint64_t rr = tr_xorshift64s(prng);
        uint32_t maxl = len - off - 2;
        if (maxl > 15) maxl = 15;
        uint8_t type = (uint8_t)(1 + (rr % 7));
        uint8_t tlen = (uint8_t)((rr >> 8) % (maxl + 1));
        pkt[off] = type;
        pkt[off + 1] = tlen;
        for (uint32_t j = 0; j < tlen; j++)
            pkt[off + 2 + j] = (uint8_t)(rr >> (16 + 8 * (j & 5)));
        off += 2 + tlen;
        if ((rr >> 60) == 0) break;               /* occasionally stop early */
    }
    if (off < len) pkt[off++] = 0;                /* terminator */
    while (off < len) pkt[off++] = (uint8_t)tr_xorshift64s(prng);
    return len;
}

/* ---- scheduling ----------------------------------------------------------
 * macOS gives no CPU affinity API, so on this asymmetric 4P+4E part the
 * scheduler is free to migrate a measurement onto an efficiency core.
 * Requesting the user-interactive QoS class is the strongest hint
 * available that a thread belongs on a performance core; every harness
 * calls this on the main thread and on each worker before timing starts.
 * It reduces run-to-run dispersion; it does not eliminate it, and the
 * evaluation still reports per-cell ranges. */
static inline void tr_qos_perf(void) {
#if defined(__APPLE__)
    pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0);
#endif
}

/* ---- timing -------------------------------------------------------------- */

static inline mach_timebase_info_data_t *tr_timebase(void) {
    static mach_timebase_info_data_t tb; /* main thread inits before workers */
    if (tb.denom == 0) mach_timebase_info(&tb);
    return &tb;
}

static inline double tr_ticks_to_ns(uint64_t ticks) {
    mach_timebase_info_data_t *tb = tr_timebase();
    return (double)ticks * (double)tb->numer / (double)tb->denom;
}

/* ---- metadata JSON (DESIGN 2.3 envelope "meta" object) ------------------- */

static inline void tr_iso_date(char *buf, size_t n) {
    time_t t = time(NULL);
    struct tm tmv;
    localtime_r(&t, &tmv);
    strftime(buf, n, "%Y-%m-%dT%H:%M:%S%z", &tmv);
}

static inline void tr_json_escape(FILE *f, const char *s) {
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '"' || c == '\\') fprintf(f, "\\%c", c);
        else if (c < 0x20) fprintf(f, "\\u%04x", c);
        else fputc(c, f);
    }
}

/* Writes the "meta": {...} object (including the trailing '}', no comma).
 * latency_batch < 0 omits the field (throughput/torn runs). */
static inline void tr_write_meta(FILE *f, uint64_t seed, int argc,
                                 char **argv, int latency_batch) {
    char datebuf[64] = "unknown";
    tr_iso_date(datebuf, sizeof datebuf);
    char host[256] = "unknown";
    size_t hostlen = sizeof host;
    sysctlbyname("machdep.cpu.brand_string", host, &hostlen, NULL, 0);
    int ncpu = 0;
    size_t ncpulen = sizeof ncpu;
    sysctlbyname("hw.ncpu", &ncpu, &ncpulen, NULL, 0);
    mach_timebase_info_data_t *tb = tr_timebase();
    double gran = (double)tb->numer / (double)tb->denom;

    fprintf(f, "\"meta\": {\n");
    fprintf(f, "    \"date_iso\": \"%s\",\n", datebuf);
    fprintf(f, "    \"host\": \"");
    tr_json_escape(f, host);
    fprintf(f, "\",\n    \"ncpu\": %d,\n", ncpu);
    fprintf(f, "    \"cores_note\": \"Apple Silicon asymmetric P/E cores, "
               "no thread pinning available\",\n");
    fprintf(f, "    \"cc\": \"");
    tr_json_escape(f, __clang_version__);
    fprintf(f, "\",\n");
    fprintf(f, "    \"timer\": \"mach_absolute_time\",\n");
    fprintf(f, "    \"timebase_num\": %u, \"timebase_denom\": %u,\n",
            tb->numer, tb->denom);
    fprintf(f, "    \"timer_granularity_ns\": %.4f,\n", gran);
    if (latency_batch >= 0)
        fprintf(f, "    \"latency_batch\": %d,\n", latency_batch);
    fprintf(f, "    \"seed\": %llu,\n", (unsigned long long)seed);
    fprintf(f, "    \"cmdline\": \"");
    for (int i = 0; i < argc; i++) {
        if (i) fputc(' ', f);
        tr_json_escape(f, argv[i]);
    }
    fprintf(f, "\"\n  }");
}

#endif /* KTX_TRACE_H */
