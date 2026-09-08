/* loader.c — .kbin / .elide parsing, ktx_env and ktx_prog lifecycle,
 * map creation/binding by name (DESIGN §2, §4).  All parsing is
 * bounds-checked; truncated or malformed input produces an errbuf
 * message, never a crash.
 */
#include <mach/mach_time.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../ktx/ktx_internal.h"
#include "../jit/jit.h"

/* ---------------- environment ---------------- */

ktx_env *ktx_env_create(int nthreads) {
    if (nthreads < 1) return NULL;
    struct ktx_env *e = calloc(1, sizeof(*e));
    if (!e) return NULL;
    e->ring = malloc(KTX_RING_BYTES);
    if (!e->ring) {
        free(e);
        return NULL;
    }
    e->nthreads = nthreads;
    e->seed = KTX_ENV_SEED;
    mach_timebase_info_data_t tb;
    mach_timebase_info(&tb);
    e->tb_num = tb.numer;
    e->tb_denom = tb.denom ? tb.denom : 1;
    e->opt_shadow_diff = 1;              /* dirty shadows only (default) */
    e->opt_seq_trace = 0;
    e->opt_observer_publish = 0;
    atomic_store_explicit(&e->commit_seq, 1, memory_order_relaxed);
    atomic_store_explicit(&e->coarse_lock, 0, memory_order_relaxed);
    atomic_store_explicit(&e->publish_lock, 0, memory_order_relaxed);
    atomic_store_explicit(&e->publish_seq, 0, memory_order_relaxed);
    atomic_store_explicit(&e->quiesce_state, 0, memory_order_relaxed);
    return e;
}

int ktx_env_set_opt(ktx_env *e, ktx_opt opt, int value) {
    if (!e) return -1;
    switch (opt) {
    case KTX_OPT_SHADOW_DIFF: e->opt_shadow_diff = value ? 1 : 0; return 0;
    case KTX_OPT_SEQ_TRACE:   e->opt_seq_trace   = value ? 1 : 0; return 0;
    case KTX_OPT_JIT:         e->opt_jit         = value ? 1 : 0; return 0;
    case KTX_OPT_OBSERVER_PUBLISH:
        e->opt_observer_publish = value ? 1 : 0; return 0;
    default: return -1;
    }
}

int ktx_env_get_opt(const ktx_env *e, ktx_opt opt) {
    if (!e) return -1;
    switch (opt) {
    case KTX_OPT_SHADOW_DIFF: return e->opt_shadow_diff;
    case KTX_OPT_SEQ_TRACE:   return e->opt_seq_trace;
    case KTX_OPT_JIT:         return e->opt_jit;
    case KTX_OPT_OBSERVER_PUBLISH: return e->opt_observer_publish;
    default: return -1;
    }
}

void ktx_env_memory(const ktx_env *e, uint64_t *map_bytes,
                    uint64_t *map_meta_bytes, uint64_t *ring_bytes) {
    uint64_t data = 0, meta = 0;
    if (e) {
        for (uint32_t i = 0; i < e->nmaps; i++) {
            const struct ktx_map *m = e->maps[i];
            meta += sizeof(struct ktx_map);      /* includes the 64 stripes */
            if (m->type == KTX_MAP_HASH) {
                data += (uint64_t)m->max_entries * m->node_stride;
                meta += (uint64_t)m->nbuckets * sizeof(uint32_t);
            } else {
                uint64_t n = (uint64_t)m->max_entries * m->value_size;
                if (m->type == KTX_MAP_PERCPU_ARRAY) n *= (uint64_t)m->nthreads;
                data += n;
            }
        }
    }
    if (map_bytes) *map_bytes = data;
    if (map_meta_bytes) *map_meta_bytes = meta;
    if (ring_bytes) *ring_bytes = e ? KTX_RING_BYTES : 0;
}

void ktx_env_destroy(ktx_env *e) {
    if (!e) return;
    for (uint32_t i = 0; i < e->nmaps; i++)
        ktx_map_destroy_internal(e->maps[i]);
    free(e->ring);
    free(e);
}

/* ---------------- program loading ---------------- */

static void set_err(char *errbuf, size_t errlen, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));
static void set_err(char *errbuf, size_t errlen, const char *fmt, ...) {
    if (!errbuf || !errlen) return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(errbuf, errlen, fmt, ap);
    va_end(ap);
}

/* Compile the three decoded streams to native code.  Failure on any
 * stream is not an error: that stream simply keeps running interpreted,
 * which is the same fallback discipline as a missing elision sidecar. */
void ktx_prog_jit(struct ktx_prog *p) {
    char jerr[256];
    if (!ktx_jit_available()) return;
    p->jit_vanilla = (void *)ktx_jit_compile(p->d_vanilla, p->n_insns, 0,
                                             &p->jit_sz_vanilla,
                                             &p->jit_emit_vanilla, jerr,
                                             sizeof jerr);
    p->jit_guarded = (void *)ktx_jit_compile(p->d_guarded, p->n_insns, 1,
                                             &p->jit_sz_guarded,
                                             &p->jit_emit_guarded, jerr,
                                             sizeof jerr);
    p->jit_elided  = (void *)ktx_jit_compile(p->d_elided, p->n_insns,
                                             p->fuel_elidable ? 0 : 1,
                                             &p->jit_sz_elided,
                                             &p->jit_emit_elided, jerr,
                                             sizeof jerr);
}

void ktx_prog_free(ktx_prog *p) {
    if (!p) return;
    ktx_jit_free((ktx_jitfn)p->jit_vanilla, p->jit_sz_vanilla);
    ktx_jit_free((ktx_jitfn)p->jit_guarded, p->jit_sz_guarded);
    ktx_jit_free((ktx_jitfn)p->jit_elided, p->jit_sz_elided);
    free(p->d_vanilla);
    free(p->d_guarded);
    free(p->d_elided);
    free(p->d_audit);
    free(p);
}

uint64_t ktx_prog_jit_bytes(const ktx_prog *p) {
    if (!p) return 0;
    return (uint64_t)(p->jit_emit_vanilla + p->jit_emit_guarded
                      + p->jit_emit_elided);
}

int ktx_prog_is_jitted(const ktx_prog *p) {
    return p && p->jit_guarded != NULL;
}

uint32_t ktx_prog_ninsns(const ktx_prog *p) { return p ? p->n_insns : 0; }

ktx_prog *ktx_prog_load_mem(ktx_env *e, const void *kbin_bytes, size_t n,
                            const void *elide_bytes, size_t elide_n,
                            char *errbuf, size_t errlen) {
    if (errbuf && errlen) errbuf[0] = 0;
    if (!e || !kbin_bytes) {
        set_err(errbuf, errlen, "null environment or image");
        return NULL;
    }
    const uint8_t *b = (const uint8_t *)kbin_bytes;

    struct ktx_kbin_hdr hdr;
    if (n < sizeof(hdr)) {
        set_err(errbuf, errlen, "kbin truncated: %zu bytes < header", n);
        return NULL;
    }
    memcpy(&hdr, b, sizeof(hdr));
    if (hdr.magic != KTX_KBIN_MAGIC_LE) {
        set_err(errbuf, errlen, "bad kbin magic 0x%08x", hdr.magic);
        return NULL;
    }
    if (hdr.version != KTX_KBIN_VERSION) {
        set_err(errbuf, errlen, "unsupported kbin version %u", hdr.version);
        return NULL;
    }
    if (hdr.n_insns == 0 || hdr.n_insns > (1u << 20)) {
        set_err(errbuf, errlen, "implausible n_insns %u", hdr.n_insns);
        return NULL;
    }
    if (hdr.n_maps > KTX_MAX_MAPS) {
        set_err(errbuf, errlen, "n_maps %u exceeds limit %d", hdr.n_maps,
                KTX_MAX_MAPS);
        return NULL;
    }
    size_t want = sizeof(hdr) + (size_t)hdr.n_maps * sizeof(struct ktx_map_desc)
                  + (size_t)hdr.n_insns * sizeof(struct ktx_insn);
    if (n != want) {
        set_err(errbuf, errlen,
                "kbin size mismatch: %zu bytes, expected %zu "
                "(n_insns=%u n_maps=%u)", n, want, hdr.n_insns, hdr.n_maps);
        return NULL;
    }

    ktx_prog *p = calloc(1, sizeof(*p));
    if (!p) {
        set_err(errbuf, errlen, "out of memory");
        return NULL;
    }
    p->env = e;
    p->n_insns = hdr.n_insns;
    p->n_maps = hdr.n_maps;
    p->min_pkt = hdr.min_pkt;

    /* --- maps: create in e, or bind to existing same-name maps --- */
    uint32_t created_from = e->nmaps;    /* rollback point on failure */
#define LOAD_FAIL() do { \
        while (e->nmaps > created_from) { \
            e->nmaps--; \
            ktx_map_destroy_internal(e->maps[e->nmaps]); \
            e->maps[e->nmaps] = NULL; \
        } \
        ktx_prog_free(p); \
        return NULL; \
    } while (0)

    const uint8_t *descp = b + sizeof(hdr);
    for (uint32_t i = 0; i < hdr.n_maps; i++) {
        struct ktx_map_desc d;
        memcpy(&d, descp + (size_t)i * sizeof(d), sizeof(d));
        char name[33];
        memcpy(name, d.name, 32);
        name[32] = 0;
        if (name[0] == 0) {
            set_err(errbuf, errlen, "map %u: empty name", i);
            LOAD_FAIL();
        }
        for (uint32_t j = 0; j < i; j++) {
            struct ktx_map *pm = e->maps[p->map_env_id[j]];
            if (strncmp(pm->name, name, 32) == 0) {
                set_err(errbuf, errlen, "map %u: duplicate name '%s'", i,
                        name);
                LOAD_FAIL();
            }
        }
        int existing = ktx_map_id(e, name);
        if (existing >= 0) {
            struct ktx_map *m = e->maps[existing];
            if (m->type != d.type || m->key_size != d.key_size ||
                m->value_size != d.value_size ||
                m->max_entries != d.max_entries) {
                set_err(errbuf, errlen,
                        "map '%s': spec mismatch with existing map "
                        "(type %u/%u key %u/%u val %u/%u max %u/%u)",
                        name, d.type, m->type, d.key_size, m->key_size,
                        d.value_size, m->value_size, d.max_entries,
                        m->max_entries);
                LOAD_FAIL();
            }
            p->map_env_id[i] = (uint16_t)existing;
        } else {
            struct ktx_map *m =
                ktx_env_map_create(e, d.type, d.key_size, d.value_size,
                                   d.max_entries, name, errbuf, errlen);
            if (!m) LOAD_FAIL();
            p->map_env_id[i] = (uint16_t)m->id;
        }
    }

    /* --- instructions: copy to aligned storage, then decode --- */
    const uint8_t *insp = descp + (size_t)hdr.n_maps *
                                      sizeof(struct ktx_map_desc);
    struct ktx_insn *ins = malloc((size_t)hdr.n_insns *
                                  sizeof(struct ktx_insn));
    if (!ins) {
        set_err(errbuf, errlen, "out of memory");
        LOAD_FAIL();
    }
    memcpy(ins, insp, (size_t)hdr.n_insns * sizeof(struct ktx_insn));

    /* --- elide sidecar (optional) --- */
    const uint8_t *iflags = NULL;
    const uint8_t *map_ro = NULL;
    if (elide_bytes && elide_n) {
        struct ktx_elide_hdr eh;
        if (elide_n < sizeof(eh)) {
            set_err(errbuf, errlen, "elide truncated: %zu bytes", elide_n);
            free(ins);
            LOAD_FAIL();
        }
        memcpy(&eh, elide_bytes, sizeof(eh));
        if (eh.magic != KTX_ELIDE_MAGIC_LE) {
            set_err(errbuf, errlen, "bad elide magic 0x%08x", eh.magic);
            free(ins);
            LOAD_FAIL();
        }
        if (eh.version != KTX_ELIDE_VERSION) {
            set_err(errbuf, errlen, "unsupported elide version %u",
                    eh.version);
            free(ins);
            LOAD_FAIL();
        }
        if (eh.n_insns != hdr.n_insns || eh.n_maps != hdr.n_maps) {
            set_err(errbuf, errlen,
                    "elide mismatch: n_insns %u/%u, n_maps %u/%u",
                    eh.n_insns, hdr.n_insns, eh.n_maps, hdr.n_maps);
            free(ins);
            LOAD_FAIL();
        }
        if (eh.flags & ~(KTX_ELIDE_FLAG_FUEL | KTX_ELIDE_FLAG_COMPLETE)) {
            set_err(errbuf, errlen, "elide has unknown header flags 0x%x",
                    eh.flags);
            free(ins);
            LOAD_FAIL();
        }
        if ((eh.flags & KTX_ELIDE_FLAG_FUEL) &&
            !(eh.flags & KTX_ELIDE_FLAG_COMPLETE)) {
            set_err(errbuf, errlen,
                    "incomplete elide certificate cannot claim fuel bound");
            free(ins);
            LOAD_FAIL();
        }
        size_t ewant = sizeof(eh) + (size_t)eh.n_insns + (size_t)eh.n_maps;
        if (elide_n != ewant) {
            set_err(errbuf, errlen, "elide size mismatch: %zu, expected %zu",
                    elide_n, ewant);
            free(ins);
            LOAD_FAIL();
        }
        const uint8_t *raw_iflags =
            (const uint8_t *)elide_bytes + sizeof(eh);
        const uint8_t *raw_map_ro = raw_iflags + eh.n_insns;
        for (uint32_t i = 0; i < eh.n_insns; i++) {
            if (raw_iflags[i] & ~(KTX_IFLAG_TX_ELIDABLE |
                                  KTX_IFLAG_DIRECT_ELIDABLE)) {
                set_err(errbuf, errlen,
                        "elide instruction %u has unknown flags 0x%x", i,
                        raw_iflags[i]);
                free(ins);
                LOAD_FAIL();
            }
            if (!(eh.flags & KTX_ELIDE_FLAG_COMPLETE) && raw_iflags[i]) {
                set_err(errbuf, errlen,
                        "incomplete elide certificate contains a claim");
                free(ins);
                LOAD_FAIL();
            }
        }
        for (uint32_t i = 0; i < eh.n_maps; i++) {
            if (raw_map_ro[i] > 1 ||
                (!(eh.flags & KTX_ELIDE_FLAG_COMPLETE) && raw_map_ro[i])) {
                set_err(errbuf, errlen, "elide map %u has invalid ro fact %u",
                        i, raw_map_ro[i]);
                free(ins);
                LOAD_FAIL();
            }
        }
        if (eh.flags & KTX_ELIDE_FLAG_COMPLETE) {
            iflags = raw_iflags;
            map_ro = raw_map_ro;
            p->fuel_elidable = (eh.flags & KTX_ELIDE_FLAG_FUEL) ? 1 : 0;
            p->have_elide = 1;
        }
        /* analysis-incomplete sidecar: sound fallback, nothing elided */
    }
    if (map_ro) {
        for (uint32_t i = 0; i < hdr.n_maps; i++) {
            p->map_ro[i] = map_ro[i] ? 1 : 0;
            if (map_ro[i])
                e->maps[p->map_env_id[i]]->ro_elide = 1;
        }
    }

    /* --- decode the four handler arrays --- */
    p->d_vanilla = calloc(hdr.n_insns, sizeof(ktx_dinsn));
    p->d_guarded = calloc(hdr.n_insns, sizeof(ktx_dinsn));
    p->d_elided  = calloc(hdr.n_insns, sizeof(ktx_dinsn));
    p->d_audit   = calloc(hdr.n_insns, sizeof(ktx_dinsn));
    if (!p->d_vanilla || !p->d_guarded || !p->d_elided || !p->d_audit) {
        set_err(errbuf, errlen, "out of memory");
        free(ins);
        LOAD_FAIL();
    }
    if (ktx_decode(ins, hdr.n_insns, hdr.n_maps, iflags,
                   KTX_DECODE_AUDIT, p->d_audit, errbuf, errlen) != 0 ||
        ktx_decode(ins, hdr.n_insns, hdr.n_maps, NULL,
                   KTX_DECODE_VANILLA, p->d_vanilla, errbuf, errlen) != 0 ||
        ktx_decode(ins, hdr.n_insns, hdr.n_maps, NULL,
                   KTX_DECODE_GUARDED, p->d_guarded, errbuf, errlen) != 0 ||
        ktx_decode(ins, hdr.n_insns, hdr.n_maps, iflags,
                   KTX_DECODE_ELIDED, p->d_elided, errbuf, errlen) != 0) {
        free(ins);
        LOAD_FAIL();
    }
    free(ins);
    if (e->opt_jit) ktx_prog_jit(p);
    return p;
#undef LOAD_FAIL
}

/* Read a whole file; returns malloc'd buffer or NULL. */
static void *read_file(const char *path, size_t *len_out,
                       char *errbuf, size_t errlen) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        set_err(errbuf, errlen, "cannot open '%s'", path);
        return NULL;
    }
    if (fseek(f, 0, SEEK_END) != 0) {
        set_err(errbuf, errlen, "cannot seek '%s'", path);
        fclose(f);
        return NULL;
    }
    long sz = ftell(f);
    if (sz < 0 || sz > (64L << 20)) {
        set_err(errbuf, errlen, "implausible size %ld for '%s'", sz, path);
        fclose(f);
        return NULL;
    }
    rewind(f);
    void *buf = malloc(sz ? (size_t)sz : 1);
    if (!buf) {
        set_err(errbuf, errlen, "out of memory reading '%s'", path);
        fclose(f);
        return NULL;
    }
    if (sz && fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        set_err(errbuf, errlen, "short read on '%s'", path);
        free(buf);
        fclose(f);
        return NULL;
    }
    fclose(f);
    *len_out = (size_t)sz;
    return buf;
}

ktx_prog *ktx_prog_load(ktx_env *e, const char *kbin_path,
                        const char *elide_path, char *errbuf, size_t errlen) {
    if (errbuf && errlen) errbuf[0] = 0;
    if (!kbin_path) {
        set_err(errbuf, errlen, "null kbin path");
        return NULL;
    }
    size_t kn = 0, en = 0;
    void *kb = read_file(kbin_path, &kn, errbuf, errlen);
    if (!kb) return NULL;
    void *eb = NULL;
    if (elide_path) {
        eb = read_file(elide_path, &en, errbuf, errlen);
        if (!eb) {
            free(kb);
            return NULL;
        }
    }
    ktx_prog *p = ktx_prog_load_mem(e, kb, kn, eb, en, errbuf, errlen);
    free(kb);
    free(eb);
    return p;
}
