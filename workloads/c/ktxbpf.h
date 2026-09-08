/* ktxbpf.h — the minimal header a KTx workload written in C needs.
 *
 * These workloads are compiled to real eBPF bytecode by clang's BPF
 * backend and loaded through tools/elf2kbin.py, so they exercise the
 * runtime with compiler output — register allocation, spills, unrolled
 * loops and all — rather than with hand-written assembly.  The idioms
 * below are the ordinary libbpf ones: helpers are constant function
 * pointers whose value is the helper id, and a map reference is the
 * address of an object in a maps section, resolved by a relocation.
 */
#ifndef KTXBPF_H
#define KTXBPF_H

#define SEC(name) __attribute__((section(name), used))
#define __always_inline inline __attribute__((always_inline))

typedef unsigned char       __u8;
typedef unsigned short      __u16;
typedef unsigned int        __u32;
typedef unsigned long long  __u64;
typedef signed long long    __s64;

/* Map descriptor; byte-identical to struct ktx_map_desc. */
struct ktx_map_def {
    __u32 type, key_size, value_size, max_entries;
    char  name[32];
};

#define KTX_MAP_HASH         1
#define KTX_MAP_ARRAY        2
#define KTX_MAP_PERCPU_ARRAY 3

#define KTX_MAP(sym, ty, ksz, vsz, mx)                                   \
    struct ktx_map_def sym SEC(".ktxmaps") = { ty, ksz, vsz, mx, #sym }

/* Program context, byte-identical to struct ktx_ctx. */
struct ktx_ctx {
    __u64 data;
    __u64 data_end;
    __u32 len;
    __u32 _pad;
};

#define KTX_ABORTED 0
#define KTX_DROP    1
#define KTX_PASS    2
#define KTX_TX      3

static void *(*map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*map_update_elem)(void *map, const void *key, const void *value,
                               __u64 flags) = (void *)2;
static long (*map_delete_elem)(void *map, const void *key) = (void *)3;
static __u64 (*ktime_get_ns)(void) = (void *)5;
static __u32 (*get_prandom_u32)(void) = (void *)7;
static long (*packet_store_bytes)(void *ctx, __u32 off, const void *from,
                                  __u32 len) = (void *)9;
static long (*ringbuf_output)(void *rb, const void *data, __u64 size,
                              __u64 flags) = (void *)130;

#endif /* KTXBPF_H */
