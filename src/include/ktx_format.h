/* ktx_format.h — byte-level constants and file-format structs for KTx.
 *
 * This header is a frozen contract between package 1 (core runtime) and
 * package 2 (assembler / analyzer / harnesses).  Everything here mirrors
 * DESIGN.md §1–§2 exactly.  Little-endian host assumed (Apple Silicon).
 */
#ifndef KTX_FORMAT_H
#define KTX_FORMAT_H

#include <stdint.h>
#include <assert.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---------------------------------------------------------------- */
/* eBPF instruction encoding (DESIGN §1.1)                          */
/* ---------------------------------------------------------------- */

/* Instruction classes (low 3 bits of opcode). */
#define KTX_CLASS_LD    0x00
#define KTX_CLASS_LDX   0x01
#define KTX_CLASS_ST    0x02
#define KTX_CLASS_STX   0x03
#define KTX_CLASS_ALU   0x04   /* 32-bit ALU, zero-extends */
#define KTX_CLASS_JMP   0x05
#define KTX_CLASS_JMP32 0x06
#define KTX_CLASS_ALU64 0x07
#define KTX_CLASS_MASK  0x07

/* Source bit. */
#define KTX_SRC_K       0x00   /* use imm */
#define KTX_SRC_X       0x08   /* use src reg */
#define KTX_SRC_MASK    0x08

/* ALU / ALU64 operations (high nibble of opcode). */
#define KTX_ALU_ADD     0x00
#define KTX_ALU_SUB     0x10
#define KTX_ALU_MUL     0x20
#define KTX_ALU_DIV     0x30
#define KTX_ALU_OR      0x40
#define KTX_ALU_AND     0x50
#define KTX_ALU_LSH     0x60
#define KTX_ALU_RSH     0x70
#define KTX_ALU_NEG     0x80
#define KTX_ALU_MOD     0x90
#define KTX_ALU_XOR     0xa0
#define KTX_ALU_MOV     0xb0
#define KTX_ALU_ARSH    0xc0
#define KTX_ALUOP_MASK  0xf0

/* JMP / JMP32 operations (high nibble of opcode). */
#define KTX_JMP_JA      0x00   /* JMP class only */
#define KTX_JMP_JEQ     0x10
#define KTX_JMP_JGT     0x20
#define KTX_JMP_JGE     0x30
#define KTX_JMP_JSET    0x40
#define KTX_JMP_JNE     0x50
#define KTX_JMP_JSGT    0x60
#define KTX_JMP_JSGE    0x70
#define KTX_JMP_CALL    0x80   /* opcode 0x85 only */
#define KTX_JMP_EXIT    0x90   /* opcode 0x95 only */
#define KTX_JMP_JLT     0xa0
#define KTX_JMP_JLE     0xb0
#define KTX_JMP_JSLT    0xc0
#define KTX_JMP_JSLE    0xd0

/* Memory access sizes (bits 3-4 of opcode) and mode (bits 5-7). */
#define KTX_SIZE_W      0x00   /* 4 bytes */
#define KTX_SIZE_H      0x08   /* 2 bytes */
#define KTX_SIZE_B      0x10   /* 1 byte  */
#define KTX_SIZE_DW     0x18   /* 8 bytes */
#define KTX_SIZE_MASK   0x18
#define KTX_MODE_IMM    0x00   /* LD_IMM64 */
#define KTX_MODE_MEM    0x60
#define KTX_MODE_MASK   0xe0

/* Frequently used composed opcodes. */
#define KTX_OP_CALL     0x85
#define KTX_OP_EXIT     0x95
#define KTX_OP_LD_IMM64 0x18   /* class LD | size DW | mode IMM; two slots */

/* LD_IMM64 src_reg pseudo values. */
#define KTX_PSEUDO_MAP_FD 1    /* imm = index into program map table */

/* One 8-byte instruction slot, exactly the on-disk layout (little-endian). */
#pragma pack(push, 1)
struct ktx_insn {
    uint8_t  code;             /* opcode */
    uint8_t  regs;             /* (src_reg << 4) | dst_reg */
    int16_t  off;
    int32_t  imm;
};
#pragma pack(pop)

static_assert(sizeof(struct ktx_insn) == 8, "ktx_insn must be 8 bytes");

#define KTX_INSN_DST(i)  ((uint8_t)((i).regs & 0x0f))
#define KTX_INSN_SRC(i)  ((uint8_t)(((i).regs >> 4) & 0x0f))

/* Initializer macro: KTX_INSN(opcode, dst, src, off, imm). */
#define KTX_INSN(op, dst, src, off_, imm_) \
    { (uint8_t)(op), (uint8_t)((((src) & 0x0f) << 4) | ((dst) & 0x0f)), \
      (int16_t)(off_), (int32_t)(imm_) }

/* ---------------------------------------------------------------- */
/* Runtime constants (DESIGN §1.2, §3.5)                            */
/* ---------------------------------------------------------------- */

/* XDP-style verdicts; default verdict on any abort is KTX_PASS. */
#define KTX_VERDICT_ABORTED 0
#define KTX_VERDICT_DROP    1
#define KTX_VERDICT_PASS    2
#define KTX_VERDICT_TX      3

/* Context handed to the program in r1 (24 bytes, read-only). */
struct ktx_ctx {
    uint64_t data;             /* start of packet buffer (host address) */
    uint64_t data_end;         /* one past last packet byte */
    uint32_t len;              /* data_end - data */
    uint32_t _pad;
};
static_assert(sizeof(struct ktx_ctx) == 24, "ktx_ctx must be 24 bytes");

/* Helper IDs (CALL imm). */
#define KTX_HELPER_MAP_LOOKUP      1
#define KTX_HELPER_MAP_UPDATE      2
#define KTX_HELPER_MAP_DELETE      3
#define KTX_HELPER_KTIME_GET_NS    5
#define KTX_HELPER_GET_PRANDOM_U32 7
#define KTX_HELPER_PKT_STORE_BYTES 9
#define KTX_HELPER_RINGBUF_OUTPUT  130

/* Runtime map handle: "KTX\0" tag in the top bytes, map index in the low. */
#define KTX_MAP_HANDLE(idx) (0x4B54580000000000ULL | (uint64_t)(idx))
#define KTX_MAP_HANDLE_TAG_MASK 0xFFFFFFFF00000000ULL
#define KTX_MAP_HANDLE_TAG      0x4B54580000000000ULL

/* ---------------------------------------------------------------- */
/* .kbin program binary layout (DESIGN §2.1)                        */
/* ---------------------------------------------------------------- */

/* "KTXP" as a little-endian u32 read from the file. */
#define KTX_KBIN_MAGIC_LE 0x5058544Bu
#define KTX_KBIN_VERSION  1u

/* Map types. */
#define KTX_MAP_HASH         1u
#define KTX_MAP_ARRAY        2u
#define KTX_MAP_PERCPU_ARRAY 3u

#pragma pack(push, 1)
struct ktx_kbin_hdr {
    uint32_t magic;            /* "KTXP" = 0x5058544B LE */
    uint32_t version;          /* 1 */
    uint32_t n_insns;          /* in 8-byte slots; LD_IMM64 counts as 2 */
    uint32_t n_maps;
    uint32_t min_pkt;          /* harness-enforced min packet length; 0=none */
};

struct ktx_map_desc {
    uint32_t type;             /* KTX_MAP_HASH / ARRAY / PERCPU_ARRAY */
    uint32_t key_size;         /* bytes; ARRAY/PERCPU must use 4 */
    uint32_t value_size;
    uint32_t max_entries;
    char     name[32];         /* NUL-padded, unique within file */
};
#pragma pack(pop)

static_assert(sizeof(struct ktx_kbin_hdr) == 20, "kbin header must be 20 bytes");
static_assert(sizeof(struct ktx_map_desc) == 48, "map_desc must be 48 bytes");

/* ---------------------------------------------------------------- */
/* .elide sidecar layout (DESIGN §2.2)                              */
/* ---------------------------------------------------------------- */

/* "KELD" as a little-endian u32 read from the file. */
#define KTX_ELIDE_MAGIC_LE 0x444C454Bu
#define KTX_ELIDE_VERSION  1u

/* Header flags. */
#define KTX_ELIDE_FLAG_FUEL     0x1u  /* whole program proven bounded */
#define KTX_ELIDE_FLAG_COMPLETE 0x2u  /* analysis completed (else all-zero) */

/* Per-instruction flags (iflags[n_insns]). */
#define KTX_IFLAG_TX_ELIDABLE     0x1u /* bounds guard elidable in TX modes */
#define KTX_IFLAG_DIRECT_ELIDABLE 0x2u /* bounds guard elidable in direct modes */

#pragma pack(push, 1)
struct ktx_elide_hdr {
    uint32_t magic;            /* "KELD" = 0x444C454B LE */
    uint32_t version;          /* 1 */
    uint32_t n_insns;          /* must equal .kbin n_insns */
    uint32_t flags;            /* KTX_ELIDE_FLAG_* */
    uint32_t n_maps;           /* must equal .kbin n_maps */
    /* then: u8 iflags[n_insns]; u8 map_ro[n_maps]; */
};
#pragma pack(pop)

static_assert(sizeof(struct ktx_elide_hdr) == 20, "elide header must be 20 bytes");

#ifdef __cplusplus
}
#endif

#endif /* KTX_FORMAT_H */
