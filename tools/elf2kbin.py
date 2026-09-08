#!/usr/bin/env python3
"""elf2kbin.py — turn a clang-compiled BPF ELF object into a .kbin.

The point of this tool is evidentiary, not engineering: it lets the
workloads be *compiled from C by a real BPF backend* instead of written in
our assembler, so the instruction streams the runtime executes carry a
compiler's register allocation, spills, unrolling and branch layout.

It handles exactly what those workloads need: one program section, the
map objects in `.ktxmaps`, and R_BPF_64_64 relocations that turn `&map`
into KTx's `ld_imm64 rX, <map index>` (src_reg = 1), which is the same
BPF_PSEUDO_MAP_FD convention libbpf uses.  Anything else — a call to a
non-inlined local function, a byte-swap, an atomic — is reported rather
than silently mistranslated, because the decoder would reject it anyway.
"""
import argparse
import struct
import sys

SHT_PROGBITS, SHT_SYMTAB, SHT_STRTAB, SHT_RELA, SHT_REL = 1, 2, 3, 4, 9
R_BPF_64_64, R_BPF_64_ABS64, R_BPF_64_ABS32, R_BPF_64_32 = 1, 2, 3, 10
EM_BPF = 247
MAGIC = b"KTXP"
VERSION = 1


class Sec:
    __slots__ = ("name", "type", "flags", "addr", "off", "size", "link",
                 "info", "entsize", "data", "_nameoff")


def read_elf(path):
    b = open(path, "rb").read()
    if b[:4] != b"\x7fELF" or b[4] != 2 or b[5] != 1:
        raise SystemExit(f"{path}: not a little-endian ELF64 object")
    e_machine, = struct.unpack_from("<H", b, 0x12)
    if e_machine != EM_BPF:
        raise SystemExit(f"{path}: e_machine {e_machine} is not EM_BPF")
    e_shoff, = struct.unpack_from("<Q", b, 0x28)
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", b, 0x3A)
    secs = []
    for i in range(e_shnum):
        o = e_shoff + i * e_shentsize
        s = Sec()
        (nameoff, s.type, s.flags, s.addr, s.off, s.size, s.link, s.info,
         _align, s.entsize) = struct.unpack_from("<IIQQQQIIQQ", b, o)
        s.data = b[s.off:s.off + s.size] if s.type != 8 else b""
        s._nameoff = nameoff
        secs.append(s)
    shstr = secs[e_shstrndx].data
    for s in secs:
        end = shstr.find(b"\0", s._nameoff)
        s.name = shstr[s._nameoff:end].decode()
    return b, secs


def parse_symbols(secs):
    symtab = next((s for s in secs if s.type == SHT_SYMTAB), None)
    if symtab is None:
        raise SystemExit("object has no symbol table")
    strtab = secs[symtab.link].data
    syms = []
    for o in range(0, len(symtab.data), 24):
        st_name, st_info, st_other, st_shndx, st_value, st_size = \
            struct.unpack_from("<IBBHQQ", symtab.data, o)
        end = strtab.find(b"\0", st_name)
        syms.append(dict(name=strtab[st_name:end].decode(), shndx=st_shndx,
                         value=st_value, size=st_size, info=st_info))
    return syms


def convert(obj, progsec, min_pkt, out):
    b, secs = read_elf(obj)
    syms = parse_symbols(secs)
    by_name = {s.name: i for i, s in enumerate(secs)}

    # ---- maps ----------------------------------------------------------
    maps, map_index = [], {}
    if ".ktxmaps" in by_name:
        mi = by_name[".ktxmaps"]
        mdata = secs[mi].data
        entries = sorted((s for s in syms if s["shndx"] == mi and s["name"]),
                         key=lambda s: s["value"])
        for s in entries:
            off = s["value"]
            if off + 48 > len(mdata):
                raise SystemExit(f"map '{s['name']}' runs past .ktxmaps")
            ty, ksz, vsz, mx = struct.unpack_from("<IIII", mdata, off)
            nm = mdata[off + 16:off + 48].split(b"\0")[0].decode()
            if nm != s["name"]:
                raise SystemExit(f"map symbol '{s['name']}' names itself "
                                 f"'{nm}' in .ktxmaps")
            map_index[s["name"]] = len(maps)
            maps.append((nm, ty, ksz, vsz, mx))

    # ---- program section ----------------------------------------------
    cands = [s for s in secs
             if s.type == SHT_PROGBITS and (s.flags & 0x4)   # SHF_EXECINSTR
             and s.size and s.name not in (".text",)] or \
            [s for s in secs if s.name == ".text" and s.size]
    if progsec:
        cands = [s for s in secs if s.name == progsec]
    if not cands:
        raise SystemExit("no program section found")
    if len(cands) > 1:
        raise SystemExit("multiple program sections: "
                         + ", ".join(s.name for s in cands)
                         + " (pass --section)")
    prog = cands[0]
    code = bytearray(prog.data)
    if len(code) % 8:
        raise SystemExit("program section is not a whole number of slots")
    pidx = secs.index(prog)

    # ---- relocations ---------------------------------------------------
    nreloc = 0
    for s in secs:
        if s.type not in (SHT_REL, SHT_RELA) or s.info != pidx:
            continue
        step = 24 if s.type == SHT_RELA else 16
        for o in range(0, len(s.data), step):
            r_offset, r_info = struct.unpack_from("<QQ", s.data, o)
            sym = syms[r_info >> 32]
            rtype = r_info & 0xFFFFFFFF
            if rtype != R_BPF_64_64:
                raise SystemExit(
                    f"unsupported relocation type {rtype} against "
                    f"'{sym['name']}' at +{r_offset:#x}; only map references "
                    f"are supported")
            if sym["name"] not in map_index:
                raise SystemExit(f"relocation against non-map symbol "
                                 f"'{sym['name']}'")
            if code[r_offset] != 0x18:
                raise SystemExit(f"map relocation at +{r_offset:#x} does not "
                                 f"target ld_imm64")
            idx = map_index[sym["name"]]
            code[r_offset + 1] = (code[r_offset + 1] & 0x0F) | (1 << 4)  # src=1
            struct.pack_into("<i", code, r_offset + 4, idx)
            struct.pack_into("<i", code, r_offset + 12, 0)
            nreloc += 1

    # ---- sanity: opcodes the KTx decoder will reject -------------------
    bad = []
    i = 0
    n = len(code) // 8
    while i < n:
        op = code[i * 8]
        src = (code[i * 8 + 1] >> 4) & 0xF
        if op == 0x18:
            i += 2
            continue
        if op == 0x85 and src == 1:
            bad.append((i, op, "BPF_PSEUDO_CALL (non-inlined local function)"))
        if (op & 0xF7) == 0xD4:
            bad.append((i, op, "byte-swap (bswap/endian) not in the subset"))
        if op in (0xDB, 0xC3):
            bad.append((i, op, "atomic op not in the subset"))
        i += 1
    if bad:
        for (i, op, why) in bad[:8]:
            print(f"  insn {i}: opcode {op:#04x}: {why}", file=sys.stderr)
        raise SystemExit(f"{obj}: {len(bad)} unsupported instruction(s)")

    hdr = MAGIC + struct.pack("<IIII", VERSION, n, len(maps), min_pkt)
    mt = b""
    for (nm, ty, ksz, vsz, mx) in maps:
        nb = nm.encode()
        mt += struct.pack("<IIII", ty, ksz, vsz, mx) + nb + b"\0" * (32 - len(nb))
    open(out, "wb").write(hdr + mt + bytes(code))
    print(f"elf2kbin: {obj} [{prog.name}] -> {out}: {n} slots, "
          f"{len(maps)} maps, {nreloc} map relocations, min_pkt={min_pkt}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("obj")
    ap.add_argument("-o", "--out", required=True)
    ap.add_argument("--section", default=None)
    ap.add_argument("--min-pkt", type=int, default=64)
    a = ap.parse_args()
    convert(a.obj, a.section, a.min_pkt, a.out)


if __name__ == "__main__":
    main()
