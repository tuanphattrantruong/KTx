#!/usr/bin/env python3
"""KTx eBPF-subset assembler: text .S -> .kbin (see DESIGN.md sections 1.1, 2.1, 6).

Two-pass assembler over real eBPF instruction encoding (little-endian):
  byte 0   : opcode
  byte 1   : (src_reg << 4) | dst_reg
  bytes 2-3: s16 off
  bytes 4-7: s32 imm

Usage:
  python3 tools/asm.py IN.S [-o OUT.kbin]
  python3 tools/asm.py --selftest
"""
import argparse
import os
import re
import struct
import sys

# ---- encoding constants (DESIGN 1.1) ----------------------------------------
CLS_LD, CLS_LDX, CLS_ST, CLS_STX = 0x0, 0x1, 0x2, 0x3
CLS_ALU, CLS_JMP, CLS_JMP32, CLS_ALU64 = 0x4, 0x5, 0x6, 0x7
SRC_K, SRC_X = 0x00, 0x08
MODE_MEM = 0x60
SIZE = {"w": 0x00, "h": 0x08, "b": 0x10, "dw": 0x18}

ALU_OPS = {"add": 0x0, "sub": 0x1, "mul": 0x2, "div": 0x3, "or": 0x4,
           "and": 0x5, "lsh": 0x6, "rsh": 0x7, "neg": 0x8, "mod": 0x9,
           "xor": 0xa, "mov": 0xb, "arsh": 0xc}
JMP_OPS = {"ja": 0x0, "jeq": 0x1, "jgt": 0x2, "jge": 0x3, "jset": 0x4,
           "jne": 0x5, "jsgt": 0x6, "jsge": 0x7, "jlt": 0xa, "jle": 0xb,
           "jslt": 0xc, "jsle": 0xd}
OP_CALL = 0x85
OP_EXIT = 0x95
OP_LD_IMM64 = 0x18

HELPERS = {"map_lookup_elem": 1, "map_update_elem": 2, "map_delete_elem": 3,
           "ktime_get_ns": 5, "get_prandom_u32": 7, "packet_store_bytes": 9,
           "ringbuf_output": 130}

MAP_TYPES = {"hash": 1, "array": 2, "percpu_array": 3}

MAGIC = b"KTXP"
VERSION = 1


class AsmError(Exception):
    def __init__(self, lineno, msg):
        super().__init__(f"line {lineno}: {msg}")
        self.lineno = lineno


def parse_int(tok, lineno):
    tok = tok.strip()
    try:
        return int(tok, 0)
    except ValueError:
        raise AsmError(lineno, f"bad integer '{tok}'")


def parse_reg(tok, lineno):
    tok = tok.strip().lower()
    m = re.fullmatch(r"r(\d+)", tok)
    if not m:
        raise AsmError(lineno, f"expected register, got '{tok}'")
    n = int(m.group(1))
    if n > 10:
        raise AsmError(lineno, f"register r{n} out of range (r0..r10)")
    return n


MEM_RE = re.compile(r"\[\s*(r\d+)\s*(?:([+-])\s*(0x[0-9a-fA-F]+|\d+)\s*)?\]")


def parse_mem(tok, lineno):
    """'[rN+off]' / '[rN-off]' / '[rN]' -> (reg, off)."""
    m = MEM_RE.fullmatch(tok.strip())
    if not m:
        raise AsmError(lineno, f"bad memory operand '{tok}'")
    reg = parse_reg(m.group(1), lineno)
    off = 0
    if m.group(2):
        off = int(m.group(3), 0)
        if m.group(2) == "-":
            off = -off
    if not (-32768 <= off <= 32767):
        raise AsmError(lineno, f"offset {off} out of s16 range")
    return reg, off


def check_s32(v, lineno, what="immediate"):
    if not (-(1 << 31) <= v <= (1 << 32) - 1):
        raise AsmError(lineno, f"{what} {v} out of 32-bit range")
    # accept unsigned literals up to 2^32-1; wrap to s32 for packing
    if v >= (1 << 31):
        v -= (1 << 32)
    return v


def enc(op, dst, src, off, imm):
    return struct.pack("<BBhi", op & 0xFF, ((src & 0xF) << 4) | (dst & 0xF),
                       off, imm)


class Insn:
    """One parsed instruction (slots = 1, or 2 for lddw)."""

    def __init__(self, lineno, slots):
        self.lineno = lineno
        self.slots = slots

    def emit(self, asm, slot_idx):
        raise NotImplementedError


class Fixed(Insn):
    def __init__(self, lineno, data):
        super().__init__(lineno, len(data) // 8)
        self.data = data

    def emit(self, asm, slot_idx):
        return self.data


class Jump(Insn):
    def __init__(self, lineno, op, dst, src, imm, target):
        super().__init__(lineno, 1)
        self.op, self.dst, self.src, self.imm = op, dst, src, imm
        self.target = target  # label name or int raw offset

    def emit(self, asm, slot_idx):
        if isinstance(self.target, int):
            off = self.target
        else:
            if self.target not in asm.labels:
                raise AsmError(self.lineno, f"undefined label '{self.target}'")
            off = asm.labels[self.target] - (slot_idx + 1)
        if not (-32768 <= off <= 32767):
            raise AsmError(self.lineno, f"branch offset {off} out of s16 range")
        return enc(self.op, self.dst, self.src, off, self.imm)


class Assembler:
    def __init__(self):
        self.min_pkt = 0
        self.maps = []          # list of (name, type, key, value, max)
        self.map_index = {}     # name -> idx
        self.insns = []         # list of Insn
        self.labels = {}        # name -> slot index
        self.nslots = 0

    # -- directives ------------------------------------------------------
    def directive(self, line, lineno):
        parts = line.split()
        if parts[0] == ".min_pkt":
            if len(parts) != 2:
                raise AsmError(lineno, ".min_pkt takes one integer")
            self.min_pkt = parse_int(parts[1], lineno)
            if not (0 <= self.min_pkt <= 0xFFFFFFFF):
                raise AsmError(lineno, ".min_pkt out of u32 range")
        elif parts[0] == ".map":
            if len(parts) != 6:
                raise AsmError(
                    lineno, ".map NAME hash|array|percpu_array key=K value=V max=M")
            name, mtype = parts[1], parts[2]
            if mtype not in MAP_TYPES:
                raise AsmError(lineno, f"unknown map type '{mtype}'")
            if len(name.encode()) > 31:
                raise AsmError(lineno, f"map name '{name}' longer than 31 bytes")
            if name in self.map_index:
                raise AsmError(lineno, f"duplicate map name '{name}'")
            kv = {}
            for p in parts[3:]:
                m = re.fullmatch(r"(key|value|max)=(\d+)", p)
                if not m:
                    raise AsmError(lineno, f"bad map attribute '{p}'")
                kv[m.group(1)] = int(m.group(2))
            if set(kv) != {"key", "value", "max"}:
                raise AsmError(lineno, ".map needs key=, value=, max=")
            t = MAP_TYPES[mtype]
            if t in (2, 3) and kv["key"] != 4:
                raise AsmError(lineno, f"{mtype} maps must use key=4")
            if kv["key"] == 0 or kv["value"] == 0 or kv["max"] == 0:
                raise AsmError(lineno, "map key/value/max must be nonzero")
            self.map_index[name] = len(self.maps)
            self.maps.append((name, t, kv["key"], kv["value"], kv["max"]))
        else:
            raise AsmError(lineno, f"unknown directive '{parts[0]}'")

    # -- instructions ----------------------------------------------------
    def add(self, insn):
        self.insns.append(insn)
        self.nslots += insn.slots

    def instruction(self, line, lineno):
        m = re.match(r"^(\S+)\s*(.*)$", line)
        mnem = m.group(1).lower()
        rest = m.group(2).strip()
        ops = [o.strip() for o in rest.split(",")] if rest else []

        is32 = False
        base = mnem
        if base.endswith("32") and (base[:-2] in ALU_OPS or
                                    base[:-2] in JMP_OPS):
            base = base[:-2]
            is32 = True

        if base in ALU_OPS:
            cls = CLS_ALU if is32 else CLS_ALU64
            opn = ALU_OPS[base]
            if base == "neg":
                if len(ops) != 1:
                    raise AsmError(lineno, "neg rD")
                dst = parse_reg(ops[0], lineno)
                self.add(Fixed(lineno, enc((opn << 4) | SRC_K | cls, dst, 0, 0, 0)))
                return
            if len(ops) != 2:
                raise AsmError(lineno, f"{mnem} rD, (rS|imm)")
            dst = parse_reg(ops[0], lineno)
            if re.fullmatch(r"[rR]\d+", ops[1]):
                src = parse_reg(ops[1], lineno)
                self.add(Fixed(lineno, enc((opn << 4) | SRC_X | cls, dst, src, 0, 0)))
            else:
                imm = check_s32(parse_int(ops[1], lineno), lineno)
                self.add(Fixed(lineno, enc((opn << 4) | SRC_K | cls, dst, 0, 0, imm)))
            return

        if base == "ja":
            if is32:
                raise AsmError(lineno, "ja has no 32-bit form")
            if len(ops) != 1:
                raise AsmError(lineno, "ja LABEL")
            self.add(self._jump(lineno, (JMP_OPS["ja"] << 4) | SRC_K | CLS_JMP,
                                0, 0, 0, ops[0]))
            return

        if base in JMP_OPS:
            cls = CLS_JMP32 if is32 else CLS_JMP
            if len(ops) != 3:
                raise AsmError(lineno, f"{mnem} rD, (rS|imm), LABEL")
            dst = parse_reg(ops[0], lineno)
            opn = JMP_OPS[base]
            if re.fullmatch(r"[rR]\d+", ops[1]):
                src = parse_reg(ops[1], lineno)
                self.add(self._jump(lineno, (opn << 4) | SRC_X | cls, dst, src,
                                    0, ops[2]))
            else:
                imm = check_s32(parse_int(ops[1], lineno), lineno)
                self.add(self._jump(lineno, (opn << 4) | SRC_K | cls, dst, 0,
                                    imm, ops[2]))
            return

        m2 = re.fullmatch(r"(ldx|stx|st)(b|h|w|dw)", base)
        if m2:
            kind, sz = m2.group(1), m2.group(2)
            szbits = SIZE[sz]
            if len(ops) != 2:
                raise AsmError(lineno, f"{mnem} takes two operands")
            if kind == "ldx":
                dst = parse_reg(ops[0], lineno)
                src, off = parse_mem(ops[1], lineno)
                self.add(Fixed(lineno, enc(MODE_MEM | szbits | CLS_LDX,
                                           dst, src, off, 0)))
            elif kind == "stx":
                dst, off = parse_mem(ops[0], lineno)
                src = parse_reg(ops[1], lineno)
                self.add(Fixed(lineno, enc(MODE_MEM | szbits | CLS_STX,
                                           dst, src, off, 0)))
            else:  # st imm
                dst, off = parse_mem(ops[0], lineno)
                imm = check_s32(parse_int(ops[1], lineno), lineno)
                self.add(Fixed(lineno, enc(MODE_MEM | szbits | CLS_ST,
                                           dst, 0, off, imm)))
            return

        if base == "lddw":
            if len(ops) != 2:
                raise AsmError(lineno, "lddw rD, imm64 | lddw rD, map:NAME")
            dst = parse_reg(ops[0], lineno)
            if ops[1].lower().startswith("map:"):
                name = ops[1][4:].strip()
                if name not in self.map_index:
                    raise AsmError(lineno, f"unknown map '{name}'")
                idx = self.map_index[name]
                data = enc(OP_LD_IMM64, dst, 1, 0, idx) + enc(0, 0, 0, 0, 0)
                self.add(Fixed(lineno, data))
            else:
                v = parse_int(ops[1], lineno)
                if not (-(1 << 63) <= v < (1 << 64)):
                    raise AsmError(lineno, f"imm64 {v} out of range")
                v &= (1 << 64) - 1
                lo = v & 0xFFFFFFFF
                hi = (v >> 32) & 0xFFFFFFFF
                if lo >= (1 << 31):
                    lo -= (1 << 32)
                if hi >= (1 << 31):
                    hi -= (1 << 32)
                data = enc(OP_LD_IMM64, dst, 0, 0, lo) + enc(0, 0, 0, 0, hi)
                self.add(Fixed(lineno, data))
            return

        if base == "call":
            if len(ops) != 1:
                raise AsmError(lineno, "call NAME|num")
            tok = ops[0]
            if tok in HELPERS:
                hid = HELPERS[tok]
            else:
                hid = parse_int(tok, lineno)
            if not (0 <= hid <= 0x7FFFFFFF):
                raise AsmError(lineno, f"helper id {hid} out of range")
            self.add(Fixed(lineno, enc(OP_CALL, 0, 0, 0, hid)))
            return

        if base == "exit":
            if ops:
                raise AsmError(lineno, "exit takes no operands")
            self.add(Fixed(lineno, enc(OP_EXIT, 0, 0, 0, 0)))
            return

        raise AsmError(lineno, f"unknown mnemonic '{mnem}'")

    def _jump(self, lineno, op, dst, src, imm, target):
        target = target.strip()
        if re.fullmatch(r"[+-]\d+", target):
            return Jump(lineno, op, dst, src, imm, int(target))
        if not re.fullmatch(r"[A-Za-z_.$][\w.$]*", target):
            raise AsmError(lineno, f"bad jump target '{target}'")
        return Jump(lineno, op, dst, src, imm, target)

    # -- driver ----------------------------------------------------------
    def assemble(self, text):
        for lineno, raw in enumerate(text.splitlines(), 1):
            line = raw.split(";", 1)[0].strip()
            if not line:
                continue
            # labels (possibly several, possibly followed by an instruction)
            while True:
                m = re.match(r"^([A-Za-z_.$][\w.$]*)\s*:\s*(.*)$", line)
                if not m:
                    break
                label = m.group(1)
                if label in self.labels:
                    raise AsmError(lineno, f"duplicate label '{label}'")
                self.labels[label] = self.nslots
                line = m.group(2).strip()
            if not line:
                continue
            if line.startswith("."):
                self.directive(line, lineno)
            else:
                self.instruction(line, lineno)
        if self.nslots == 0:
            raise AsmError(0, "empty program")
        # second pass: resolve jumps and emit
        out = bytearray()
        slot = 0
        for insn in self.insns:
            out += insn.emit(self, slot)
            slot += insn.slots
        assert slot == self.nslots
        return bytes(out)

    def kbin(self, text):
        code = self.assemble(text)
        hdr = MAGIC + struct.pack("<IIII", VERSION, self.nslots,
                                  len(self.maps), self.min_pkt)
        mt = b""
        for (name, t, k, v, mx) in self.maps:
            nb = name.encode()
            mt += struct.pack("<IIII", t, k, v, mx) + nb + b"\0" * (32 - len(nb))
        return hdr + mt + code


# ---- self-test: golden vectors from DESIGN 1.1 -------------------------------
GOLDEN = [
    ("mov r1, 7", bytes.fromhex("b701000007000000")),
    ("add r2, r3", bytes.fromhex("0f32000000000000")),
    ("ldxw r0, [r1+16]", bytes.fromhex("6110100000000000")),
    ("jeq r0, 0, +5", bytes.fromhex("1500050000000000")),
    ("call 1", bytes.fromhex("8500000001000000")),
    ("exit", bytes.fromhex("9500000000000000")),
    ("stxdw [r10-8], r7", bytes.fromhex("7b7af8ff00000000")),
    (".map m0 hash key=8 value=16 max=4\nlddw r1, map:m0",
     bytes.fromhex("1811000000000000") + bytes(8)),
]


def selftest():
    ok = True
    for i, (src, want) in enumerate(GOLDEN):
        a = Assembler()
        try:
            blob = a.kbin(src)
        except AsmError as e:
            print(f"golden {i}: ASSEMBLY ERROR: {e}")
            ok = False
            continue
        code = blob[20 + 48 * len(a.maps):]
        if code != want:
            print(f"golden {i} FAIL: '{src.splitlines()[-1]}'\n"
                  f"  want {want.hex()}\n  got  {code.hex()}")
            ok = False
        else:
            print(f"golden {i} PASS: {src.splitlines()[-1]!r} -> {code.hex()}")
    print("selftest:", "ALL PASS" if ok else "FAILURES")
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description="KTx eBPF-subset assembler")
    ap.add_argument("input", nargs="?", help="input .S file")
    ap.add_argument("-o", "--output", help="output .kbin (default: stem.kbin)")
    ap.add_argument("--selftest", action="store_true",
                    help="verify golden encoding vectors")
    args = ap.parse_args()

    if args.selftest:
        sys.exit(selftest())
    if not args.input:
        ap.error("input file required (or --selftest)")
    out = args.output or os.path.splitext(args.input)[0] + ".kbin"
    try:
        with open(args.input) as f:
            text = f.read()
    except OSError as e:
        print(f"asm.py: cannot read {args.input}: {e}", file=sys.stderr)
        sys.exit(1)
    a = Assembler()
    try:
        blob = a.kbin(text)
    except AsmError as e:
        print(f"asm.py: {args.input}: {e}", file=sys.stderr)
        sys.exit(1)
    with open(out, "wb") as f:
        f.write(blob)
    print(f"asm.py: {args.input} -> {out}: {a.nslots} slots, "
          f"{len(a.maps)} maps, min_pkt={a.min_pkt}")


if __name__ == "__main__":
    main()
