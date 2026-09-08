#!/usr/bin/env python3
"""KTx guard-elision analyzer (DESIGN.md section 5).

Parses a .kbin program, runs interval/type abstract interpretation over the
CFG (worklist dataflow, join = type-meet + interval hull, widening to +-inf on
the 3rd changed visit of a block -- loop heads in practice), performs branch
refinement, counted-loop detection for fuel elision, and per-map read-only
proofs. Emits the byte-exact .elide sidecar (DESIGN 2.2) plus a stats JSON.

Soundness stance: every fact defaults to "not elidable"; any unsupported
construct bails to an all-zero sidecar with flags.bit1 (analysis-complete) = 0.

Usage: python3 src/elide/elide.py IN.kbin [-o OUT.elide] [--json OUT.json]
"""
import argparse
import json
import os
import struct
import sys
import time

INF = float("inf")
NINF = float("-inf")
S64_MIN, S64_MAX = -(1 << 63), (1 << 63) - 1
U32_MAX = (1 << 32) - 1
FUEL_BUDGET = 65536
STACK_SIZE = 512
NGRAN = 64          # 8-byte stack granules
MAX_DATAFLOW_STEPS = 65536

# instruction classes / helpers (DESIGN 1.1, 3.5)
CLS_LD, CLS_LDX, CLS_ST, CLS_STX = 0, 1, 2, 3
CLS_ALU, CLS_JMP, CLS_JMP32, CLS_ALU64 = 4, 5, 6, 7
H_LOOKUP, H_UPDATE, H_DELETE, H_KTIME, H_PRANDOM, H_PSB, H_RINGBUF = \
    1, 2, 3, 5, 7, 9, 130
KNOWN_HELPERS = {H_LOOKUP, H_UPDATE, H_DELETE, H_KTIME, H_PRANDOM, H_PSB,
                 H_RINGBUF}

# Abstract values: tuples, first element is the type tag.
#  ('UNK',)                  unknown
#  ('SC', lo, hi)            scalar, signed-64 interval with +-inf
#  ('STK', lo, hi)           stack pointer, offset interval relative to fp
#  ('CTX', lo, hi)           ctx pointer + offset
#  ('PKT', lo, hi)           packet pointer + offset
#  ('END',)                  pkt data_end
#  ('MV', m, lo, hi)         map-value pointer for map m + offset
#  ('MH', m)                 map handle (lddw src=1)
#  ('NM', m)                 NULL or map-value(base) for map m
UNK = ("UNK",)
SC_TOP = ("SC", NINF, INF)


class Bail(Exception):
    pass


def sc(lo, hi):
    if lo == hi and lo in (INF, NINF):
        return SC_TOP
    if lo != NINF and (lo < S64_MIN or lo > S64_MAX):
        lo = NINF
    if hi != INF and (hi < S64_MIN or hi > S64_MAX):
        hi = INF
    if lo > hi:  # empty (unreachable) -- caller checks
        return None
    return ("SC", lo, hi)


def sc_width(nbytes):
    return ("SC", 0, (1 << (8 * nbytes)) - 1)


def iadd(a, b):
    if a in (INF, NINF):
        return a
    if b in (INF, NINF):
        return b
    return a + b


def isub(a, b):
    return iadd(a, -b if b not in (INF, NINF) else (NINF if b == INF else INF))


def hull(a1, b1, a2, b2):
    return (min(a1, a2), max(b1, b2))


def join(v1, v2):
    if v1 == v2:
        return v1
    t1, t2 = v1[0], v2[0]
    if t1 == "SC" and t2 == "SC":
        lo, hi = hull(v1[1], v1[2], v2[1], v2[2])
        return ("SC", lo, hi)
    if t1 == t2 and t1 in ("STK", "CTX", "PKT"):
        lo, hi = hull(v1[1], v1[2], v2[1], v2[2])
        return (t1, lo, hi)
    if t1 == "MV" and t2 == "MV" and v1[1] == v2[1]:
        lo, hi = hull(v1[2], v1[3], v2[2], v2[3])
        return ("MV", v1[1], lo, hi)
    if t1 == "NM" and t2 == "MV" and v1[1] == v2[1] and v2[2:] == (0, 0):
        return v1
    if t1 == "MV" and t2 == "NM" and v1[1] == v2[1] and v1[2:] == (0, 0):
        return v2
    return UNK


def widen_pair(old, new):
    """Widen interval growth in `new` relative to `old` to +-inf."""
    if old == new or old[0] != new[0]:
        return new
    t = new[0]
    if t in ("SC", "STK", "CTX", "PKT"):
        lo = new[1] if new[1] >= old[1] else NINF
        hi = new[2] if new[2] <= old[2] else INF
        return (t, lo, hi)
    if t == "MV" and new[1] == old[1]:
        lo = new[2] if new[2] >= old[2] else NINF
        hi = new[3] if new[3] <= old[3] else INF
        return ("MV", new[1], lo, hi)
    return new


def join_state(s1, s2):
    regs = tuple(join(a, b) for a, b in zip(s1[0], s2[0]))
    stk = tuple(join(a, b) for a, b in zip(s1[1], s2[1]))
    return (regs, stk)


def widen_state(old, new):
    regs = tuple(widen_pair(a, b) for a, b in zip(old[0], new[0]))
    stk = tuple(widen_pair(a, b) for a, b in zip(old[1], new[1]))
    return (regs, stk)


# ---------------------------------------------------------------------------
# .kbin parsing and decoding to logical instructions
# ---------------------------------------------------------------------------

def parse_kbin(path):
    with open(path, "rb") as f:
        blob = f.read()
    if len(blob) < 20 or blob[:4] != b"KTXP":
        raise SystemExit(f"elide.py: {path}: not a KTXP file")
    version, n_insns, n_maps, min_pkt = struct.unpack_from("<IIII", blob, 4)
    if version != 1:
        raise SystemExit(f"elide.py: {path}: unsupported version {version}")
    off = 20
    maps = []
    for _ in range(n_maps):
        if off + 48 > len(blob):
            raise SystemExit(f"elide.py: {path}: truncated map table")
        t, ks, vs, mx = struct.unpack_from("<IIII", blob, off)
        name = blob[off + 16:off + 48].split(b"\0", 1)[0].decode()
        maps.append({"type": t, "key_size": ks, "value_size": vs,
                     "max_entries": mx, "name": name})
        off += 48
    if off + 8 * n_insns > len(blob):
        raise SystemExit(f"elide.py: {path}: truncated instruction stream")
    slots = []
    for i in range(n_insns):
        op, regs, soff, imm = struct.unpack_from("<BBhi", blob, off + 8 * i)
        slots.append((op, regs & 0xF, (regs >> 4) & 0xF, soff, imm))
    return {"n_insns": n_insns, "min_pkt": min_pkt, "maps": maps,
            "slots": slots}


def decode(kb):
    """Slots -> logical insns. Raises Bail on anything unsupported."""
    slots = kb["slots"]
    insns = []          # dicts
    slot_to_log = {}
    i = 0
    while i < len(slots):
        op, dst, src, off, imm = slots[i]
        ins = {"slot": i, "op": op, "dst": dst, "src": src, "off": off,
               "imm": imm, "slots": 1}
        cls = op & 7
        if op == 0x18:  # LD_IMM64
            if i + 1 >= len(slots):
                raise Bail("lddw at end of program")
            op2, d2, s2, off2, imm2 = slots[i + 1]
            if op2 != 0 or d2 != 0 or s2 != 0 or off2 != 0:
                raise Bail("malformed lddw second slot")
            ins["kind"] = "lddw"
            ins["slots"] = 2
            ins["imm64"] = (imm & 0xFFFFFFFF) | ((imm2 & 0xFFFFFFFF) << 32)
            ins["is_map"] = (src == 1)
            if src not in (0, 1):
                raise Bail(f"lddw src_reg {src} unsupported")
            if src == 1 and not (0 <= imm < len(kb["maps"])):
                raise Bail(f"lddw map index {imm} out of range")
        elif op == 0x85:
            ins["kind"] = "call"
            if imm not in KNOWN_HELPERS:
                raise Bail(f"unknown helper {imm}")
        elif op == 0x95:
            ins["kind"] = "exit"
        elif cls in (CLS_ALU, CLS_ALU64):
            opn = op >> 4
            if opn > 0xC:
                raise Bail(f"bad ALU op {op:#x}")
            ins["kind"] = "alu"
            ins["aluop"] = opn
            ins["is32"] = (cls == CLS_ALU)
            ins["xsrc"] = bool(op & 8)
        elif cls in (CLS_JMP, CLS_JMP32):
            opn = op >> 4
            if opn == 0 and cls == CLS_JMP:
                ins["kind"] = "ja"
            elif opn in (1, 2, 3, 4, 5, 6, 7, 0xA, 0xB, 0xC, 0xD):
                ins["kind"] = "jcc"
                ins["jop"] = opn
                ins["is32"] = (cls == CLS_JMP32)
                ins["xsrc"] = bool(op & 8)
            else:
                raise Bail(f"bad JMP op {op:#x}")
        elif cls in (CLS_LDX, CLS_STX, CLS_ST):
            if (op & 0xE0) != 0x60:
                raise Bail(f"bad mem mode {op:#x}")
            size = {0x00: 4, 0x08: 2, 0x10: 1, 0x18: 8}[op & 0x18]
            ins["kind"] = {CLS_LDX: "ldx", CLS_STX: "stx", CLS_ST: "st"}[cls]
            ins["size"] = size
        else:
            raise Bail(f"unknown opcode {op:#x}")
        slot_to_log[i] = len(insns)
        insns.append(ins)
        i += ins["slots"]
    # resolve jump targets to logical indices
    for li, ins in enumerate(insns):
        if ins["kind"] in ("ja", "jcc"):
            tslot = ins["slot"] + 1 + ins["off"]
            if tslot not in slot_to_log:
                raise Bail(f"jump target slot {tslot} invalid")
            ins["target"] = slot_to_log[tslot]
            ins["fall"] = li + 1
            if ins["kind"] == "jcc" and li + 1 >= len(insns):
                raise Bail("conditional jump falls off program end")
    return insns


def build_cfg(insns):
    leaders = {0}
    for li, ins in enumerate(insns):
        if ins["kind"] in ("ja", "jcc"):
            leaders.add(ins["target"])
            if li + 1 < len(insns):
                leaders.add(li + 1)
        elif ins["kind"] == "exit" and li + 1 < len(insns):
            leaders.add(li + 1)
    order = sorted(leaders)
    block_of = {}
    blocks = []
    for bi, start in enumerate(order):
        end = order[bi + 1] if bi + 1 < len(order) else len(insns)
        blocks.append({"id": bi, "insns": list(range(start, end)), "succ": []})
        for li in range(start, end):
            block_of[li] = bi
    for b in blocks:
        last = insns[b["insns"][-1]]
        if last["kind"] == "exit":
            pass
        elif last["kind"] == "ja":
            b["succ"] = [block_of[last["target"]]]
        elif last["kind"] == "jcc":
            b["succ"] = [block_of[last["fall"]], block_of[last["target"]]]
        else:
            nxt = b["insns"][-1] + 1
            if nxt >= len(insns):
                raise Bail("program falls off the end")
            b["succ"] = [block_of[nxt]]
    preds = [[] for _ in blocks]
    for b in blocks:
        for s in b["succ"]:
            preds[s].append(b["id"])
    return blocks, preds, block_of


# ---------------------------------------------------------------------------
# Transfer functions
# ---------------------------------------------------------------------------

class Analyzer:
    def __init__(self, kb, insns, blocks, preds):
        self.kb = kb
        self.insns = insns
        self.blocks = blocks
        self.preds = preds
        self.min_pkt = kb["min_pkt"]
        self.maps = kb["maps"]
        nm = len(self.maps)
        # RO bookkeeping (filled in the facts pass)
        self.map_written = [False] * nm
        self.iflags = [0] * kb["n_insns"]
        self.n_mem = sum(1 for i in insns if i["kind"] in ("ldx", "stx", "st"))

    # -- ALU ------------------------------------------------------------
    def alu(self, opn, dstv, srcv, is32):
        if opn == 0xB:  # MOV
            res = srcv
        elif opn == 0x0:  # ADD
            res = self._add(dstv, srcv)
        elif opn == 0x1:  # SUB
            res = self._sub(dstv, srcv)
        elif dstv[0] != "SC" or srcv[0] != "SC":
            res = UNK if opn != 0x8 else UNK
        else:
            res = self._sc_alu(opn, dstv, srcv)
        if is32:
            if res is not None and res[0] == "SC" and res[1] >= 0 and \
                    res[2] <= U32_MAX:
                return res
            return ("SC", 0, U32_MAX)
        return res if res is not None else SC_TOP

    def _add(self, a, b):
        if a[0] == "SC" and b[0] == "SC":
            return sc(iadd(a[1], b[1]), iadd(a[2], b[2])) or SC_TOP
        for p, s in ((a, b), (b, a)):
            if p[0] in ("STK", "CTX", "PKT") and s[0] == "SC":
                return (p[0], iadd(p[1], s[1]), iadd(p[2], s[2]))
            if p[0] == "MV" and s[0] == "SC":
                return ("MV", p[1], iadd(p[2], s[1]), iadd(p[3], s[2]))
        return UNK

    def _sub(self, a, b):
        if a[0] == "SC" and b[0] == "SC":
            return sc(isub(a[1], b[2]), isub(a[2], b[1])) or SC_TOP
        if a[0] in ("STK", "CTX", "PKT") and b[0] == "SC":
            return (a[0], isub(a[1], b[2]), isub(a[2], b[1]))
        if a[0] == "MV" and b[0] == "SC":
            return ("MV", a[1], isub(a[2], b[2]), isub(a[3], b[1]))
        ptrish = ("STK", "CTX", "PKT", "MV", "END")
        if a[0] in ptrish and b[0] in ptrish:
            return SC_TOP  # e.g. data_end - data
        return UNK

    def _sc_alu(self, opn, a, b):
        lo1, hi1, lo2, hi2 = a[1], a[2], b[1], b[2]
        const = lo2 == hi2 and lo2 not in (INF, NINF)
        c = lo2 if const else None
        nonneg = lo1 >= 0
        if opn == 0x2:  # MUL
            if const and lo1 == hi1 and lo1 not in (INF, NINF):
                v = lo1 * c
                if S64_MIN <= v <= S64_MAX:
                    return ("SC", v, v)
            return SC_TOP
        if opn == 0x3:  # DIV (unsigned; div by 0 -> 0)
            if const and c > 0 and nonneg:
                return sc(0, hi1 // c if hi1 != INF else INF) or SC_TOP
            if const and c == 0:
                return ("SC", 0, 0)
            return SC_TOP
        if opn == 0x9:  # MOD (unsigned; mod by 0 -> dst unchanged)
            if const and c > 0:
                if c <= S64_MAX:
                    return ("SC", 0, c - 1)
            if const and c == 0:
                return a
            return SC_TOP
        if opn == 0x4:  # OR
            if const and c >= 0 and nonneg and hi1 != INF:
                return sc(max(lo1, c), hi1 + c) or SC_TOP
            return SC_TOP
        if opn == 0x5:  # AND
            if const and c >= 0:
                return ("SC", 0, c)
            if nonneg and lo2 >= 0:
                m = min(hi1, hi2)
                return ("SC", 0, m) if m != INF else ("SC", 0, INF)
            return SC_TOP
        if opn == 0xA:  # XOR
            if const and c >= 0 and nonneg and hi1 != INF:
                bits = max(hi1, c).bit_length()
                return ("SC", 0, (1 << bits) - 1)
            return SC_TOP
        if opn == 0x6:  # LSH
            if const:
                c &= 63
                if nonneg and hi1 != INF and (hi1 << c) <= S64_MAX:
                    return ("SC", lo1 << c, hi1 << c)
            return SC_TOP
        if opn == 0x7:  # RSH (logical)
            if const:
                c &= 63
                if c == 0:
                    return a
                cap = (1 << (64 - c)) - 1
                if nonneg:
                    lo = lo1 >> c if lo1 != INF else cap
                    hi = hi1 >> c if hi1 != INF else cap
                    return ("SC", lo, min(hi, cap))
                return ("SC", 0, cap)
            return SC_TOP
        if opn == 0xC:  # ARSH
            if const:
                c &= 63
                lo = lo1 >> c if lo1 not in (INF, NINF) else lo1
                hi = hi1 >> c if hi1 not in (INF, NINF) else hi1
                return sc(lo, hi) or SC_TOP
            return SC_TOP
        if opn == 0x8:  # NEG (unary; b is dst itself here, ignore)
            return sc(isub(0, hi1), isub(0, lo1)) or SC_TOP
        return SC_TOP

    # -- memory ----------------------------------------------------------
    def granules_of(self, lo, hi, size):
        """Stack granule indices possibly touched by access at fp-relative
        [lo, hi+size)."""
        if lo in (INF, NINF) or hi in (INF, NINF):
            return range(NGRAN)
        a = max(lo + STACK_SIZE, 0)
        b = min(hi + size - 1 + STACK_SIZE, STACK_SIZE - 1)
        if a > b:
            return []
        return range(a // 8, b // 8 + 1)

    def load_result(self, ptr, disp, size, stk):
        t = ptr[0]
        if t == "CTX":
            lo, hi = iadd(ptr[1], disp), iadd(ptr[2], disp)
            if lo == hi:
                if size == 8 and lo == 0:
                    return ("PKT", 0, 0)
                if size == 8 and lo == 8:
                    return ("END",)
                if size == 4 and lo == 16:
                    return ("SC", 0, U32_MAX)
            return sc_width(size) if size < 8 else SC_TOP
        if t == "STK":
            lo, hi = iadd(ptr[1], disp), iadd(ptr[2], disp)
            if lo == hi and size == 8 and lo % 8 == 0 and \
                    -STACK_SIZE <= lo <= -8:
                return stk[(lo + STACK_SIZE) // 8]
            return sc_width(size) if size < 8 else SC_TOP
        if t in ("PKT", "MV"):
            return sc_width(size) if size < 8 else SC_TOP
        return UNK

    def store_effect(self, ptr, disp, size, val, stk):
        """Returns updated stack tuple."""
        if ptr[0] != "STK":
            return stk
        lo, hi = iadd(ptr[1], disp), iadd(ptr[2], disp)
        stk = list(stk)
        if lo == hi and size == 8 and lo % 8 == 0 and -STACK_SIZE <= lo <= -8:
            stk[(lo + STACK_SIZE) // 8] = val
        else:
            for g in self.granules_of(lo, hi, size):
                stk[g] = SC_TOP
        return tuple(stk)

    def mem_fact(self, ptr, disp, size, is_store):
        """(tx_bit, direct_bit) for one memory access."""
        t = ptr[0]
        if t == "STK":
            lo, hi = iadd(ptr[1], disp), iadd(ptr[2], disp)
            ok = lo != NINF and hi != INF and lo >= -STACK_SIZE and \
                hi + size <= 0
            return (ok, ok)
        if t == "CTX":
            if is_store:
                return (False, False)  # ctx is RO in every mode
            lo, hi = iadd(ptr[1], disp), iadd(ptr[2], disp)
            ok = lo == hi and (lo, size) in ((0, 8), (8, 8), (16, 4))
            return (ok, ok)
        if t == "PKT":
            lo, hi = iadd(ptr[1], disp), iadd(ptr[2], disp)
            ok = lo != NINF and hi != INF and lo >= 0 and \
                hi + size <= self.min_pkt
            if is_store:
                return (False, ok)  # pkt is RO in tx modes: guard must stay
            return (ok, ok)
        if t == "MV":
            vs = self.maps[ptr[1]]["value_size"]
            lo, hi = iadd(ptr[2], disp), iadd(ptr[3], disp)
            ok = lo != NINF and hi != INF and lo >= 0 and hi + size <= vs
            return (ok, ok)
        return (False, False)

    # -- branch refinement ------------------------------------------------
    def refine(self, ins, regs, taken):
        """Refine register state along one edge of a jcc. Returns regs tuple
        or None if the edge is proven unreachable."""
        jop, is32, xsrc = ins["jop"], ins["is32"], ins["xsrc"]
        d = ins["dst"]
        dv = regs[d]
        if xsrc:
            return regs  # reg-reg compares: no refinement (sound)
        k = ins["imm"]
        # NULL_OR_MAPVAL split on jeq/jne 0 (64-bit)
        if dv[0] == "NM" and not is32 and k == 0:
            if jop == 1:   # jeq
                nv = ("SC", 0, 0) if taken else ("MV", dv[1], 0, 0)
            elif jop == 5:  # jne
                nv = ("MV", dv[1], 0, 0) if taken else ("SC", 0, 0)
            else:
                return regs
            return regs[:d] + (nv,) + regs[d + 1:]
        if dv[0] != "SC":
            return regs
        lo, hi = dv[1], dv[2]
        if is32:
            # low-32 compare: refine only when value proven within [0, 2^31)
            if not (lo >= 0 and hi <= (1 << 31) - 1):
                return regs
        # effective condition on (taken)
        if jop == 1:      cond = ("eq",) if taken else ("ne",)
        elif jop == 5:    cond = ("ne",) if taken else ("eq",)
        elif jop == 2:    cond = ("gt", "u") if taken else ("le", "u")
        elif jop == 3:    cond = ("ge", "u") if taken else ("lt", "u")
        elif jop == 0xA:  cond = ("lt", "u") if taken else ("ge", "u")
        elif jop == 0xB:  cond = ("le", "u") if taken else ("gt", "u")
        elif jop == 6:    cond = ("gt", "s") if taken else ("le", "s")
        elif jop == 7:    cond = ("ge", "s") if taken else ("lt", "s")
        elif jop == 0xC:  cond = ("lt", "s") if taken else ("ge", "s")
        elif jop == 0xD:  cond = ("le", "s") if taken else ("gt", "s")
        else:
            return regs  # jset
        op = cond[0]
        if op in ("eq", "ne"):
            if op == "eq":
                nlo, nhi = max(lo, k), min(hi, k)
            else:
                nlo, nhi = lo, hi
                if lo == hi == k:
                    return None
                if k == lo:
                    nlo = lo + 1
                elif k == hi:
                    nhi = hi - 1
        else:
            # unsigned refinement is sound only on a proven-nonnegative range
            if cond[1] == "u" and not (lo >= 0 and k >= 0):
                return regs
            if op == "gt":
                nlo, nhi = max(lo, k + 1), hi
            elif op == "ge":
                nlo, nhi = max(lo, k), hi
            elif op == "lt":
                nlo, nhi = lo, min(hi, k - 1)
            else:  # le
                nlo, nhi = lo, min(hi, k)
        if nlo > nhi:
            return None
        return regs[:d] + (("SC", nlo, nhi),) + regs[d + 1:]

    # -- per-block transfer ----------------------------------------------
    def transfer_block(self, b, state, facts=None):
        """Run the block; return list of (succ_block_id, state|None).
        facts: optional dict collector for the final pass."""
        regs, stk = state
        regs = tuple(regs)
        for li in b["insns"]:
            ins = self.insns[li]
            k = ins["kind"]
            if k == "alu":
                d, s = ins["dst"], ins["src"]
                if ins["aluop"] == 0x8:  # NEG (unary)
                    if regs[d][0] == "SC":
                        res = self._sc_alu(0x8, regs[d], regs[d])
                    else:
                        res = SC_TOP
                    if ins["is32"] and not (res[0] == "SC" and res[1] >= 0
                                            and res[2] <= U32_MAX):
                        res = ("SC", 0, U32_MAX)
                else:
                    srcv = regs[s] if ins["xsrc"] else \
                        ("SC", ins["imm"], ins["imm"])
                    res = self.alu(ins["aluop"], regs[d], srcv, ins["is32"])
                regs = regs[:d] + (res,) + regs[d + 1:]
            elif k == "lddw":
                d = ins["dst"]
                if ins["is_map"]:
                    res = ("MH", ins["imm"])
                else:
                    v = ins["imm64"]
                    if v > S64_MAX:
                        v -= 1 << 64
                    res = ("SC", v, v)
                regs = regs[:d] + (res,) + regs[d + 1:]
            elif k == "ldx":
                d, s = ins["dst"], ins["src"]
                ptr = regs[s]
                if facts is not None:
                    tx, dr = self.mem_fact(ptr, ins["off"], ins["size"], False)
                    facts["mem"].setdefault(ins["slot"], [True, True])
                    facts["mem"][ins["slot"]][0] &= tx
                    facts["mem"][ins["slot"]][1] &= dr
                res = self.load_result(ptr, ins["off"], ins["size"], stk)
                regs = regs[:d] + (res,) + regs[d + 1:]
            elif k in ("stx", "st"):
                d = ins["dst"]
                ptr = regs[d]
                val = regs[ins["src"]] if k == "stx" else \
                    ("SC", ins["imm"], ins["imm"])
                if facts is not None:
                    tx, dr = self.mem_fact(ptr, ins["off"], ins["size"], True)
                    facts["mem"].setdefault(ins["slot"], [True, True])
                    facts["mem"][ins["slot"]][0] &= tx
                    facts["mem"][ins["slot"]][1] &= dr
                    # RO proof: which maps might this store target?
                    if ptr[0] in ("MV", "NM"):
                        facts["stored_maps"].add(ptr[1])
                    elif ptr[0] not in ("STK", "CTX", "PKT"):
                        # UNK / scalar / handle-typed pointers could target
                        # any map value -> conservatively poison all
                        facts["stored_maps"].update(range(len(self.maps)))
                stk = self.store_effect(ptr, ins["off"], ins["size"], val, stk)
            elif k == "call":
                hid = ins["imm"]
                if facts is not None and hid in (H_UPDATE, H_DELETE):
                    if regs[1][0] == "MH":
                        facts["written_maps"].add(regs[1][1])
                    else:
                        facts["written_maps"].update(range(len(self.maps)))
                if hid == H_LOOKUP and regs[1][0] == "MH":
                    r0 = ("NM", regs[1][1])
                elif hid == H_KTIME:
                    r0 = ("SC", 0, INF)
                elif hid == H_PRANDOM:
                    r0 = ("SC", 0, U32_MAX)
                elif hid in (H_UPDATE, H_DELETE, H_PSB, H_RINGBUF):
                    r0 = ("SC", -2, 0)
                else:
                    r0 = UNK
                regs = (r0,) + tuple(UNK for _ in range(5)) + regs[6:]
            elif k == "exit":
                return []
            elif k == "ja":
                pass
            elif k == "jcc":
                out = []
                fr = self.refine(ins, regs, taken=False)
                tr = self.refine(ins, regs, taken=True)
                fb = b["succ"][0]
                tb = b["succ"][1]
                out.append((fb, None if fr is None else (fr, stk)))
                out.append((tb, None if tr is None else (tr, stk)))
                return out
            else:
                raise Bail(f"unhandled kind {k}")
        return [(s, (regs, stk)) for s in b["succ"]]


# ---------------------------------------------------------------------------
# Fixpoint, facts, loops
# ---------------------------------------------------------------------------

def entry_state():
    regs = [UNK] * 11
    regs[1] = ("CTX", 0, 0)
    regs[10] = ("STK", 0, 0)
    return (tuple(regs), tuple([UNK] * NGRAN))


def structural_reachable(blocks):
    seen = {0}
    work = [0]
    while work:
        b = work.pop()
        for s in blocks[b]["succ"]:
            if s not in seen:
                seen.add(s)
                work.append(s)
    return seen


def fixpoint(an, widen_targets):
    """Worklist dataflow. Widening to +-inf on the 3rd changed visit of a
    loop-head block (per DESIGN 5); a high fallback threshold on all other
    blocks guarantees termination even on irreducible CFGs."""
    st0 = entry_state()
    entry = {0: st0}
    changes = {0: 1}
    work = [0]
    steps = 0
    while work:
        bid = work.pop()
        steps += 1
        if steps > MAX_DATAFLOW_STEPS:
            raise Bail("dataflow did not converge (state budget exceeded)")
        outs = an.transfer_block(an.blocks[bid], entry[bid])
        for succ, ost in outs:
            if ost is None:
                continue
            cur = entry.get(succ)
            new = ost if cur is None else join_state(cur, ost)
            if cur is not None and new == cur:
                continue
            changes[succ] = changes.get(succ, 0) + 1
            thresh = 3 if succ in widen_targets else 24
            if cur is not None and changes[succ] >= thresh:
                new = widen_state(cur, new)
                if new == cur:
                    continue
            entry[succ] = new
            if succ not in work:
                work.append(succ)
    return entry


def dominators(blocks, preds, reachable):
    n = len(blocks)
    allr = set(reachable)
    dom = {b: set(allr) for b in allr}
    dom[0] = {0}
    changed = True
    while changed:
        changed = False
        for b in sorted(allr):
            if b == 0:
                continue
            ps = [p for p in preds[b] if p in allr]
            if not ps:
                continue
            nd = set.intersection(*(dom[p] for p in ps)) | {b}
            if nd != dom[b]:
                dom[b] = nd
                changed = True
    return dom


def natural_loops(blocks, preds, dom, reachable):
    loops = {}  # header -> set(body)
    back_edges = []
    for b in reachable:
        for s in blocks[b]["succ"]:
            if s in reachable and s in dom.get(b, ()):
                back_edges.append((b, s))
    for (u, v) in back_edges:
        body = {v, u}
        stack = [u]
        while stack:
            n = stack.pop()
            if n == v:
                continue
            for p in preds[n]:
                if p in reachable and p not in body:
                    body.add(p)
                    stack.append(p)
        loops.setdefault(v, set()).update(body)
    return loops, back_edges


def acyclic_without_back_edges(blocks, reachable, back_edges):
    be = set(back_edges)
    indeg = {b: 0 for b in reachable}
    for b in reachable:
        for s in blocks[b]["succ"]:
            if s in reachable and (b, s) not in be:
                indeg[s] += 1
    work = [b for b in reachable if indeg[b] == 0]
    seen = 0
    while work:
        b = work.pop()
        seen += 1
        for s in blocks[b]["succ"]:
            if s in reachable and (b, s) not in be:
                indeg[s] -= 1
                if indeg[s] == 0:
                    work.append(s)
    return seen == len(reachable)


def ceil_div(a, b):
    return -(-a // b)


def counted_loop_bound(an, header, body, edge_out, dom, insns, blocks,
                       block_of, back_edges):
    """Return max trip count (executions of any block in the loop per entry)
    or None if the loop is not provably counted."""
    back_srcs = [u for (u, v) in back_edges if v == header and u in body]
    # candidate exit branches: jcc in a loop block with exactly one successor
    # outside the loop, comparing a register against a constant
    for bid in sorted(body):
        b = blocks[bid]
        last = insns[b["insns"][-1]]
        if last["kind"] != "jcc" or last["xsrc"] or last["is32"]:
            continue
        fall, tgt = b["succ"][0], b["succ"][1]
        t_in, f_in = tgt in body, fall in body
        if t_in == f_in:
            continue  # both stay or both leave
        # the branch must run every iteration
        if not all(bid in dom.get(u, ()) for u in back_srcs):
            continue
        rn = last["dst"]
        k = last["imm"]
        taken_exits = not t_in
        jop = last["jop"]
        # continue-condition (staying in the loop): cond(rn, k) that holds on
        # the in-loop edge
        m = {1: "eq", 5: "ne", 2: ("gt", "u"), 3: ("ge", "u"),
             0xA: ("lt", "u"), 0xB: ("le", "u"), 6: ("gt", "s"),
             7: ("ge", "s"), 0xC: ("lt", "s"), 0xD: ("le", "s")}
        if jop not in m or m[jop] in ("eq", "ne"):
            continue
        op, sign = m[jop]
        if taken_exits:  # continue on fall-through = !op
            op = {"gt": "le", "ge": "lt", "lt": "ge", "le": "gt"}[op]
        # find writes to rn inside the loop
        step = None
        step_block = None
        bad = False
        for lb in body:
            for li in blocks[lb]["insns"]:
                ins = insns[li]
                writes = False
                if ins["kind"] in ("alu", "lddw", "ldx"):
                    writes = ins["dst"] == rn
                elif ins["kind"] == "call":
                    writes = rn <= 5
                if not writes:
                    continue
                if ins["kind"] == "alu" and not ins["is32"] and \
                        not ins["xsrc"] and ins["aluop"] in (0x0, 0x1) and \
                        ins["dst"] == rn and step is None:
                    c = ins["imm"] if ins["aluop"] == 0x0 else -ins["imm"]
                    step = c
                    step_block = lb
                else:
                    bad = True
        if bad or step is None or step == 0:
            continue
        if not all(step_block in dom.get(u, ()) for u in back_srcs):
            continue
        # init interval of rn on entry to the loop (preheader edges only)
        init_lo, init_hi = None, None
        found = False
        for (p, s), stt in edge_out.items():
            if s != header or p in body or stt is None:
                continue
            av = stt[0][rn]
            if av[0] != "SC":
                return None
            found = True
            lo, hi = av[1], av[2]
            init_lo = lo if init_lo is None else min(init_lo, lo)
            init_hi = hi if init_hi is None else max(init_hi, hi)
        if not found:
            continue
        # direction / bound
        if op in ("lt", "le") and step > 0:
            lim = k + (1 if op == "le" else 0)
            if init_lo in (NINF, INF):
                continue
            if sign == "u" and not (init_lo >= 0 and k >= 0):
                continue
            if lim <= init_lo:
                return 1
            return ceil_div(lim - init_lo, step) + 1
        if op in ("gt", "ge") and step < 0:
            c = -step
            lim = k - (1 if op == "ge" else 0)
            if init_hi in (NINF, INF):
                continue
            if sign == "u":
                if not (init_lo is not None and init_lo >= 0 and k >= 0
                        and k >= c - 1):
                    continue
            if init_hi <= lim:
                return 1
            return ceil_div(init_hi - lim, c) + 1
    return None


def analyze(path):
    t0 = time.perf_counter_ns()
    kb = parse_kbin(path)
    n_insns = kb["n_insns"]
    n_maps = len(kb["maps"])
    result = {
        "prog": os.path.splitext(os.path.basename(path))[0],
        "n_insns": n_insns,
        "n_mem_insns": 0,
        "elided_tx_pct": 0.0,
        "elided_direct_pct": 0.0,
        "fuel_elided": False,
        "ro_maps": [],
        "analysis_ms": 0.0,
    }
    iflags = bytes(n_insns)
    map_ro = bytes(n_maps)
    flags = 0
    try:
        insns = decode(kb)
        blocks, preds, block_of = build_cfg(insns)
        an = Analyzer(kb, insns, blocks, preds)
        result["n_mem_insns"] = an.n_mem
        # loop heads are structural: compute them before the value analysis
        sreach = structural_reachable(blocks)
        sdom = dominators(blocks, preds, sreach)
        _, sback = natural_loops(blocks, preds, sdom, sreach)
        widen_targets = {v for (_, v) in sback}
        entry = fixpoint(an, widen_targets)
        reachable = set(entry.keys())

        # facts pass: replay each reachable block from its fixpoint entry
        facts = {"mem": {}, "written_maps": set(), "stored_maps": set()}
        edge_out = {}
        for bid in sorted(reachable):
            outs = an.transfer_block(an.blocks[bid], entry[bid], facts=facts)
            for succ, ost in outs:
                key = (bid, succ)
                if key in edge_out and edge_out[key] is not None:
                    if ost is not None:
                        edge_out[key] = join_state(edge_out[key], ost)
                else:
                    edge_out[key] = ost

        ifl = [0] * n_insns
        for slot, (tx, dr) in facts["mem"].items():
            ifl[slot] = (1 if tx else 0) | (2 if dr else 0)
        iflags = bytes(ifl)

        # read-only maps
        ro = []
        for m in range(n_maps):
            is_ro = m not in facts["written_maps"] and \
                m not in facts["stored_maps"]
            ro.append(1 if is_ro else 0)
        map_ro = bytes(ro)
        result["ro_maps"] = [kb["maps"][m]["name"] for m in range(n_maps)
                             if ro[m]]

        # fuel: loops + bound
        dom = dominators(blocks, preds, reachable)
        loops, back_edges = natural_loops(blocks, preds, dom, reachable)
        fuel_ok = acyclic_without_back_edges(blocks, reachable, back_edges)
        mult = {b: 1 for b in reachable}
        if fuel_ok:
            for header, body in loops.items():
                bound = counted_loop_bound(an, header, body, edge_out, dom,
                                           insns, blocks, block_of,
                                           back_edges)
                if bound is None:
                    fuel_ok = False
                    break
                for b in body:
                    if b in mult:
                        mult[b] *= bound
        if fuel_ok:
            total = 0
            for bid in reachable:
                nslots = sum(insns[li]["slots"]
                             for li in blocks[bid]["insns"])
                total += nslots * mult[bid]
            fuel_ok = total <= FUEL_BUDGET
            result["fuel_bound"] = total
        result["fuel_elided"] = bool(fuel_ok)

        mem = result["n_mem_insns"]
        ntx = sum(1 for f in iflags if f & 1)
        ndr = sum(1 for f in iflags if f & 2)
        result["elided_tx_pct"] = round(100.0 * ntx / mem, 2) if mem else 100.0
        result["elided_direct_pct"] = round(100.0 * ndr / mem, 2) if mem \
            else 100.0
        flags = (1 if fuel_ok else 0) | 2  # bit1 = analysis completed
        result["analysis_complete"] = True
    except Bail as e:
        # sound bail: nothing elided, analysis-complete bit cleared
        iflags = bytes(n_insns)
        map_ro = bytes(n_maps)
        flags = 0
        result["analysis_complete"] = False
        result["bail_reason"] = str(e)
        result["fuel_elided"] = False
        result["elided_tx_pct"] = 0.0
        result["elided_direct_pct"] = 0.0
        result["ro_maps"] = []

    result["analysis_ms"] = round((time.perf_counter_ns() - t0) / 1e6, 3)
    sidecar = b"KELD" + struct.pack("<IIII", 1, n_insns, flags, n_maps) + \
        iflags + map_ro
    return sidecar, result


def main():
    ap = argparse.ArgumentParser(description="KTx guard-elision analyzer")
    ap.add_argument("input", help="input .kbin")
    ap.add_argument("-o", "--output", help=".elide output (default stem.elide)")
    ap.add_argument("--json", dest="json_out", help="stats JSON output path")
    args = ap.parse_args()
    out = args.output or os.path.splitext(args.input)[0] + ".elide"
    sidecar, stats = analyze(args.input)
    with open(out, "wb") as f:
        f.write(sidecar)
    if args.json_out:
        with open(args.json_out, "w") as f:
            json.dump(stats, f, indent=2)
            f.write("\n")
    print(f"elide.py: {args.input} -> {out}: "
          f"tx {stats['elided_tx_pct']}% direct {stats['elided_direct_pct']}% "
          f"fuel_elided={stats['fuel_elided']} ro_maps={stats['ro_maps']} "
          f"complete={stats.get('analysis_complete')}")


if __name__ == "__main__":
    main()
