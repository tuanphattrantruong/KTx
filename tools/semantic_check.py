#!/usr/bin/env python3
"""Retained semantic checker for KTx v2 elision certificates.

Version 1 sidecars are compact but trust the analyzer.  Version 2 adds a
SHA-256 binding to the exact kbin and is accepted only after this checker
replays the reference typed transfer analysis.  A submitted fact may be more
conservative than the replay, but may never claim a guard, fuel check, or map
write-back is elidable unless the replay proves the same fact.

The checker can materialize a loader-compatible v1 sidecar only after all v2
checks succeed.  This keeps the existing C loader small while making the
admission path proof-carrying and fail closed.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import importlib.util
import json
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ELIDE_PATH = ROOT / "src/elide/elide.py"
_SPEC = importlib.util.spec_from_file_location("ktx_elide", ELIDE_PATH)
ELIDE = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
_SPEC.loader.exec_module(ELIDE)

MAGIC = b"KELD"
V1 = 1
V2 = 2
HDR = struct.Struct("<4sIIII")
DIGEST_BYTES = 32
KNOWN_HEADER_FLAGS = 0x3
KNOWN_INSN_FLAGS = 0x3


class CertificateError(ValueError):
    pass


def _parse(blob: bytes) -> dict:
    if len(blob) < HDR.size:
        raise CertificateError("truncated header")
    magic, version, n_insns, flags, n_maps = HDR.unpack_from(blob)
    if magic != MAGIC:
        raise CertificateError("bad magic")
    if version not in (V1, V2):
        raise CertificateError(f"unsupported version {version}")
    if flags & ~KNOWN_HEADER_FLAGS:
        raise CertificateError("unknown header flag")
    if (flags & 1) and not (flags & 2):
        raise CertificateError("fuel fact without complete analysis")
    off = HDR.size
    digest = None
    if version == V2:
        if len(blob) < off + DIGEST_BYTES:
            raise CertificateError("truncated program digest")
        digest = blob[off:off + DIGEST_BYTES]
        off += DIGEST_BYTES
    expected = off + n_insns + n_maps
    if len(blob) != expected:
        raise CertificateError(f"size {len(blob)} != expected {expected}")
    iflags = blob[off:off + n_insns]
    map_ro = blob[off + n_insns:]
    if any(f & ~KNOWN_INSN_FLAGS for f in iflags):
        raise CertificateError("unknown instruction flag")
    if any(f not in (0, 1) for f in map_ro):
        raise CertificateError("non-Boolean map fact")
    if not (flags & 2) and (any(iflags) or any(map_ro)):
        raise CertificateError("claims in incomplete certificate")
    return {"version": version, "n_insns": n_insns, "flags": flags,
            "n_maps": n_maps, "digest": digest, "iflags": iflags,
            "map_ro": map_ro}


def make_v2(kbin: Path) -> tuple[bytes, dict]:
    canonical, stats = ELIDE.analyze(str(kbin))
    c = _parse(canonical)
    digest = hashlib.sha256(kbin.read_bytes()).digest()
    blob = HDR.pack(MAGIC, V2, c["n_insns"], c["flags"], c["n_maps"])
    blob += digest + c["iflags"] + c["map_ro"]
    return blob, stats


def check_bytes(kbin: Path, blob: bytes) -> dict:
    submitted = _parse(blob)
    if submitted["version"] != V2:
        raise CertificateError("semantic admission requires v2")
    raw = kbin.read_bytes()
    if not hmac.compare_digest(submitted["digest"],
                               hashlib.sha256(raw).digest()):
        raise CertificateError("program digest mismatch")

    canonical_blob, stats = ELIDE.analyze(str(kbin))
    canonical = _parse(canonical_blob)
    if (submitted["n_insns"], submitted["n_maps"]) != \
            (canonical["n_insns"], canonical["n_maps"]):
        raise CertificateError("program dimensions mismatch")
    if (submitted["flags"] & 1) and not (canonical["flags"] & 1):
        raise CertificateError("unentailed fuel-elision fact")
    for i, (claim, proved) in enumerate(zip(submitted["iflags"],
                                            canonical["iflags"])):
        if claim & ~proved:
            raise CertificateError(f"unentailed instruction fact at slot {i}")
    for i, (claim, proved) in enumerate(zip(submitted["map_ro"],
                                            canonical["map_ro"])):
        if claim and not proved:
            raise CertificateError(f"unentailed read-only map fact at map {i}")

    kb = ELIDE.parse_kbin(str(kbin))
    insns = ELIDE.decode(kb)
    helpers: dict[str, int] = {}
    helper_names = {1: "lookup", 2: "update", 3: "delete", 5: "ktime",
                    7: "prandom", 9: "packet_store", 130: "ringbuf"}
    for ins in insns:
        if ins["kind"] == "call":
            name = helper_names[ins["imm"]]
            helpers[name] = helpers.get(name, 0) + 1
    return {
        "accepted": True,
        "program": kbin.name,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "n_insns": submitted["n_insns"],
        "n_maps": submitted["n_maps"],
        "claimed_instruction_facts": sum(int(bool(x & 1)) + int(bool(x & 2))
                                         for x in submitted["iflags"]),
        "claimed_read_only_maps": sum(submitted["map_ro"]),
        "fuel_elided": bool(submitted["flags"] & 1),
        "helper_effect_surface": helpers,
        "analysis": stats,
    }


def materialize_v1(blob: bytes) -> bytes:
    c = _parse(blob)
    if c["version"] != V2:
        raise CertificateError("expected v2 certificate")
    return HDR.pack(MAGIC, V1, c["n_insns"], c["flags"], c["n_maps"]) + \
        c["iflags"] + c["map_ro"]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("kbin", type=Path)
    ap.add_argument("certificate", nargs="?", type=Path)
    ap.add_argument("--emit-v2", type=Path)
    ap.add_argument("--materialize-v1", type=Path)
    ap.add_argument("--json", type=Path)
    args = ap.parse_args()
    if args.emit_v2:
        blob, _ = make_v2(args.kbin)
        args.emit_v2.write_bytes(blob)
    elif args.certificate:
        blob = args.certificate.read_bytes()
    else:
        ap.error("provide CERTIFICATE or --emit-v2")
    try:
        result = check_bytes(args.kbin, blob)
        if args.materialize_v1:
            args.materialize_v1.write_bytes(materialize_v1(blob))
    except CertificateError as exc:
        result = {"accepted": False, "program": args.kbin.name,
                  "reason": str(exc)}
    if args.json:
        args.json.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, sort_keys=True))
    return 0 if result["accepted"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
