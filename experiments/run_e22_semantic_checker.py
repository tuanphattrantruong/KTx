#!/usr/bin/env python3
"""E22: semantic certificate replay and mutation campaign."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CHECKER_PATH = ROOT / "tools/semantic_check.py"
SPEC = importlib.util.spec_from_file_location("semantic_check", CHECKER_PATH)
SC = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(SC)


def rejected(kbin: Path, blob: bytes) -> tuple[bool, str]:
    try:
        SC.check_bytes(kbin, blob)
        return False, "accepted"
    except SC.CertificateError as exc:
        return True, str(exc)


def main() -> int:
    programs = sorted(p for p in (ROOT / "workloads").glob("*.kbin")
                      if p.with_suffix(".elide").exists())
    valid = []
    attacks = []
    for kbin in programs:
        blob, _ = SC.make_v2(kbin)
        check = SC.check_bytes(kbin, blob)
        valid.append(check)

        cases: list[tuple[str, bytes]] = []
        bad = bytearray(blob); bad[SC.HDR.size] ^= 0x80
        cases.append(("program_digest", bytes(bad)))
        bad = bytearray(blob); bad[4:8] = struct.pack("<I", 99)
        cases.append(("version", bytes(bad)))
        cases.append(("truncation", blob[:-1]))
        c = SC._parse(blob)
        io = SC.HDR.size + SC.DIGEST_BYTES
        canonical, _ = SC.ELIDE.analyze(str(kbin))
        cp = SC._parse(canonical)
        false_bit = next(((i, bit) for i, f in enumerate(cp["iflags"])
                          for bit in (1, 2) if not (f & bit)), None)
        if false_bit:
            i, bit = false_bit; bad = bytearray(blob); bad[io + i] |= bit
            cases.append(("unentailed_bounds", bytes(bad)))
        false_map = next((i for i, f in enumerate(cp["map_ro"]) if not f), None)
        if false_map is not None:
            bad = bytearray(blob); bad[io + c["n_insns"] + false_map] = 1
            cases.append(("unentailed_read_only_map", bytes(bad)))
        if not (cp["flags"] & 1):
            bad = bytearray(blob)
            flags = struct.unpack_from("<I", bad, 12)[0] | 1 | 2
            struct.pack_into("<I", bad, 12, flags)
            cases.append(("unentailed_fuel", bytes(bad)))
        for attack, candidate in cases:
            denied, reason = rejected(kbin, candidate)
            attacks.append({"program": kbin.name, "attack": attack,
                            "rejected": denied, "reason": reason})

    out = {
        "experiment": "E22_semantic_certificate_checker",
        "programs": len(programs),
        "valid_accepted": sum(1 for x in valid if x["accepted"]),
        "valid": valid,
        "mutations": len(attacks),
        "mutations_rejected": sum(1 for x in attacks if x["rejected"]),
        "attacks": attacks,
        "checker_sha256": hashlib.sha256(CHECKER_PATH.read_bytes()).hexdigest(),
        "protocol": ("generate digest-bound v2 certificates, replay typed "
                     "transfer semantics, and mutate digest/framing/fuel/"
                     "bounds/map facts wherever applicable"),
    }
    result_path = ROOT / "experiments/results/e22_semantic_checker.json"
    result_path.write_text(json.dumps(out, indent=2) + "\n")
    print(json.dumps({k: out[k] for k in ("programs", "valid_accepted",
                                         "mutations", "mutations_rejected")},
                     indent=2))
    return 0 if out["valid_accepted"] == len(programs) and \
        out["mutations_rejected"] == len(attacks) else 1


if __name__ == "__main__":
    raise SystemExit(main())
