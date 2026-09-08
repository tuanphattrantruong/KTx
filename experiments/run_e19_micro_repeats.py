#!/usr/bin/env python3
"""E19: independent-process replication of the subtractive microbenchmark."""
from __future__ import annotations

import argparse
import json
import statistics
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def quantile(xs: list[float], p: float) -> float:
    ys = sorted(xs)
    x = (len(ys) - 1) * p
    lo = int(x)
    hi = min(lo + 1, len(ys) - 1)
    return ys[lo] * (hi - x) + ys[hi] * (x - lo)


def stats(xs: list[float]) -> dict:
    return {"median_ns": statistics.median(xs), "min_ns": min(xs),
            "max_ns": max(xs), "q1_ns": quantile(xs, .25),
            "q3_ns": quantile(xs, .75), "values_ns": xs}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=10)
    ap.add_argument("--reps", type=int, default=5_120)
    ap.add_argument("--out", default=str(ROOT / "experiments/results/e19_micro_repeats.json"))
    args = ap.parse_args()
    subprocess.run(["make", "core"], cwd=ROOT, check=True,
                   stdout=subprocess.DEVNULL)
    by: dict[tuple[str, int], list[float]] = {}
    derived: dict[tuple[str, int], list[float]] = {}
    metas = []
    with tempfile.TemporaryDirectory(prefix="ktx-e19-") as td:
        for run in range(args.runs):
            p = Path(td) / f"run-{run}.json"
            subprocess.run([str(ROOT / "bin/ktxmicro"), "--out", str(p),
                            "--reps", str(args.reps), "--warmup", "512"],
                           cwd=ROOT, check=True)
            d = json.loads(p.read_text())
            metas.append(d["meta"])
            cells = {(x["op"], x["log_k"]): x["metrics"]["ns_p50"]
                     for x in d["runs"]}
            for key, value in cells.items():
                by.setdefault(key, []).append(value)
            for k in (1, 2, 4, 8, 16, 32, 64, 128, 256):
                derived.setdefault(("commit_minus_append", k), []).append(
                    cells[("commit", k)] - cells[("append", k)])
                derived.setdefault(("abort_minus_append", k), []).append(
                    cells[("abort", k)] - cells[("append", k)])
    result = {
        "experiment": "E19_micro_independent_process_repeats",
        "independent_process_runs": args.runs, "timed_reps_per_cell": args.reps,
        "scope": "Apple M3 Ultra/macOS arm64 only; no Linux/x86 claim",
        "warning": "commit-only and abort-only are differences of separately timed distributions; a negative value is measurement noise, not negative work",
        "meta": metas[0],
        "raw_cell_p50_across_processes": [
            {"op": op, "log_k": k, **stats(xs)}
            for (op, k), xs in sorted(by.items())],
        "derived_differences_across_processes": [
            {"metric": op, "log_k": k, **stats(xs),
             "negative_runs": sum(x < 0 for x in xs)}
            for (op, k), xs in sorted(derived.items())],
    }
    out = Path(args.out); out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"out": str(out), "runs": args.runs,
                      "k1_commit_minus_append": result["derived_differences_across_processes"][0]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
