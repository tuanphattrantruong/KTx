#!/usr/bin/env python3
"""E18: same-host KTx versus deadlock-free predeclared-map 2PL and coarse TX."""
from __future__ import annotations

import argparse
import json
import statistics
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--reps", type=int, default=3)
    ap.add_argument("--iters", type=int, default=100_000)
    ap.add_argument("--warmup", type=int, default=10_000)
    ap.add_argument("--out", default=str(ROOT / "experiments/results/e18_p2pl.json"))
    args = ap.parse_args()
    subprocess.run(["make", "bench"], cwd=ROOT, check=True,
                   stdout=subprocess.DEVNULL)
    cells: dict[tuple[str, str, int], list[float]] = {}
    meta = None
    with tempfile.TemporaryDirectory(prefix="ktx-e18-") as td:
        for prog in ("ctnat", "l4lb"):
            for mode in ("tx", "p2pl", "coarse"):
                for threads in (1, 2, 4, 8, 16):
                    vals = []
                    for rep in range(args.reps):
                        out = Path(td) / f"{prog}-{mode}-{threads}-{rep}.json"
                        cmd = [
                            str(ROOT / "bin/ktxbench"), "--prog",
                            str(ROOT / f"workloads/{prog}.kbin"), "--mode", mode,
                            "--jit", "--measure", "throughput", "--threads", str(threads),
                            "--iters", str(args.iters), "--warmup", str(args.warmup),
                            "--seed", str(201 + rep), "--nkeys", "1024", "--zipf", "0.0",
                            "--pktlen-min", "64", "--pktlen-max", "256", "--fuel", "65536",
                            "--exp", "e18_p2pl", "--out", str(out),
                        ]
                        subprocess.run(cmd, cwd=ROOT, check=True,
                                       stdout=subprocess.DEVNULL)
                        row = json.loads(out.read_text())
                        meta = row["meta"]
                        vals.append(row["runs"][0]["metrics"]["mops_per_s"])
                    cells[(prog, mode, threads)] = vals
    rows = []
    for (prog, mode, threads), vals in sorted(cells.items()):
        rows.append({
            "program": prog, "mode": mode, "threads": threads,
            "repeats": len(vals), "mops_per_s_median": statistics.median(vals),
            "mops_per_s_min": min(vals), "mops_per_s_max": max(vals),
        })
    ratios = []
    for prog in ("ctnat", "l4lb"):
        for threads in (1, 2, 4, 8, 16):
            tx = statistics.median(cells[(prog, "tx", threads)])
            p2pl = statistics.median(cells[(prog, "p2pl", threads)])
            coarse = statistics.median(cells[(prog, "coarse", threads)])
            ratios.append({"program": prog, "threads": threads,
                           "tx_over_p2pl": tx / p2pl,
                           "tx_over_coarse": tx / coarse})
    result = {
        "experiment": "E18_deadlock_free_predeclared_2pl",
        "design": "all declared shared program maps acquired in ascending environment-map-id order; direct effects; guards and fuel retained",
        "scope": "single Apple M3 Ultra host; no Linux/x86 transfer claim",
        "meta": meta, "cells": rows, "ratios": ratios,
    }
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
