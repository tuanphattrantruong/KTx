#!/usr/bin/env python3
"""Summarize E15 medians and KTx/coarse throughput ratios."""

from __future__ import annotations

import argparse
import json
import re
import statistics
from pathlib import Path

PATTERN = re.compile(r"e15_(ctnat|l4lb)_(tx|coarse)_(\d+)t_r(\d+)\.json$")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--results", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    cells: dict[tuple[str, str, int], list[float]] = {}
    commits: dict[tuple[str, str, int], list[float]] = {}
    for path in sorted(Path(args.results).glob("e15_*.json")):
        match = PATTERN.match(path.name)
        if not match:
            continue
        prog, mode, threads, _ = match.groups()
        row = json.loads(path.read_text())["runs"][0]["metrics"]
        key = (prog, mode, int(threads))
        cells.setdefault(key, []).append(float(row["mops_per_s"]))
        commits.setdefault(key, []).append(float(row["goodput_commits_per_s"]))
    output = {"experiment": "E15_coarse_baseline", "cells": [], "ratios": []}
    for key in sorted(cells):
        prog, mode, threads = key
        values = cells[key]
        output["cells"].append(
            {
                "program": prog,
                "mode": mode,
                "threads": threads,
                "repeats": len(values),
                "mops_per_s_median": statistics.median(values),
                "mops_per_s_min": min(values),
                "mops_per_s_max": max(values),
                "goodput_per_s_median": statistics.median(commits[key]),
            }
        )
    for prog in ("ctnat", "l4lb"):
        for threads in (1, 2, 4, 8, 16, 32):
            tx = statistics.median(cells[(prog, "tx", threads)])
            coarse = statistics.median(cells[(prog, "coarse", threads)])
            tx_goodput = statistics.median(commits[(prog, "tx", threads)])
            coarse_goodput = statistics.median(commits[(prog, "coarse", threads)])
            output["ratios"].append(
                {
                    "program": prog,
                    "threads": threads,
                    "operation_throughput_ratio": tx / coarse if coarse else None,
                    "commit_goodput_ratio": (
                        tx_goodput / coarse_goodput if coarse_goodput else None
                    ),
                }
            )
    Path(args.out).write_text(json.dumps(output, indent=2, sort_keys=True) + "\n")
    print(json.dumps(output, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
