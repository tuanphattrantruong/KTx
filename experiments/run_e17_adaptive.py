#!/usr/bin/env python3
"""E17: adaptive conflict pressure, bounded retries, CPU amplification/fairness."""
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
    ap.add_argument("--ops", type=int, default=5000)
    ap.add_argument("--out", default=str(ROOT / "experiments/results/e17_adaptive.json"))
    args = ap.parse_args()
    rows = []
    with tempfile.TemporaryDirectory(prefix="ktx-e17-") as td:
        for seed in (17, 29, 43):
            for attackers in (1, 2, 4, 8):
                for retries in (0, 2, 4):
                    for default in ("pass", "drop"):
                        raw = Path(td) / f"{seed}-{attackers}-{retries}-{default}.json"
                        cmd = [str(ROOT / "bin/ktxpolicy"),
                               "--prog", str(ROOT / "workloads/firewall.kbin"),
                               "--elide", str(ROOT / "workloads/firewall.elide"),
                               "--mode", "tx", "--vector", "conflict", "--jit",
                               "--attackers", str(attackers), "--legit", "4",
                               "--ops", str(args.ops), "--attack-keys", "1",
                               "--legit-keys", "1024", "--retries", str(retries),
                               "--default", default, "--seed", str(seed),
                               "--out", str(raw)]
                        subprocess.run(cmd, cwd=ROOT, check=True,
                                       stdout=subprocess.DEVNULL,
                                       stderr=subprocess.DEVNULL)
                        run = json.loads(raw.read_text())["runs"][0]
                        rows.append({"seed": seed, "attackers": attackers,
                                     "config_retries": retries, "default": default,
                                     **run["metrics"]})
    grouped = []
    for attackers in (1, 2, 4, 8):
        for retries in (0, 2, 4):
            for default in ("pass", "drop"):
                rs = [r for r in rows if r["attackers"] == attackers and
                      r["config_retries"] == retries and r["default"] == default]
                grouped.append({
                    "attackers": attackers, "legit": 4, "retries": retries,
                    "default": default, "seeds": len(rs),
                    "bypass_rate_median": statistics.median(r["bypass_rate"] for r in rs),
                    "false_drop_rate_median": statistics.median(r["false_drop_rate"] for r in rs),
                    "attempts_per_invocation_median": statistics.median(
                        r["attempts_per_invocation"] for r in rs),
                    "aggregate_kops_s_median": statistics.median(
                        r["aggregate_kops_s"] for r in rs),
                    "legit_jain_fairness_min": min(r["legit_jain_fairness"] for r in rs),
                    "legit_thread_kops_min": min(r["legit_thread_kops_min"] for r in rs),
                })
    result = {
        "experiment": "E17_adaptive_conflict_policy",
        "scope": ("JIT userspace prototype; one hot attacker key, four legitimate "
                  "threads, bounded immediate retries; no scheduler backoff"),
        "ops_per_thread": args.ops, "seeds": [17, 29, 43],
        "rows": rows, "summary": grouped,
    }
    out = Path(args.out); out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"experiment": result["experiment"],
                      "runs": len(rows), "summary": grouped}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
