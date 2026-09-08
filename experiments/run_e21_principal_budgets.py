#!/usr/bin/env python3
"""E21: denial-oriented attacker with per-principal retry budgets."""
from __future__ import annotations

import json
import statistics
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    subprocess.run(["make", "all"], cwd=ROOT, check=True,
                   stdout=subprocess.DEVNULL)
    configs = [
        ("no_retry", 0, 0),
        ("global_two", 2, 2),
        ("principal_partitioned", 0, 2),
    ]
    rows = []
    with tempfile.TemporaryDirectory(prefix="ktx-e21-") as td:
        for seed in (17, 29, 43, 61, 73):
            for label, ar, lr in configs:
                out = Path(td) / f"{seed}-{label}.json"
                cmd = [str(ROOT / "bin/ktxpolicy"), "--prog",
                       str(ROOT / "workloads/firewall.kbin"), "--elide",
                       str(ROOT / "workloads/firewall.elide"), "--mode", "tx",
                       "--vector", "conflict", "--jit", "--attackers", "8",
                       "--legit", "4", "--ops", "10000", "--attack-keys", "1",
                       "--legit-keys", "1024", "--attacker-retries", str(ar),
                       "--legit-retries", str(lr), "--default", "drop",
                       "--seed", str(seed), "--out", str(out)]
                subprocess.run(cmd, cwd=ROOT, check=True,
                               stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)
                m = json.loads(out.read_text())["runs"][0]["metrics"]
                rows.append({"seed": seed, "policy": label,
                             "attacker_retries": ar, "legit_retries": lr, **m})
    summary = []
    for label, ar, lr in configs:
        rs = [r for r in rows if r["policy"] == label]
        summary.append({
            "policy": label, "runs": len(rs), "attacker_retries": ar,
            "legit_retries": lr,
            "bypass_rate_median": statistics.median(r["bypass_rate"] for r in rs),
            "false_drop_rate_median": statistics.median(r["false_drop_rate"] for r in rs),
            "attempts_per_invocation_median": statistics.median(
                r["attempts_per_invocation"] for r in rs),
            "legit_thread_kops_min": min(r["legit_thread_kops_min"] for r in rs),
            "legit_jain_fairness_min": min(r["legit_jain_fairness"] for r in rs),
        })
    result = {
        "experiment": "E21_per_principal_retry_budgets",
        "adversary": "eight blocklisted principals contend deliberately on one key; four legitimate threads use 1024 disjoint keys",
        "attachment_policy": "fail closed",
        "scope": "bounded immediate retries in the userspace runtime; scheduling/backoff remains an integration obligation",
        "rows": rows, "summary": summary,
        "doomed_effect_test": "test_ktx repeats 1000 guard-doomed invocations after map/ring/packet intents and requires zero publication",
    }
    out = ROOT / "experiments/results/e21_principal_budgets.json"
    out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result["summary"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
