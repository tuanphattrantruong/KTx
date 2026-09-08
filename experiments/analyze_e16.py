#!/usr/bin/env python3
import json
import statistics
import sys

rows = [json.load(open(path)) for path in sys.argv[1:]]
out = {"experiment": "E16_mixed_observer", "repetitions": {}}
for mode in ("ordinary", "published"):
    cells = [r for r in rows if r["mode"] == mode]
    out["repetitions"][mode] = {
        "runs": len(cells),
        "reader_samples": sum(r["reader_samples"] for r in cells),
        "torn_observations": sum(r["torn_observations"] for r in cells),
        "commits_per_s_median": statistics.median(
            r["commits_per_s"] for r in cells),
        "commits_per_s_min": min(r["commits_per_s"] for r in cells),
        "commits_per_s_max": max(r["commits_per_s"] for r in cells),
    }
base = out["repetitions"]["ordinary"]["commits_per_s_median"]
safe = out["repetitions"]["published"]["commits_per_s_median"]
out["published_throughput_fraction"] = safe / base
out["published_overhead_fraction"] = 1.0 - safe / base
out["pass"] = (out["repetitions"]["ordinary"]["torn_observations"] > 0 and
               out["repetitions"]["published"]["torn_observations"] == 0)
print(json.dumps(out, indent=2))
