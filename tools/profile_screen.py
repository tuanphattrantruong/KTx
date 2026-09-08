#!/usr/bin/env python3
"""Conservative source screen of E10 multi-map candidates against KTx profile.

This intentionally reports a three-way result: visibly incompatible,
provisionally within the source-level profile, and unavailable/indeterminate.
It never turns absence of a token in unpreprocessed C into a compatibility
proof; whole-TU preprocessing, bytecode inspection, and map relocation checks
remain necessary before admission.
"""
from __future__ import annotations

import json
import re
import subprocess
import tempfile
from pathlib import Path

from corpus_survey import blank_comments, extract_functions

ROOT = Path(__file__).resolve().parents[1]
SURVEY = ROOT / "experiments/results/e10_corpus.json"
OUT = ROOT / "experiments/results/e20_profile_screen.json"

REPOS = {
    "DataDog_datadog-agent": "https://github.com/DataDog/datadog-agent.git",
    "aquasecurity_tracee": "https://github.com/aquasecurity/tracee.git",
    "cilium_cilium": "https://github.com/cilium/cilium.git",
    "cilium_tetragon": "https://github.com/cilium/tetragon.git",
    "cloudflare_ebpf_exporter": "https://github.com/cloudflare/ebpf_exporter.git",
    "facebookincubator_katran": "https://github.com/facebookincubator/katran.git",
    "iovisor_bcc": "https://github.com/iovisor/bcc.git",
    "libbpf_libbpf-bootstrap": "https://github.com/libbpf/libbpf-bootstrap.git",
    "linux": "https://github.com/torvalds/linux.git",
}

ALLOWED_HELPERS = {
    "bpf_map_lookup_elem", "bpf_map_update_elem", "bpf_map_delete_elem",
    "bpf_ktime_get_ns", "bpf_get_prandom_u32", "bpf_ringbuf_output",
    "bpf_skb_store_bytes",
}
FEATURES = {
    "tail_call": re.compile(r"\bbpf_tail_call\s*\("),
    "kfunc_or_ksym": re.compile(r"\b(?:__ksym|__kfunc|bpf_kfunc_call_test)\b"),
    "dynptr": re.compile(r"\bbpf_dynptr\b|\bbpf_ringbuf_reserve_dynptr\b"),
    "timer": re.compile(r"\bbpf_timer_(?:init|set_callback|start|cancel)\b"),
    "callback": re.compile(r"\bbpf_(?:loop|for_each_map_elem)\s*\("),
    "spin_lock": re.compile(r"\bbpf_spin_(?:lock|unlock)\s*\("),
    "reference_lifetime": re.compile(r"\bbpf_(?:kptr_xchg|refcount_acquire|task_acquire|task_release)\s*\("),
}


def reachable_text(src: str, entry: str) -> str | None:
    fns = {name: body for name, _, body in extract_functions(src)}
    if entry not in fns:
        return None
    seen, todo, bodies = set(), [entry], []
    while todo:
        name = todo.pop()
        if name in seen or name not in fns:
            continue
        seen.add(name); body = fns[name]; bodies.append(body)
        for callee in re.findall(r"\b(\w+)\s*\(", body):
            if callee in fns and callee not in seen:
                todo.append(callee)
    return "\n".join(bodies)


def main() -> int:
    d = json.loads(SURVEY.read_text())
    candidates = [p for p in d["programs"] if len(p["writes"]) >= 2]
    rows = []
    commits = {}
    with tempfile.TemporaryDirectory(prefix="ktx-profile-") as td:
        base = Path(td)
        for repo, url in REPOS.items():
            dest = base / repo
            needed = sorted({p["file"] for p in candidates if p["repo"] == repo})
            cp = subprocess.run(["git", "clone", "--depth", "1", "--filter=blob:none",
                                 "--no-checkout", url, str(dest)],
                                capture_output=True, text=True)
            if cp.returncode != 0:
                commits[repo] = {"url": url, "error": cp.stderr.strip()[-500:]}
                continue
            subprocess.run(["git", "-C", str(dest), "sparse-checkout", "init", "--no-cone"],
                           check=True, capture_output=True)
            (dest / ".git/info/sparse-checkout").write_text(
                "\n".join("/" + p for p in needed) + "\n")
            co = subprocess.run(["git", "-C", str(dest), "checkout"],
                                capture_output=True, text=True)
            rev = subprocess.check_output(["git", "-C", str(dest), "rev-parse", "HEAD"],
                                          text=True).strip()
            commits[repo] = {"url": url, "commit": rev,
                             "checkout_ok": co.returncode == 0}
            for p in [x for x in candidates if x["repo"] == repo]:
                path = dest / p["file"]
                if not path.exists():
                    rows.append({**p, "classification": "indeterminate",
                                 "reasons": ["source_path_unavailable_at_screened_revision"]})
                    continue
                src = blank_comments(path.read_text(errors="ignore"))
                text = reachable_text(src, p["prog"])
                if text is None:
                    rows.append({**p, "classification": "indeterminate",
                                 "reasons": ["entry_function_not_recovered"]})
                    continue
                reasons = [name for name, pat in FEATURES.items() if pat.search(text)]
                helpers = sorted(set(re.findall(r"\b(bpf_[A-Za-z0-9_]+)\s*\(", text)))
                unsupported_helpers = [h for h in helpers if h not in ALLOWED_HELPERS]
                if unsupported_helpers:
                    reasons.append("unclassified_helpers:" + ",".join(unsupported_helpers))
                # Linux sleepable programs use the .s suffix in section names.
                if re.search(r"(?:^|/)\w+\.s(?:/|$)", p["sec"]):
                    reasons.append("sleepable_section")
                rows.append({**p,
                             "classification": "visibly_incompatible" if reasons else "provisional_source_pass",
                             "reasons": reasons, "reachable_helpers": helpers})
    # Repositories that could not be cloned contribute indeterminate rows.
    seen = {(r["repo"], r["file"], r["prog"]) for r in rows}
    for p in candidates:
        if (p["repo"], p["file"], p["prog"]) not in seen:
            rows.append({**p, "classification": "indeterminate",
                         "reasons": ["repository_unavailable"]})
    counts = {k: sum(r["classification"] == k for r in rows)
              for k in ("visibly_incompatible", "provisional_source_pass", "indeterminate")}
    result = {
        "experiment": "E20_KTx_profile_source_screen",
        "survey_candidates": len(candidates), "screened_repositories": commits,
        "counts": counts,
        "provisional_pass_fraction_of_281": counts["provisional_source_pass"] / len(candidates),
        "proven_compatible_fraction": 0.0,
        "interpretation": "The source pass is an upper bound after rejecting visible unsupported constructs. No program is called compatible until whole-TU preprocessing, bytecode/helper/map-type inspection, and mutable-access rewriting succeed.",
        "allowed_helper_profile": sorted(ALLOWED_HELPERS), "rows": rows,
    }
    OUT.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"output": str(OUT), "counts": counts,
                      "provisional_pass_fraction": result["provisional_pass_fraction_of_281"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
