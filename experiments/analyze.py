#!/usr/bin/env python3
"""analyze.py - merge experiments/results/*.json, derive paper quantities,
verify E3 invariant expectations, and write summary.json + aligned text
tables (DESIGN.md section 9, honesty rules section 13).

Honesty: every derived value is computed only from numbers read out of a
produced results file, and summary.json cites the source filename next to
every derived number. Missing or failed runs appear as explicit nulls with a
note; expectation failures are printed LOUDLY, never hidden.
"""
import glob
import json
import os
import sys
import time

import numpy as np

RES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results")

W8 = ["pktcount", "flowstats", "tokenbucket", "maglev", "ctnat",
      "pktrewrite", "loopy", "atomic_demo"]
MODES = ["vanilla", "sfi", "tx", "tx-elide"]
ALL10 = W8 + ["ctnat_reader", "atomic_reader"]

notes = []          # explicit record of everything missing/failed
expectation_failures = []


def load_all():
    files = {}
    for p in sorted(glob.glob(os.path.join(RES, "*.json"))):
        base = os.path.basename(p)
        if base == "summary.json":
            continue
        try:
            with open(p) as f:
                files[base] = json.load(f)
        except Exception as e:  # noqa: BLE001 - report, don't crash
            files[base] = {"_load_error": str(e)}
            notes.append(f"{base}: unreadable JSON ({e})")
    return files


def get_run(files, name):
    """First run object of a results file, or (None, reason)."""
    d = files.get(name)
    if d is None:
        return None, f"{name}: file missing"
    if "_load_error" in d:
        return None, f"{name}: unreadable"
    runs = d.get("runs") or []
    if not runs:
        return None, f"{name}: no runs"
    r = runs[0]
    if "error" in r:
        return None, f"{name}: run recorded error: {r['error']}"
    return r, None


def metric(files, name, key):
    r, err = get_run(files, name)
    if err:
        notes.append(err)
        return None
    v = r.get("metrics", {}).get(key)
    if v is None:
        notes.append(f"{name}: metric '{key}' absent")
    return v


# ---------------------------------------------------------------------------
# E3 expectations (C1, C2, C7)
# ---------------------------------------------------------------------------
def check_e3(files):
    out = {}
    for pair in ("ctnat", "atomic"):
        for mode, want_zero in (("vanilla", False), ("tx", True)):
            fn = f"e3a_{pair}_{mode}.json"
            v = metric(files, fn, "violations")
            rc = metric(files, fn, "reader_commits")
            out[f"e3a_{pair}_{mode}"] = {
                "violations": v, "reader_commits": rc, "source": fn,
                "expected": "violations == 0" if want_zero
                            else "violations > 0",
            }
            if v is None:
                continue
            ok = (v == 0) if want_zero else (v > 0)
            if not ok:
                expectation_failures.append(
                    f"{fn}: violations={v}, expected "
                    f"{'== 0' if want_zero else '> 0'}")
        for mode, want_zero in (("sfi", False), ("tx", True)):
            fn = f"e3b_{pair}_{mode}.json"
            t = metric(files, fn, "torn_keys")
            af = metric(files, fn, "abort_fraction")
            out[f"e3b_{pair}_{mode}"] = {
                "torn_keys": t, "abort_fraction": af, "source": fn,
                "expected": "torn_keys == 0" if want_zero
                            else "torn_keys > 0",
            }
            if t is None:
                continue
            ok = (t == 0) if want_zero else (t > 0)
            if not ok:
                expectation_failures.append(
                    f"{fn}: torn_keys={t}, expected "
                    f"{'== 0' if want_zero else '> 0'}")
    return out


# ---------------------------------------------------------------------------
# E4 elision stats (+ loopy/maglev expectations, C4)
# ---------------------------------------------------------------------------
def check_e4(files):
    d = files.get("e4_elision.json")
    out = {}
    if d is None or "_load_error" in d:
        notes.append("e4_elision.json: missing/unreadable")
        return out
    for run in d.get("runs", []):
        p = run.get("prog")
        if not p:
            continue
        out[p] = {k: run.get(k) for k in
                  ("n_insns", "n_mem_insns", "elided_tx_pct",
                   "elided_direct_pct", "fuel_elided", "ro_maps",
                   "analysis_ms", "analysis_complete")}
        out[p]["source"] = "e4_elision.json"
    if "loopy" in out and out["loopy"].get("fuel_elided") is not False:
        expectation_failures.append(
            "e4_elision.json: loopy fuel_elided expected false, got "
            f"{out['loopy'].get('fuel_elided')}")
    if "maglev" in out and "table" not in (out["maglev"].get("ro_maps") or []):
        expectation_failures.append(
            "e4_elision.json: maglev ro_maps expected to contain 'table'")
    return out


# ---------------------------------------------------------------------------
# E1 overhead (C3, C4, C8)
# ---------------------------------------------------------------------------
def e1_tables(files):
    lat, thr = {}, {}
    for p in W8:
        lat[p], thr[p] = {}, {}
        base_lat = metric(files, f"e1_lat_{p}_vanilla.json", "ns_p50")
        base_thr = metric(files, f"e1_thr_{p}_vanilla.json", "mops_per_s")
        for m in MODES:
            fl = f"e1_lat_{p}_{m}.json"
            ft = f"e1_thr_{p}_{m}.json"
            p50 = metric(files, fl, "ns_p50")
            p99 = metric(files, fl, "ns_p99")
            mean = metric(files, fl, "ns_mean")
            mops = metric(files, ft, "mops_per_s")
            ovl = None
            if p50 is not None and base_lat:
                ovl = round((p50 / base_lat - 1.0) * 100.0, 2)
            ovt = None
            if mops is not None and base_thr:
                ovt = round((1.0 - mops / base_thr) * 100.0, 2)
            lat[p][m] = {"ns_p50": p50, "ns_p99": p99, "ns_mean": mean,
                         "overhead_pct_vs_vanilla": ovl, "source": fl}
            thr[p][m] = {"mops_per_s": mops,
                         "throughput_loss_pct_vs_vanilla": ovt, "source": ft}
    return lat, thr


def elision_recovery(files, lat):
    """recovery % = (tx - tx-elide) / (tx - vanilla) on ns_p50, guarded."""
    out = {}
    for p in W8:
        v = lat[p]["vanilla"]["ns_p50"]
        t = lat[p]["tx"]["ns_p50"]
        e = lat[p]["tx-elide"]["ns_p50"]
        entry = {
            "formula": "(tx - tx_elide) / (tx - vanilla) * 100 on ns_p50",
            "sources": [f"e1_lat_{p}_{m}.json"
                        for m in ("vanilla", "tx", "tx-elide")],
        }
        if None in (v, t, e):
            entry["recovery_pct"] = None
            entry["note"] = "missing inputs"
            notes.append(f"elision recovery {p}: missing E1 inputs")
        else:
            denom = t - v
            if denom <= max(1e-9, 0.005 * v):
                entry["recovery_pct"] = None
                entry["note"] = (f"tx overhead over vanilla too small to "
                                 f"attribute ({denom:.3f} ns)")
            else:
                entry["recovery_pct"] = round((t - e) / denom * 100.0, 2)
        out[p] = entry
    return out


# ---------------------------------------------------------------------------
# E2 linear fit (C5)
# ---------------------------------------------------------------------------
def e2_fit(files):
    d = files.get("e2_micro.json")
    out = {"source": "e2_micro.json"}
    if d is None or "_load_error" in d:
        notes.append("e2_micro.json: missing/unreadable")
        out["error"] = "missing/unreadable"
        return out
    # tolerant extraction: accept either one run per (op, k) with fields
    # op/kind + k/log_records/records and metrics.ns_p50|ns_mean, or a flat
    # metrics dict with keys like commit_k8_ns_p50.
    pts = {"commit": [], "abort": [], "append": []}
    for run in d.get("runs", []):
        mt = run.get("metrics", run)
        op = run.get("op") or run.get("kind") or run.get("bench")
        k = run.get("k") or run.get("log_k") or run.get("records") \
            or run.get("log_records") or mt.get("k") or mt.get("records")
        val = mt.get("ns_p50", mt.get("ns_mean"))
        if op in pts and k is not None and val is not None:
            pts[op].append((int(k), float(val)))
            continue
        if isinstance(mt, dict):
            for key, v in mt.items():
                for op2 in pts:
                    if key.startswith(op2) and key.endswith(
                            ("ns_p50", "ns_mean")):
                        digits = "".join(c for c in key if c.isdigit())
                        if digits:
                            pts[op2].append((int(digits), float(v)))
    for op in pts:
        pts[op] = sorted(set(pts[op]))
    if len(pts["commit"]) >= 3:
        out["commit_points"] = pts["commit"]
        out["raw_curve_note"] = (
            "raw per-op curves INCLUDE tx_begin + k log appends (see "
            "e2_micro.json notes); commit-only / abort-only costs are "
            "derived below as (op - append) at each k")
        app = dict(pts["append"])
        # commit-only = commit - append (both include begin + k appends)
        co = [(k, round(v - app[k], 3)) for k, v in pts["commit"]
              if k in app]
        ab = [(k, round(v - app[k], 3)) for k, v in pts["abort"]
              if k in app]
        out["commit_minus_append_points"] = co
        out["abort_minus_append_points"] = ab
        out["commit_only_ns_per_record"] = [
            (k, round(v / k, 2)) for k, v in co]
        if ab:
            out["abort_only_ns"] = {
                "min": min(v for _, v in ab), "max": max(v for _, v in ab),
                "note": "flat in k (O(1) log reset); raw abort curve is "
                        "dominated by the k appends each rep performs",
            }
        # linear fit of commit-only over the workload-realistic range
        # (all bytecode workloads log <= ~8 records; large k stresses the
        # stripe-set dedup + cache footprint and grows superlinearly)
        small = [(k, v) for k, v in co if k <= 16]
        for name, data in (("commit_only_fit_k_le_16", small),
                           ("commit_only_fit_all_k", co)):
            if len(data) >= 3:
                ks = np.array([k for k, _ in data], dtype=float)
                vs = np.array([v for _, v in data], dtype=float)
                slope, intercept = np.polyfit(ks, vs, 1)
                pred = slope * ks + intercept
                ss_res = float(np.sum((vs - pred) ** 2))
                ss_tot = float(np.sum((vs - np.mean(vs)) ** 2))
                out[name] = {
                    "slope_ns_per_record": round(float(slope), 4),
                    "intercept_ns": round(float(intercept), 3),
                    "points": len(ks),
                    "r_squared": round(1.0 - ss_res / ss_tot, 6)
                                 if ss_tot > 0 else None,
                    "fit": "numpy.polyfit deg 1 over (commit-append) ns_p50",
                }
        out["linearity_note"] = (
            "commit-only cost is near-linear for k <= 16 (workload range) "
            "but the per-record cost grows with k (see "
            "commit_only_ns_per_record): 'linear in log size' holds only "
            "as a small-k approximation, not across k = 1..256")
    else:
        out["error"] = ("could not extract >=3 (k, ns) commit points from "
                        "e2_micro.json runs")
        notes.append("e2_micro.json: unrecognized structure for fit; "
                     "recorded raw in summary")
    for op in ("abort", "append"):
        if pts[op]:
            out[f"{op}_points"] = pts[op]
    return out


# ---------------------------------------------------------------------------
# E5 abort rate / goodput (C6)
# ---------------------------------------------------------------------------
def e5_table(files):
    out = []
    for t in (1, 2, 4, 8):
        for z in ("0.0", "0.9", "1.2"):
            for m in ("tx-elide", "vanilla"):
                fn = f"e5_{t}t_z{z}_{m}.json"
                r, err = get_run(files, fn)
                row = {"threads": t, "zipf_theta": float(z), "mode": m,
                       "source": fn}
                if err:
                    notes.append(err)
                    row["error"] = err
                    out.append(row)
                    continue
                mt = r.get("metrics", {})
                ops = mt.get("ops_total")
                conf = mt.get("aborts_conflict")
                row["mops_per_s"] = mt.get("mops_per_s")
                row["goodput_commits_per_s"] = mt.get(
                    "goodput_commits_per_s")
                row["abort_rate"] = (round(conf / ops, 6)
                                     if ops and conf is not None else None)
                out.append(row)
    return out


# ---------------------------------------------------------------------------
# text tables
# ---------------------------------------------------------------------------
def fmt(v, w=10, prec=1):
    if v is None:
        return " " * (w - 4) + "null"
    if isinstance(v, float):
        return f"{v:>{w}.{prec}f}"
    return f"{v:>{w}}"


def print_tables(lat, thr, rec, e4, e2, e5, e3):
    print("\n== E1 latency ns_p50 (overhead% vs vanilla) ==")
    hdr = f"{'workload':<14}" + "".join(f"{m:>22}" for m in MODES)
    print(hdr)
    for p in W8:
        row = f"{p:<14}"
        for m in MODES:
            c = lat[p][m]
            if c["ns_p50"] is None:
                row += f"{'null':>22}"
            else:
                ov = c["overhead_pct_vs_vanilla"]
                ovs = f"({ov:+.1f}%)" if ov is not None else ""
                row += f"{c['ns_p50']:>12.1f} {ovs:>9}"
        print(row)

    print("\n== E1 throughput Mops/s, 8 threads ==")
    print(hdr)
    for p in W8:
        row = f"{p:<14}"
        for m in MODES:
            c = thr[p][m]
            if c["mops_per_s"] is None:
                row += f"{'null':>22}"
            else:
                ov = c["throughput_loss_pct_vs_vanilla"]
                ovs = f"({ov:+.1f}%)" if ov is not None else ""
                row += f"{c['mops_per_s']:>12.2f} {ovs:>9}"
        print(row)

    print("\n== Elision recovery (latency p50) ==")
    for p in W8:
        r = rec[p]
        val = r.get("recovery_pct")
        extra = r.get("note", "")
        print(f"  {p:<14} {fmt(val, 8, 1)}%  {extra}")

    print("\n== E4 elision (static) ==")
    print(f"{'prog':<14}{'mem insns':>10}{'tx%':>8}{'direct%':>9}"
          f"{'fuel':>6}  ro_maps")
    for p in ALL10:
        c = e4.get(p)
        if not c:
            print(f"{p:<14}{'(missing)':>10}")
            continue
        print(f"{p:<14}{fmt(c.get('n_mem_insns'), 10)}"
              f"{fmt(c.get('elided_tx_pct'), 8, 1)}"
              f"{fmt(c.get('elided_direct_pct'), 9, 1)}"
              f"{str(c.get('fuel_elided')):>6}  {c.get('ro_maps')}")

    print("\n== E2 commit-only (commit - append) vs log size ==")
    cf = e2.get("commit_only_fit_k_le_16")
    if cf:
        print(f"  k<=16 fit: slope {cf['slope_ns_per_record']} ns/record, "
              f"intercept {cf['intercept_ns']} ns, "
              f"R^2 {cf['r_squared']} [{e2['source']}]")
        for k, v in e2.get("commit_only_ns_per_record", []):
            print(f"    k={k:>3}: {v:8.2f} ns/record (commit-only)")
        ao = e2.get("abort_only_ns")
        if ao:
            print(f"  abort-only: {ao['min']}..{ao['max']} ns, flat in k")
    else:
        print(f"  unavailable: {e2.get('error')}")

    print("\n== E5 abort rate / goodput (flowstats) ==")
    print(f"{'thr':>4}{'theta':>7}{'mode':>10}{'Mops/s':>10}"
          f"{'abort_rate':>12}{'goodput/s':>14}")
    for row in e5:
        print(f"{row['threads']:>4}{row['zipf_theta']:>7.1f}"
              f"{row['mode']:>10}"
              f"{fmt(row.get('mops_per_s'), 10, 2)}"
              f"{fmt(row.get('abort_rate'), 12, 4)}"
              f"{fmt(row.get('goodput_commits_per_s'), 14, 0)}")

    print("\n== E3 invariant results ==")
    for k in sorted(e3):
        print(f"  {k:<22} {e3[k]}")


def main():
    files = load_all()
    if not files:
        print(f"analyze.py: no results found in {RES}", file=sys.stderr)
        sys.exit(1)
    e3 = check_e3(files)
    e4 = check_e4(files)
    lat, thr = e1_tables(files)
    rec = elision_recovery(files, lat)
    e2 = e2_fit(files)
    e5 = e5_table(files)
    notes[:] = list(dict.fromkeys(notes))  # dedupe, keep order

    summary = {
        "generated": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "generator": "experiments/analyze.py",
        "note": ("every derived number cites its source results file; "
                 "nulls mark missing/failed runs (see notes)"),
        "e3_expectations": e3,
        "e4_elision": e4,
        "e1_latency": lat,
        "e1_throughput": thr,
        "elision_recovery": rec,
        "e2_fit": e2,
        "e5_contention": e5,
        "expectation_failures": expectation_failures,
        "notes": notes,
    }
    out = os.path.join(RES, "summary.json")
    with open(out, "w") as f:
        json.dump(summary, f, indent=2)
        f.write("\n")

    print_tables(lat, thr, rec, e4, e2, e5, e3)

    if expectation_failures:
        print("\n" + "!" * 72)
        for x in expectation_failures:
            print("FAILED EXPECTATION:", x)
        print("!" * 72)
    else:
        print("\nAll E3/E4 invariant expectations satisfied "
              "(or inputs missing - see notes).")
    if notes:
        print(f"\nnotes ({len(notes)}):")
        for n in notes:
            print("  -", n)
    print(f"\nsummary written to {out}")
    sys.exit(2 if expectation_failures else 0)


if __name__ == "__main__":
    main()
