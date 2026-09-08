#!/usr/bin/env python3
"""analyze_v2.py — derive every number the paper cites from the raw
result JSONs in experiments/results/v2, and nothing else.

Rules this script follows, so the paper can state them:
  * a cell measured more than once is reported as median [min, max] over
    the repeats; a comparison whose difference is inside the union of the
    two cells' ranges is labelled *parity*, never a win;
  * derived quantities (overheads, recovery fractions, fits) are computed
    here from stored values, never transcribed;
  * every table records the files it came from.
"""
import glob
import json
import os
import re
import statistics as st
import sys

RES = os.path.join(os.path.dirname(__file__), 'results', 'v2')
OUT = {}
FILES = {}


def load(p):
    with open(p) as f:
        return json.load(f)


def runs(p):
    d = load(p)
    return d['runs'][0] if 'runs' in d else d


def med(xs):
    return st.median(xs) if xs else None


def cell(vals):
    return dict(median=med(vals), min=min(vals) if vals else None,
                max=max(vals) if vals else None, n=len(vals))


def overlap(a, b):
    """Do two cells' [min,max] ranges overlap?  If so the comparison is
    inside run-to-run noise and must be reported as parity."""
    if not a or not b or a['min'] is None or b['min'] is None:
        return False
    return not (a['max'] < b['min'] or b['max'] < a['min'])


# ------------------------------------------------------------------ E1
TAGS = ('vanilla', 'sfi', 'tx', 'tx-elide', '2pl', 'txnd', 'tx-elidend',
        'jvanilla', 'jsfi', 'jtx', 'jtx-elide', 'j2pl')
TAG_RE = '|'.join(re.escape(t) for t in sorted(TAGS, key=len, reverse=True))


def e1(prefix, metric, key):
    grid = {}
    for p in sorted(glob.glob(os.path.join(RES, f'{prefix}_*_r*.json'))):
        m = re.match(rf'{prefix}_(.+)_({TAG_RE})_r(\d+)\.json$',
                     os.path.basename(p))
        if not m:
            continue
        prog, mode = m.group(1), m.group(2)
        r = runs(p)
        if 'metrics' not in r:
            continue
        grid.setdefault(prog, {}).setdefault(mode, []).append(r['metrics'][key])
        FILES.setdefault(metric, set()).add(os.path.basename(p))
    out = {}
    for prog, modes in grid.items():
        row = {mo: cell(v) for mo, v in modes.items()}
        base = row.get('vanilla')
        for mo, c in row.items():
            if base and base['median'] and mo != 'vanilla':
                rel = c['median'] / base['median'] - 1.0
                c['vs_vanilla_pct'] = round(100 * rel, 1)
                c['parity'] = overlap(c, base)
        out[prog] = row
    return out


def e1_memory():
    mem = {}
    for p in sorted(glob.glob(os.path.join(RES, 'e1_lat_*_tx_r1.json'))):
        r = runs(p)
        if 'memory' not in r:
            continue
        prog = re.match(r'e1_lat_(.+)_tx_r1\.json$', os.path.basename(p)).group(1)
        mem[prog] = r['memory']
    return mem


# ------------------------------------------------------------------ E2
def e2():
    p = os.path.join(RES, 'e2_micro.json')
    if not os.path.exists(p):
        return None
    d = load(p)
    pts = {}
    for r in d.get('runs', []):
        k = r.get('log_k', r.get('k'))
        op = r.get('op') or r.get('operation')
        v = (r.get('metrics') or {}).get('ns_p50')
        if k is None or op is None or v is None:
            continue
        pts.setdefault(op, {})[int(k)] = v
    if not pts:
        return None
    ap = pts.get('append', {})
    res = {'raw': pts, 'derived': {}}
    for op in ('commit', 'abort'):
        cur = pts.get(op, {})
        res['derived'][op + '_only'] = {str(k): round(cur[k] - ap.get(k, 0), 3)
                                        for k in sorted(cur) if k in ap}
    # linear fit of commit-only over k <= 16
    xs = [k for k in sorted(pts.get('commit', {})) if k <= 16 and k in ap]
    ys = [pts['commit'][k] - ap[k] for k in xs]
    if len(xs) >= 3:
        n = len(xs)
        mx, my = sum(xs) / n, sum(ys) / n
        sxy = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
        sxx = sum((x - mx) ** 2 for x in xs)
        slope = sxy / sxx
        icpt = my - slope * mx
        ss_res = sum((y - (slope * x + icpt)) ** 2 for x, y in zip(xs, ys))
        ss_tot = sum((y - my) ** 2 for y in ys)
        res['fit_k_le_16'] = dict(ns_per_record=round(slope, 2),
                                  intercept_ns=round(icpt, 2),
                                  r2=round(1 - ss_res / ss_tot, 4)
                                  if ss_tot else None, points=n)
    return res


# ------------------------------------------------------------------ E3
def e3():
    a, b = {}, {}
    for p in sorted(glob.glob(os.path.join(RES, 'e3a_*.json'))):
        m = re.match(rf'e3a_(\w+)_({TAG_RE})_r(\d+)\.json$',
                     os.path.basename(p))
        if not m:
            continue
        r = runs(p)['metrics']
        a.setdefault(m.group(1), {}).setdefault(m.group(2), []).append(r)
    for p in sorted(glob.glob(os.path.join(RES, 'e3b_*.json'))):
        m = re.match(rf'e3b_(\w+)_({TAG_RE})\.json$', os.path.basename(p))
        if not m:
            continue
        b.setdefault(m.group(1), {})[m.group(2)] = runs(p)['metrics']
    a2 = {}
    for pair, modes in a.items():
        a2[pair] = {}
        for mo, rs in modes.items():
            a2[pair][mo] = dict(
                violations=cell([r['violations'] for r in rs]),
                reader_commits=cell([r['reader_commits'] for r in rs]),
                reader_conflicts=cell([r['reader_conflicts'] for r in rs]),
                writer_aborts=cell([r['writer_other_aborts'] for r in rs]),
                final_torn=cell([r.get('final_torn_keys', 0) for r in rs]))
    return dict(e3a=a2, e3b=b)


# ------------------------------------------------------------------ E5
def e5():
    grid = {}
    for p in sorted(glob.glob(os.path.join(RES, 'e5_*_r*.json'))):
        m = re.match(rf'e5_(\d+)t_z([\d.]+)_({TAG_RE})_r(\d+)\.json$',
                     os.path.basename(p))
        if not m:
            continue
        t, z, mo = int(m.group(1)), m.group(2), m.group(3)
        r = runs(p)['metrics']
        e = grid.setdefault((t, z, mo), {'good': [], 'abort': [], 'ops': []})
        e['good'].append(r['goodput_commits_per_s'])
        e['ops'].append(r['mops_per_s'])
        tot = (r['commits'] + r['aborts_conflict'] + r['aborts_capacity']
               + r['aborts_deadlock'])
        e['abort'].append(100.0 * (r['aborts_conflict'] + r['aborts_capacity']
                                   + r['aborts_deadlock']) / tot if tot else 0)
    return {f'{t}t_z{z}_{mo}': dict(goodput=cell(v['good']),
                                    mops=cell(v['ops']),
                                    abort_pct=cell(v['abort']))
            for (t, z, mo), v in sorted(grid.items())}


# ------------------------------------------------------------------ E4
def e4():
    p = os.path.join(RES, 'e4_elision.json')
    if not os.path.exists(p):
        return None
    d = load(p)
    return {r.get('program', r.get('prog', '?')): r for r in d['runs']}


# ------------------------------------------------------------------ E8/E9
def e8():
    out = {}
    for p in sorted(glob.glob(os.path.join(RES, 'e8_*.json'))):
        d = load(p)
        out[os.path.basename(p)] = dict(meta=d['meta'],
                                        committed=d['committed'],
                                        conflict_aborts=d['conflict_aborts'])
    for name in ('e8_check_tx.txt', 'e8_check_direct.txt'):
        q = os.path.join(RES, name)
        if os.path.exists(q):
            txt = open(q).read()
            out[name] = dict(
                serializable=txt.count('"verdict": "SERIALIZABLE"'),
                not_serializable=txt.count('"verdict": "NOT_SERIALIZABLE"'),
                lost_updates=[int(x) for x in
                              re.findall(r'"lost_updates": (\d+)', txt)],
                orphan_reads=[int(x) for x in
                              re.findall(r'"orphan_reads": (\d+)', txt)],
                cyclic=[x for x in re.findall(r'"cyclic": (\w+)', txt)])
    return out


def e9():
    out = {}
    for p in sorted(glob.glob(os.path.join(RES, 'e9_*.json'))):
        r = runs(p)
        out[os.path.basename(p)[3:-5]] = dict(
            mode=r['mode'], vector=r['vector'],
            default=r['default_verdict'], retries=r['retries'],
            bypass_pct=round(100 * r['metrics']['bypass_rate'], 4),
            false_drop_pct=round(100 * r['metrics']['false_drop_rate'], 4),
            aborts_conflict=r['metrics']['aborts_conflict'],
            aborts_fuel=r['metrics']['aborts_fuel'],
            aborts_deadlock=r['metrics']['aborts_deadlock'],
            retries_used=r['metrics']['retries'])
    return out


def e10():
    p = os.path.join(RES, 'e10_corpus.json')
    if not os.path.exists(p):
        p = os.path.join(os.path.dirname(RES), 'e10_corpus.json')
    if not os.path.exists(p):
        return None
    d = load(p)
    s = dict(d['summary'])
    progs = d['programs']
    prod = {'cilium_cilium', 'facebookincubator_katran', 'cilium_tetragon',
            'aquasecurity_tracee', 'DataDog_datadog-agent',
            'cloudflare_ebpf_exporter'}

    def sub(sel):
        eff = [p for p in sel if p['writes']]
        w2 = [p for p in sel if len(p['writes']) >= 2]
        return dict(programs=len(sel), effectful=len(eff), write2=len(w2),
                    pct_of_effectful=round(100 * len(w2) / len(eff), 1)
                    if eff else 0)
    s['by_class'] = dict(
        production=sub([p for p in progs if p['repo'] in prod]),
        kernel_selftests=sub([p for p in progs if p['repo'] == 'linux']),
        bcc_tools=sub([p for p in progs if p['repo'] == 'iovisor_bcc']))
    s['by_repo'] = {r: sub([p for p in progs if p['repo'] == r])
                    for r in sorted({p['repo'] for p in progs})}
    return s


def e11():
    p = os.path.join(RES, 'e11_model_check.json')
    return load(p) if os.path.exists(p) else None


def main():
    OUT['e1_latency_ns_p50'] = e1('e1_lat', 'e1_lat', 'ns_p50')
    OUT['e1_latency_ns_p99'] = e1('e1_lat', 'e1_lat_p99', 'ns_p99')
    OUT['e1_throughput_mops'] = e1('e1_thr', 'e1_thr', 'mops_per_s')
    OUT['e7_memory'] = e1_memory()
    OUT['e2'] = e2()
    OUT.update(e3())
    OUT['e5'] = e5()
    OUT['e4_elision'] = e4()
    OUT['e8_serializability'] = e8()
    OUT['e9_policy'] = e9()
    OUT['e10_corpus'] = e10()
    OUT['e11_model_check'] = e11()

    # derived: guard+fuel cost and elision recovery, per workload (p50)
    lat = OUT['e1_latency_ns_p50']
    rec = {}
    for prog, row in lat.items():
        for arm, pre in (('interp', ''), ('jit', 'j')):
            keys = [pre + k for k in ('vanilla', 'sfi', 'tx', 'tx-elide')]
            if not all(k in row for k in keys):
                continue
            v, sf, tx, te = (row[k]['median'] for k in keys)
            g = sf - v                       # SFI guard + fuel cost
            a = tx - sf                      # transactional add-on
            r = tx - te                      # what elision gives back
            rec.setdefault(prog, {})[arm] = dict(
                body_ns=round(v, 2),
                guard_fuel_cost_ns=round(g, 2),
                tx_addon_ns=round(a, 2),
                elision_recovery_ns=round(r, 2),
                post_elision_addon_ns=round(te - v, 2),
                recovery_pct_of_guard_cost=(round(100 * r / g, 1)
                                            if g > 0 else None),
                recovery_pct_of_total_overhead=(round(100 * r / (tx - v), 1)
                                                if tx > v else None))
    OUT['e4x_e1_recovery'] = rec

    # derived: what shadow diffing is worth (nodiff - diff)
    thr = OUT['e1_throughput_mops']
    sd = {}
    for prog in lat:
        e = {}
        for mo, nd in (('tx', 'txnd'), ('tx-elide', 'tx-elidend')):
            if mo in lat[prog] and nd in lat[prog]:
                e[f'{mo}_lat_pct'] = round(
                    100 * (lat[prog][mo]['median'] / lat[prog][nd]['median']
                           - 1), 1)
            if prog in thr and mo in thr[prog] and nd in thr[prog]:
                e[f'{mo}_thr_pct'] = round(
                    100 * (thr[prog][mo]['median'] / thr[prog][nd]['median']
                           - 1), 1)
                e[f'{mo}_conflicts_diff'] = None
        sd[prog] = e
    OUT['e1b_shadow_diff_effect'] = sd

    OUT['_provenance'] = {k: sorted(v) for k, v in FILES.items()}
    with open(os.path.join(RES, 'summary_v2.json'), 'w') as f:
        json.dump(OUT, f, indent=1, default=str)

    # --- derived CSVs -----------------------------------------------------
    proj = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    data = os.path.join(proj, 'experiments', 'derived')
    os.makedirs(data, exist_ok=True)
    order = ['pktcount', 'flowstats', 'tokenbucket', 'maglev', 'ctnat',
             'pktrewrite', 'atomic_demo', 'firewall', 'loopy']
    for arm, name in (('interp', 'v2_recovery.csv'),
                      ('jit', 'v2_recovery_jit.csv')):
        with open(os.path.join(data, name), 'w') as f:
            f.write('workload,guardcost,txaddon,recovered\n')
            for w in order:
                r = rec.get(w, {}).get(arm)
                if r and w != 'loopy':
                    f.write(f"{w},{r['guard_fuel_cost_ns']},"
                            f"{r['tx_addon_ns']},{r['elision_recovery_ns']}\n")
    def e5g(t, z, tag, field='goodput'):
        c = OUT['e5'].get(f'{t}t_z{z}_{tag}', {}).get(field, {})
        v = c.get('median')
        return (v or 0) / (1e6 if field == 'goodput' else 1)
    for arm, pre in (('', ''), ('jit', 'j')):
        name = 'v2_e5.csv' if not arm else 'v2_e5_jit.csv'
        with open(os.path.join(data, name), 'w') as f:
            f.write('threads,g00,g09,g12,a00,a09,a12,v00,p00\n')
            for t in (1, 2, 4, 8):
                g = [e5g(t, z, pre + 'tx-elide') for z in ('0.0', '0.9', '1.2')]
                a = [e5g(t, z, pre + 'tx-elide', 'abort_pct')
                     for z in ('0.0', '0.9', '1.2')]
                v = e5g(t, '0.0', pre + 'vanilla')
                q = e5g(t, '0.0', pre + '2pl')
                f.write(f"{t},{g[0]:.3f},{g[1]:.3f},{g[2]:.3f},"
                        f"{a[0]:.3f},{a[1]:.3f},{a[2]:.3f},{v:.3f},{q:.3f}\n")
    if OUT['e2']:
        with open(os.path.join(data, 'v2_e2.csv'), 'w') as f:
            f.write('k,commit,abort,append\n')
            for k in sorted(int(x) for x in OUT['e2']['raw'].get('commit', {})):
                r = OUT['e2']['raw']
                f.write(f"{k},{r['commit'][k]},{r['abort'][k]},"
                        f"{r['append'][k]}\n")
    with open(os.path.join(data, 'v2_bypass.csv'), 'w') as f:
        f.write('retries,tx_pass,tx_drop_falsedrop,jtx_pass,jtx_drop\n')
        for rr in (0, 1, 2, 4, 8):
            a = OUT['e9_policy'].get(f'conflict_tx_pass_r{rr}')
            b = OUT['e9_policy'].get(f'conflict_tx_drop_r{rr}')
            c = OUT['e9_policy'].get(f'conflict_jtx_pass_r{rr}')
            d = OUT['e9_policy'].get(f'conflict_jtx_drop_r{rr}')
            if a and b:
                f.write(f"{rr},{a['bypass_pct']},{b['false_drop_pct']},"
                        f"{c['bypass_pct'] if c else ''},"
                        f"{d['false_drop_pct'] if d else ''}\n")
    print(json.dumps({k: v for k, v in OUT.items()
                      if k in ('e4x_e1_recovery', 'e1b_shadow_diff_effect')},
                     indent=1)[:2000])
    print(f"\nwrote {RES}/summary_v2.json and experiments/derived/v2_*.csv")


if __name__ == '__main__':
    sys.exit(main())
