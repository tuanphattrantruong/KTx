#!/usr/bin/env python3
"""corpus_survey.py — how common is multi-map effect in real eBPF?

The KTx motivation rests on a claim about deployed code: that real
extensions routinely mutate more than one map in a single invocation, so
that per-map atomicity leaves cross-map state unprotected.  This survey
measures that claim over open-source eBPF C source instead of asserting it.

Method.  For every C file in a repository that both defines a BPF map and
contains a `SEC(...)`-annotated function:

  1. comments and string literals are blanked, so nothing below matches
     inside them;
  2. map objects are collected from the three declaration styles in the
     wild (libbpf `struct {...} NAME SEC(".maps")`, legacy
     `struct bpf_map_def SEC("maps") NAME`, and the `__section_maps*`
     forms Cilium and Katran use);
  3. every function body is extracted by brace matching, and the ones
     preceded by SEC()/__section() are marked as *entry points* — one
     eBPF program each;
  4. inside a body we record map reads (`..._lookup_elem(&M`) and map
     writes (`..._update_elem(&M`, `..._delete_elem(&M`, push/pop).  A
     lookup whose result is stored through — `v = bpf_map_lookup_elem(&M,
     ..); v->x = ..` or `__sync_fetch_and_add(&v->x, 1)` — is *also*
     counted as a write to M, because that is eBPF's dominant mutation
     idiom and the one this paper is about;
  5. calls between functions of the same repository are resolved by name
     and map effects are propagated transitively from each entry point
     (fixpoint over the call graph), so effects reached through
     `static __always_inline` helpers are attributed to the program.

Limits, stated up front: this is a syntactic analysis of C, not of
bytecode.  Effects hidden behind repository-specific macros that do not
textually contain a helper name are missed; same-named static functions
in different files are merged; tail calls are not followed (each tail
target is its own program, which is the correct unit anyway); and a
program that writes two maps is a *candidate* for a cross-map invariant,
not a proof of one.  All of these bias the multi-map-write count
*downwards* except the name-merging, which we quantify separately.
"""
import json
import os
import re
import sys
from collections import defaultdict

# ---------------------------------------------------------------- lexing
def blank_comments(src):
    """Blank comments only.  String *contents* are kept: `SEC(".maps")`
    and `SEC("tc")` are how programs and maps are declared, so blanking
    them would erase the very thing we are looking for."""
    out = []
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        if c == '/' and i + 1 < n and src[i + 1] == '/':
            j = src.find('\n', i)
            j = n if j < 0 else j
            out.append(' ' * (j - i))
            i = j
        elif c == '/' and i + 1 < n and src[i + 1] == '*':
            j = src.find('*/', i + 2)
            j = n if j < 0 else j + 2
            out.append(''.join(ch if ch == '\n' else ' ' for ch in src[i:j]))
            i = j
        else:
            out.append(c)
            i += 1
    return ''.join(out)


def blank_comments_and_strings(src):
    out = []
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        if c == '/' and i + 1 < n and src[i + 1] == '/':
            j = src.find('\n', i)
            j = n if j < 0 else j
            out.append(' ' * (j - i))
            i = j
        elif c == '/' and i + 1 < n and src[i + 1] == '*':
            j = src.find('*/', i + 2)
            j = n if j < 0 else j + 2
            out.append(''.join(ch if ch == '\n' else ' ' for ch in src[i:j]))
            i = j
        elif c in '"\'':
            q, j = c, i + 1
            while j < n:
                if src[j] == '\\':
                    j += 2
                    continue
                if src[j] == q:
                    j += 1
                    break
                j += 1
            out.append(q + ' ' * max(0, j - i - 2) + q)
            i = j
        else:
            out.append(c)
            i += 1
    return ''.join(out)


# ---------------------------------------------------------------- maps
MAP_PATTERNS = [
    # struct { ... } NAME SEC(".maps");
    re.compile(r'\}\s*(\w+)\s+SEC\s*\(\s*"\.maps"\s*\)\s*;'),
    re.compile(r'\}\s*(\w+)\s+__section_maps_btf\s*;'),
    re.compile(r'\}\s*(\w+)\s+__section\s*\(\s*"\.maps"\s*\)\s*;'),
    # struct bpf_map_def SEC("maps") NAME = {
    re.compile(r'SEC\s*\(\s*"maps[^"]*"\s*\)\s*(\w+)\s*='),
    re.compile(r'__section_maps\s+(\w+)\s*='),
    re.compile(r'__section\s*\(\s*"maps[^"]*"\s*\)\s*(\w+)\s*='),
    # struct bpf_elf_map __section_maps NAME = {   (Cilium / tc)
    re.compile(r'struct\s+bpf_elf_map\s+\w*\s*(\w+)\s*='),
]

SEC_FN = re.compile(r'(?:SEC|__section|__bpf_section)\s*\(\s*"([^"]*)"\s*\)')
# Cilium marks entry points and tail-call targets with argument-free or
# non-string macros; without these its whole datapath looks like library code.
SEC_MACRO = re.compile(
    r'\b(__section_entry|__section_tail\s*\([^)]*\)|'
    r'__declare_tail\s*\([^)]*\)|__section_license)\b')

READ_CALL = re.compile(r'\b(?:bpf_)?map_lookup_(?:elem|percpu_elem)\s*\(\s*&?\s*(\w+)')
WRITE_CALL = re.compile(
    r'\b(?:bpf_)?map_(?:update|delete|push|pop)_elem\s*\(\s*&?\s*(\w+)')
# v = ...lookup...(&M, ...)
ASSIGN_LOOKUP = re.compile(
    r'(\w+)\s*=\s*[^;]*?\b(?:bpf_)?map_lookup_(?:elem|percpu_elem)\s*\(\s*&?\s*(\w+)')

FN_DEF = re.compile(r'(\w[\w\s\*]*?)\b(\w+)\s*\(([^;{}]*)\)\s*\{')

KEYWORDS = {'if', 'for', 'while', 'switch', 'return', 'sizeof', 'else',
            'do', 'case', 'typedef', 'struct', 'union', 'enum'}
# Attribute macros that the loose function-header regex would otherwise
# mistake for function names.
NOT_FN = {'__attribute__', '__section', 'SEC', '__section_tail',
          '__declare_tail', '__always_inline', '__section_entry',
          '__bpf_section', '__maybe_unused', 'static', 'inline',
          'defined', 'offsetof', 'alignof', '__builtin_expect'}
# libbpf's tracing wrappers put the real program name in the first macro
# argument: `SEC("kprobe/x") int BPF_KPROBE(do_x, ...)`.
WRAPPER_FN = {'BPF_KPROBE', 'BPF_KRETPROBE', 'BPF_PROG', 'BPF_UPROBE',
              'BPF_URETPROBE', 'BPF_KSYSCALL', 'BPF_KPROBE_SYSCALL',
              'BPF_STRUCT_OPS', 'BPF_RAW_TRACEPOINT'}


def extract_functions(src):
    """[(name, header_start, body_text)] via brace matching."""
    fns = []
    for m in FN_DEF.finditer(src):
        name = m.group(2)
        if name in WRAPPER_FN:
            first = m.group(3).split(',')[0].strip()
            mm = re.match(r'[\w\s\*]*?(\w+)\s*$', first)
            name = mm.group(1) if mm else name
        elif name in KEYWORDS or name in NOT_FN:
            continue
        start = m.end() - 1              # at '{'
        depth, i, n = 0, start, len(src)
        while i < n:
            if src[i] == '{':
                depth += 1
            elif src[i] == '}':
                depth -= 1
                if depth == 0:
                    break
            i += 1
        if i >= n:
            continue
        fns.append((name, m.start(2), src[start:i + 1]))
    return fns


def written_through(body, var):
    """Is `var` (a map-value pointer) stored through in this body?"""
    v = re.escape(var)
    pats = [
        rf'\*\s*{v}\s*(?:\+\+|--|[-+*/|&^]?=[^=])',
        rf'\b{v}\s*->\s*\w+(?:\s*\[[^\]]*\])?\s*(?:\+\+|--|[-+*/|&^]?=[^=])',
        rf'\b{v}\s*\[[^\]]*\]\s*(?:\+\+|--|[-+*/|&^]?=[^=])',
        rf'__sync_fetch_and_\w+\s*\(\s*&\s*{v}\s*(?:->|\[)',
        rf'__sync_\w+_and_\w+\s*\(\s*{v}\b',
        rf'\b(?:memcpy|memset|__builtin_memcpy|__builtin_memset)\s*\(\s*{v}\b',
        rf'\b(?:memcpy|memset|__builtin_memcpy|__builtin_memset)\s*\(\s*&\s*{v}\s*->',
        rf'\b__sync_bool_compare_and_swap\s*\(\s*&?\s*{v}\b',
    ]
    return any(re.search(p, body) for p in pats)


def analyse_file(path, text, mapnames_global):
    src = blank_comments(text)
    local_maps = set()
    for pat in MAP_PATTERNS:
        for m in pat.finditer(src):
            local_maps.add(m.group(1))
    fns = extract_functions(src)
    if not fns:
        return None
    known = mapnames_global | local_maps

    entries, table = [], {}
    for name, hstart, body in fns:
        window = src[max(0, hstart - 260):hstart]
        secs = SEC_FN.findall(window)
        secs = [s for s in secs if s not in ('.maps',) and
                not s.startswith('maps')]
        if not secs:
            mm = SEC_MACRO.findall(window)
            secs = [re.sub(r'\s+', '', m2) for m2 in mm
                    if not m2.startswith('__section_license')]
        reads, writes, calls = set(), set(), set()
        for m in READ_CALL.finditer(body):
            if m.group(1) in known:
                reads.add(m.group(1))
        for m in WRITE_CALL.finditer(body):
            if m.group(1) in known:
                writes.add(m.group(1))
        for m in ASSIGN_LOOKUP.finditer(body):
            var, mp = m.group(1), m.group(2)
            if mp in known and written_through(body, var):
                writes.add(mp)
        for m in re.finditer(r'\b(\w+)\s*\(', body):
            calls.add(m.group(1))
        table[name] = dict(reads=reads, writes=writes, calls=calls)
        if secs:
            entries.append((name, secs[-1]))
    return dict(path=path, maps=local_maps, table=table, entries=entries)


def survey(root, repo, follow_calls=True):
    files = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames
                       if d not in ('.git', 'vendor', 'node_modules',
                                    'testdata', 'third_party')]
        for fn in filenames:
            if fn.endswith(('.c', '.h')):
                files.append(os.path.join(dirpath, fn))
    parsed, all_maps = [], set()
    texts = {}
    for p in files:
        try:
            t = open(p, errors='ignore').read()
        except OSError:
            continue
        if not any(k in t for k in ('SEC(', '__section(', '__section_maps',
                                    'map_lookup_elem', 'map_update_elem',
                                    'bpf_map_def', 'bpf_elf_map')):
            continue
        texts[p] = t
    # pass 1: map names
    for p, t in texts.items():
        src = blank_comments(t)
        for pat in MAP_PATTERNS:
            for m in pat.finditer(src):
                all_maps.add(m.group(1))
    # pass 2: per-file function tables, keyed (file, name).  Calls resolve
    # to the same file first; otherwise to a repo-wide *unique* definition
    # of that name.  Names defined in several files with no same-file
    # definition are unresolvable and flagged, never merged — merging them
    # would inflate the multi-map counts this survey exists to measure.
    node = {}
    byname = defaultdict(list)
    for p, t in texts.items():
        r = analyse_file(p, t, all_maps)
        if not r:
            continue
        parsed.append(r)
        for k, v in r['table'].items():
            node[(p, k)] = dict(reads=set(v['reads']), writes=set(v['writes']),
                                calls=set(v['calls']), unresolved=0)
            byname[k].append(p)

    def resolve(caller_file, name):
        if (caller_file, name) in node:
            return (caller_file, name)
        cands = byname.get(name, [])
        if len(cands) == 1:
            return (cands[0], name)
        return None

    for _ in range(16 if follow_calls else 0):
        changed = False
        for (p, name), e in node.items():
            for c in e['calls']:
                if c == name:
                    continue
                key = resolve(p, c)
                if key is None:
                    if c in byname:
                        e['unresolved'] = 1
                    continue
                t2 = node[key]
                nr, nw = len(e['reads']), len(e['writes'])
                e['reads'] |= t2['reads']
                e['writes'] |= t2['writes']
                e['unresolved'] |= t2['unresolved']
                if len(e['reads']) != nr or len(e['writes']) != nw:
                    changed = True
        if not changed:
            break

    progs = []
    for r in parsed:
        for name, sec in r['entries']:
            e = node.get((r['path'], name))
            if not e:
                continue
            progs.append(dict(repo=repo,
                              file=os.path.relpath(r['path'], root),
                              prog=name, sec=sec,
                              reads=sorted(e['reads']),
                              writes=sorted(e['writes']),
                              ambiguous_name=bool(e['unresolved'])))
    return progs, sorted(all_maps)


def main():
    root = sys.argv[1]
    out = sys.argv[2] if len(sys.argv) > 2 else None
    # --direct-only disables call-graph propagation: effects are counted
    # only where they appear syntactically in the entry point's own body.
    # It is a strict lower bound with no over-attribution risk, and the
    # gap between the two is the sensitivity of the headline number to
    # the one analysis step that could inflate it.
    follow = '--direct-only' not in sys.argv
    repos = sorted(d for d in os.listdir(root)
                   if os.path.isdir(os.path.join(root, d)))
    allprogs, permap = [], {}
    for repo in repos:
        progs, maps = survey(os.path.join(root, repo), repo, follow)
        permap[repo] = len(maps)
        allprogs.extend(progs)
        nw2 = sum(1 for p in progs if len(p['writes']) >= 2)
        print(f"{repo:<28} programs={len(progs):>5}  maps={len(maps):>4}  "
              f"write>=2 maps={nw2:>4} "
              f"({100.0*nw2/len(progs) if progs else 0:.1f}%)")

    n = len(allprogs)
    eff = [p for p in allprogs if p['writes']]
    w2 = [p for p in allprogs if len(p['writes']) >= 2]
    w3 = [p for p in allprogs if len(p['writes']) >= 3]
    rw = [p for p in allprogs
          if p['reads'] and set(p['writes']) - set(p['reads'])]
    amb = [p for p in allprogs if p['ambiguous_name']]
    dist = defaultdict(int)
    for p in allprogs:
        dist[len(p['writes'])] += 1
    summary = dict(
        programs=n, programs_with_any_write=len(eff),
        programs_writing_2plus_maps=len(w2),
        programs_writing_3plus_maps=len(w3),
        programs_read_one_write_another=len(rw),
        follow_calls=follow,
        pct_writing_2plus=round(100.0 * len(w2) / n, 2) if n else 0,
        pct_of_effectful_writing_2plus=(round(100.0 * len(w2) / len(eff), 2)
                                        if eff else 0),
        ambiguous_name_programs=len(amb),
        write_multiplicity_histogram={str(k): v for k, v in sorted(dist.items())},
        maps_per_repo=permap,
        top_multimap_programs=sorted(
            ({k: p[k] for k in ('repo', 'file', 'prog', 'sec', 'writes')}
             for p in w2), key=lambda x: -len(x['writes']))[:25],
    )
    print("\n== corpus totals ==")
    for k, v in summary.items():
        if k not in ('top_multimap_programs', 'maps_per_repo'):
            print(f"  {k}: {v}")
    if out:
        json.dump(dict(summary=summary, programs=allprogs), open(out, 'w'),
                  indent=1)
        print(f"\nwrote {out}")


if __name__ == '__main__':
    main()
