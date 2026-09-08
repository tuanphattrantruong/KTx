#!/usr/bin/env python3
"""corpus_validate.py — draw a stratified sample from the corpus survey
and print the evidence a human needs to label it by hand.

The survey (tools/corpus_survey.py) is a syntactic analysis, so its
headline number is only as good as its precision and recall. This dumps a
seeded random sample of programs together with every map-helper call site
the analysis attributed to them, so the labels in
experiments/results/v2/e10_validation.json can be checked, and re-checked
by a reader, rather than taken on trust.
"""
import json
import os
import random
import re
import sys

CALL = re.compile(r'\b(?:bpf_)?map_(?:lookup|update|delete|push|pop)'
                  r'_(?:elem|percpu_elem)\s*\(\s*&?\s*(\w+)')


def evidence(root, repo, path, prog):
    full = os.path.join(root, repo, path)
    try:
        src = open(full, errors='ignore').read().splitlines()
    except OSError:
        return ["<file unavailable>"]
    out = []
    for i, line in enumerate(src, 1):
        if CALL.search(line) or re.search(r'\bSEC\s*\(|__section_entry', line):
            out.append(f"{i}: {line.strip()[:110]}")
    return out


def main():
    corpus_root, survey = sys.argv[1], sys.argv[2]
    n = int(sys.argv[3]) if len(sys.argv) > 3 else 10
    d = json.load(open(survey))
    progs = [p for p in d['programs'] if p['writes'] or p['reads']]
    pos = [p for p in progs if len(p['writes']) >= 2]
    neg = [p for p in progs if len(p['writes']) < 2 and p['writes']]
    rng = random.Random(20260909)
    sample = rng.sample(pos, min(n, len(pos))) + rng.sample(neg, min(n, len(neg)))
    for k, p in enumerate(sample):
        print(f"\n### [{k}] {p['repo']} :: {p['file']} :: {p['prog']} "
              f"(SEC {p['sec']})")
        print(f"    classifier: reads={p['reads']} writes={p['writes']} "
              f"=> label={'WRITE>=2' if len(p['writes']) >= 2 else 'WRITE<2'}")
        for line in evidence(corpus_root, p['repo'], p['file'], p['prog'])[:14]:
            print("      " + line)
    json.dump(sample, open('/tmp/corpus_sample.json', 'w'), indent=1)


if __name__ == '__main__':
    main()
