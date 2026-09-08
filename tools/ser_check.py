#!/usr/bin/env python3
"""ser_check.py — offline conflict-serializability check for bin/ktxser.

Every transaction in the history is a read-modify-write of one key in each
of two maps, and every write value is globally unique.  That makes the
history self-describing:

  * the transaction that wrote the value T read on key k is T's unique
    predecessor on k (reads-from), so following predecessors from the
    initial token reconstructs the *total order* of writes on k;
  * two transactions reading the same version of k and both committing a
    write to k make that reconstruction fork — a lost update;
  * a transaction reading a value no transaction ever wrote is an orphan
    (a read of state that was never committed);
  * a cycle in the union of the per-key orders is a non-serializable
    interleaving across keys.

A history is conflict-serializable iff every per-key order is a simple
path covering all of that key's writers and the union graph is acyclic.
We additionally check the final map contents against the end of each
chain.  Exit status 0 = serializable, 1 = violation found.
"""
import json
import sys
from collections import defaultdict


def check(path):
    d = json.load(open(path))
    init = d["meta"]["init_token"]
    hist = d["history"]
    # rec = [seq, ka, kb, ra, rb, wa, wb]
    writers = defaultdict(dict)     # (map,key) -> {write_value: txid}
    reads = defaultdict(list)       # (map,key) -> [(read_value, txid)]
    for i, r in enumerate(hist):
        _seq, ka, kb, ra, rb, wa, wb = r
        for mp, k, rv, wv in (("a", ka, ra, wa), ("b", kb, rb, wb)):
            if wv in writers[(mp, k)]:
                return dict(verdict="DUPLICATE_WRITE_TOKEN", detail=(mp, k, wv))
            writers[(mp, k)][wv] = i
            reads[(mp, k)].append((rv, i))

    forks, orphans, edges = [], [], set()
    chain_len = {}
    for cell, rd in reads.items():
        by_read = defaultdict(list)
        for rv, tx in rd:
            by_read[rv].append(tx)
        for rv, txs in by_read.items():
            if len(txs) > 1:
                forks.append(dict(cell=list(cell), read_value=rv, txs=txs[:8],
                                  n=len(txs)))
            if rv != init and rv not in writers[cell]:
                orphans.append(dict(cell=list(cell), read_value=rv, tx=txs[0]))
        # walk the chain from the initial token
        seen, cur, n = set(), init, 0
        while True:
            nxt = by_read.get(cur)
            if not nxt:
                break
            tx = nxt[0]
            if tx in seen:
                break
            seen.add(tx)
            if n > 0 or True:
                pass
            prev_tx = writers[cell].get(cur)
            if prev_tx is not None:
                edges.add((prev_tx, tx))
            cur = hist[tx][5] if cell[0] == "a" else hist[tx][6]
            n += 1
        chain_len[cell] = (n, len(writers[cell]))

    uncovered = {str(list(c)): v for c, v in chain_len.items() if v[0] != v[1]}

    # cycle detection over the union of per-key orders (Kahn)
    indeg = defaultdict(int)
    adj = defaultdict(list)
    nodes = set()
    for u, v in edges:
        adj[u].append(v)
        indeg[v] += 1
        nodes.add(u)
        nodes.add(v)
    q = [n for n in nodes if indeg[n] == 0]
    seen = 0
    while q:
        u = q.pop()
        seen += 1
        for v in adj[u]:
            indeg[v] -= 1
            if indeg[v] == 0:
                q.append(v)
    cyclic = seen != len(nodes)

    # final-state check: last write in each chain must be the stored value
    final_bad = []
    for mp, arr in (("a", d["final_a"]), ("b", d["final_b"])):
        for k, val in enumerate(arr):
            cell = (mp, k)
            if cell not in writers:
                if val != init:
                    final_bad.append(dict(cell=[mp, k], stored=val,
                                          expected=init))
                continue
            # end of chain = the write value with no successor
            succ = {rv for rv, _ in reads[cell]}
            ends = [w for w in writers[cell] if w not in succ]
            if val not in ends:
                final_bad.append(dict(cell=[mp, k], stored=val,
                                      chain_ends=ends[:4]))

    ok = (not forks and not orphans and not cyclic and not uncovered
          and not final_bad)
    return dict(
        verdict="SERIALIZABLE" if ok else "NOT_SERIALIZABLE",
        mode=d["meta"]["mode"], threads=d["meta"]["threads"],
        keys=d["meta"]["keys"], zipf_theta=d["meta"]["zipf_theta"],
        committed=d["committed"], conflict_aborts=d["conflict_aborts"],
        cells=len(writers),
        lost_updates=len(forks), lost_update_examples=forks[:3],
        orphan_reads=len(orphans), orphan_examples=orphans[:3],
        cyclic=cyclic, uncovered_chains=uncovered,
        final_state_mismatches=len(final_bad),
        final_state_examples=final_bad[:3])


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: ser_check.py HISTORY.json [HISTORY.json ...]")
        sys.exit(2)
    bad = 0
    results = []
    for p in sys.argv[1:]:
        r = check(p)
        r["file"] = p
        results.append(r)
        print(json.dumps(r, indent=1))
        if r["verdict"] != "SERIALIZABLE":
            bad += 1
    sys.exit(1 if bad else 0)
