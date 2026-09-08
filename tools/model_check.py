#!/usr/bin/env python3
"""model_check.py — exhaustive interleaving check of the KTx commit
protocol (and of the 2PL strawman, for contrast).

The empirical checker (tools/ser_check.py) validates histories the real
runtime actually produced.  This checks *all* of them for small
configurations: it enumerates every interleaving of a handful of
transactions over a few stripes and tests, at every terminal state,

  P1 (atomicity)      an aborted transaction changed no stripe;
  P2 (serializability) the committed transactions and the final state are
                       explained by some serial order of exactly those
                       transactions, with every committed transaction's
                       observed reads equal to that order's prefix;
  P3 (deadlock freedom) no reachable state has every unfinished
                       transaction blocked.

Stripe values are modelled as the sequence of transactions that have
written them, which makes P2 an exact view-equivalence test rather than a
sampled one.  The protocol steps mirror src/ktx/commit.c one-for-one:
snapshot reads, sorted lock acquisition, validation against the recorded
versions, an apply phase that cannot fail, then release with a version
bump; abort restores versions and touches nothing.
"""
import itertools
import json
import sys

RUNNING, COMMITTED, ABORTED = 0, 1, 2


class Spec:
    """One transaction: the stripes it reads and the stripes it writes."""
    def __init__(self, reads, writes):
        self.reads = tuple(reads)
        # KTx locks the write set in a global order (no cycles by
        # construction); the 2PL strawman locks in *program* order, which
        # is exactly where its cycles come from.
        self.writes = tuple(sorted(set(writes)))
        self.writes_program = tuple(dict.fromkeys(writes))


# ---------------------------------------------------------------- KTx model
def ktx_successors(specs, st, allow_spin_abort):
    """Yield successor states of `st` under the KTx protocol."""
    ver, val, txs = st
    out = []
    for i, (pc, rs, rv, pre, status) in enumerate(txs):
        if status != RUNNING:
            continue
        sp = specs[i]
        nr, nw = len(sp.reads), len(sp.writes)

        def with_tx(newtx, newver=None, newval=None):
            t = list(txs)
            t[i] = newtx
            return ((newver if newver is not None else ver),
                    (newval if newval is not None else val), tuple(t))

        if pc < nr:                                     # snapshot read
            s = sp.reads[pc]
            if ver[s] % 2 == 1:
                continue                                # spinning: blocked
            out.append(with_tx((pc + 1, rs + ((s, ver[s]),),
                                rv + (val[s],), pre, RUNNING)))
        elif pc < nr + nw:                              # lock phase
            j = pc - nr
            s = sp.writes[j]
            if ver[s] % 2 == 0:
                nv = list(ver)
                nv[s] += 1
                out.append(with_tx((pc + 1, rs, rv, pre + ((s, ver[s]),),
                                    RUNNING), newver=tuple(nv)))
            if allow_spin_abort:                        # bounded-spin giveup
                nv = list(ver)
                for (hs, hp) in pre:
                    nv[hs] = hp                         # restore held locks
                out.append(with_tx((pc, rs, rv, (), ABORTED),
                                   newver=tuple(nv)))
        elif pc == nr + nw:                             # validate
            held = dict(pre)
            ok = True
            for (s, v) in rs:
                if s in held:
                    ok = ok and (v == held[s])
                else:
                    ok = ok and (ver[s] % 2 == 0 and ver[s] == v)
            if ok:
                out.append(with_tx((pc + 1, rs, rv, pre, RUNNING)))
            else:
                nv = list(ver)
                for (hs, hp) in pre:
                    nv[hs] = hp
                out.append(with_tx((pc, rs, rv, (), ABORTED),
                                   newver=tuple(nv)))
        elif pc == nr + nw + 1 and allow_spin_abort:
            # Reserve phase: capacity exhaustion can fail a commit after
            # every write stripe is held and validation has passed.  The
            # protocol must still leave shared state untouched, so this
            # transition exists to be checked, not to be likely.
            nv = list(ver)
            for (hs, hp) in pre:
                nv[hs] = hp
            out.append(with_tx((pc, rs, rv, (), ABORTED), newver=tuple(nv)))
            out.append(with_tx((pc + 1, rs, rv, pre, RUNNING)))
        elif pc == nr + nw + 1:
            out.append(with_tx((pc + 1, rs, rv, pre, RUNNING)))
        else:                                           # apply + release
            nval = list(val)
            for s in sp.writes:
                nval[s] = nval[s] + (i,)
            nv = list(ver)
            for (hs, hp) in pre:
                nv[hs] = hp + 2
            out.append(with_tx((pc + 1, rs, rv, (), COMMITTED),
                               newver=tuple(nv), newval=tuple(nval)))
    return out


# ---------------------------------------------------------------- 2PL model
def twopl_successors(specs, st, allow_cancel):
    """Pessimistic strawman: locks in *program* order, effects applied
    immediately at each write step, no rollback of any kind."""
    ver, val, txs = st
    out = []
    for i, (pc, rs, rv, pre, status) in enumerate(txs):
        if status != RUNNING:
            continue
        sp = specs[i]
        steps = ([("r", s) for s in sp.reads] +
                 [("w", s) for s in sp.writes_program])

        def with_tx(newtx, newver=None, newval=None):
            t = list(txs)
            t[i] = newtx
            return ((newver if newver is not None else ver),
                    (newval if newval is not None else val), tuple(t))

        if pc < len(steps):
            kind, s = steps[pc]
            held = dict(pre)
            if s not in held:
                if ver[s] % 2 == 1:
                    if allow_cancel:                   # cancellation/fuel stop
                        nv = list(ver)
                        for (hs, hp) in pre:
                            nv[hs] = hp + 2            # release, do NOT undo
                        out.append(with_tx((pc, rs, rv, (), ABORTED),
                                           newver=tuple(nv)))
                    continue                            # otherwise blocked
                nv = list(ver)
                nv[s] += 1
                pre2 = pre + ((s, ver[s]),)
            else:
                nv = list(ver)
                pre2 = pre
            if kind == "r":
                out.append(with_tx((pc + 1, rs + ((s, ver[s]),),
                                    rv + (val[s],), pre2, RUNNING),
                                   newver=tuple(nv)))
            else:
                nval = list(val)
                nval[s] = nval[s] + (i,)               # immediate effect
                out.append(with_tx((pc + 1, rs, rv, pre2, RUNNING),
                                   newver=tuple(nv), newval=tuple(nval)))
        else:
            nv = list(ver)
            for (hs, hp) in pre:
                nv[hs] = hp + 2
            out.append(with_tx((pc + 1, rs, rv, (), COMMITTED),
                               newver=tuple(nv)))
    return out


# ------------------------------------------------------------- property P2
def serializable(specs, nstripes, txs, val, init):
    """Is the terminal state explained by some serial order of the
    committed transactions, matching every committed read?"""
    done = [i for i, t in enumerate(txs) if t[4] == COMMITTED]
    for order in itertools.permutations(done):
        state = list(init)
        ok = True
        for i in order:
            pc, rs, rv, pre, _ = txs[i]
            for pos, s in enumerate(specs[i].reads):
                if rv[pos] != state[s]:
                    ok = False
                    break
            if not ok:
                break
            for s in specs[i].writes:
                state[s] = state[s] + (i,)
        if ok and tuple(state) == tuple(val):
            return True, order
    return False, None


def explore(specs, nstripes, model, allow_escape):
    init_ver = tuple([0] * nstripes)
    init_val = tuple([() for _ in range(nstripes)])
    start = (init_ver, init_val,
             tuple((0, (), (), (), RUNNING) for _ in specs))
    seen = {start}
    stack = [start]
    terminals = 0
    deadlocks = 0
    p1 = p2 = 0
    succ = ktx_successors if model == "ktx" else twopl_successors
    torn_after_abort = 0
    while stack:
        st = stack.pop()
        nxt = succ(specs, st, allow_escape)
        if not nxt:
            terminals += 1
            ver, val, txs = st
            unfinished = [i for i, t in enumerate(txs) if t[4] == RUNNING]
            if unfinished:
                deadlocks += 1
                continue
            # P1: an aborted transaction wrote nothing
            for i, t in enumerate(txs):
                if t[4] == ABORTED and any(i in val[s] for s in range(nstripes)):
                    p1 += 1
                    torn_after_abort += 1
                    break
            ok, _ = serializable(specs, nstripes, txs, val, init_val)
            if not ok:
                p2 += 1
            continue
        for n in nxt:
            if n not in seen:
                seen.add(n)
                stack.append(n)
    return dict(states=len(seen), terminals=terminals,
                deadlock_states=deadlocks,
                atomicity_violations=p1, serializability_violations=p2,
                effects_after_abort=torn_after_abort)


CONFIGS = [
    ("2 tx, disjoint stripes",
     [Spec([0], [0]), Spec([1], [1])], 2),
    ("2 tx, same stripe (lost-update shape)",
     [Spec([0], [0]), Spec([0], [0])], 2),
    ("2 tx, crossed read/write (the cross-map shape)",
     [Spec([0, 1], [0, 1]), Spec([1, 0], [1, 0])], 2),
    ("2 tx, reader vs writer over a map pair",
     [Spec([0, 1], []), Spec([0, 1], [0, 1])], 2),
    ("3 tx over 2 stripes",
     [Spec([0], [0, 1]), Spec([1], [1]), Spec([0, 1], [0])], 2),
    ("3 tx over 3 stripes, overlapping",
     [Spec([0, 1], [0]), Spec([1, 2], [1]), Spec([2, 0], [2])], 3),
    ("3 tx, cross-map pair + observer (the E3 shape)",
     [Spec([0, 1], [0, 1]), Spec([1, 0], [1, 0]), Spec([0, 1], [])], 2),
    ("4 tx over 2 stripes",
     [Spec([0], [0, 1]), Spec([1], [1, 0]), Spec([0, 1], [0]),
      Spec([1, 0], [1])], 2),
]

if __name__ == "__main__":
    out = {"configs": []}
    bad = 0
    for name, specs, ns in CONFIGS:
        k = explore(specs, ns, "ktx", allow_escape=True)
        knoescape = explore(specs, ns, "ktx", allow_escape=False)
        t = explore(specs, ns, "2pl", allow_escape=True)
        tnoescape = explore(specs, ns, "2pl", allow_escape=False)
        rec = dict(config=name,
                   ktx=k, ktx_no_spin_abort=knoescape,
                   twopl=t, twopl_no_cancel=tnoescape)
        out["configs"].append(rec)
        if (k["atomicity_violations"] or k["serializability_violations"]
                or knoescape["deadlock_states"]
                or knoescape["atomicity_violations"]
                or knoescape["serializability_violations"]):
            bad += 1
        print(f"{name}")
        print(f"  KTx : {k['states']:>7} states, {k['terminals']:>6} terminal, "
              f"deadlock={knoescape['deadlock_states']}, "
              f"atomicity_viol={k['atomicity_violations']}, "
              f"serializability_viol={k['serializability_violations']}")
        print(f"  2PL : {t['states']:>7} states, {t['terminals']:>6} terminal, "
              f"deadlock={tnoescape['deadlock_states']}, "
              f"effects_after_abort={t['effects_after_abort']}, "
              f"serializability_viol={t['serializability_violations']}")
    out["verdict"] = "PASS" if bad == 0 else "FAIL"
    print("\nverdict:", out["verdict"])
    if len(sys.argv) > 1:
        json.dump(out, open(sys.argv[1], "w"), indent=1)
    sys.exit(0 if bad == 0 else 1)
