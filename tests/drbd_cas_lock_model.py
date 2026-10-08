#!/usr/bin/env python3
"""Exhaustive check of the two-host lock that guards the DRBD compare-and-swap
emulation (pal/linux/drbd.c), under DRBD's storage model.

THE STORAGE MODEL.  Each host has its own disk.  A register write is issued
by its owner, lands on each of the two disks at its own moment (protocol C
replicates it; nothing orders the local landing against the remote one), and
completes for its writer only once both disks hold it.  A host reads its OWN
disk.  Every register has exactly one writer, so no two writes to one sector
are ever in flight together: the lock waits for its own release to complete
before it raises again.

THE LOCK ("one-bit", Burns-Lamport for two):
  index 0 (priority):  [defer while the peer's want is set, bounded]
                       raise {1,0}; wait until peer.number == 0; CRIT;
                       release {0,0} (completes after the caller returns)
  index 1:             raise {1,w}; read peer; if peer.number == 0: CRIT
                       else lower {0,1}, wait until peer.number == 0, retry
                       with w = 1; release {0,0} (completes later)
`want` only delays index 0 (fairness); it never admits anyone.

Checked over every interleaving and every landing order:
  - mutual exclusion: never both in CRIT;
  - no deadlock: from every reachable state some host can still reach CRIT;
  - index 1 is not starved: once its want is on index 0's disk and index 0
    has not raised again, index 1 reaches CRIT before index 0 enters again,
    provided index 0's deferral is not cut short by its bound.
The bakery (MODEL=bakery) is checked by the same harness as a control.

Exit 0 when every property holds; 1 with a counterexample trace otherwise.
"""
import sys
from collections import deque

BROKEN = "--broken" in sys.argv
IDLE, WREL, DEFER, RAISE, RAISEW, CHECK, LOWER, LOWERW, BACKOFF, CRIT, RELEASE = range(11)
NAMES = "IDLE WREL DEFER RAISE RAISEW CHECK LOWER LOWERW BACKOFF CRIT RELEASE".split()


def onebit_steps(s, p):
    """Successors of host p's next action in state s (fairness=False lets the
    deferral bound fire)."""
    pc, w, disk, infl = s
    q = 1 - p
    out = []
    mine_landed = infl[p] is None
    peer = disk[p][q]  # host p reads its own disk: the peer's register there

    def put(npc=None, nw=None, ninfl=None):
        pcs = list(pc); ws = list(w); fl = list(infl)
        if npc is not None:
            pcs[p] = npc
        if nw is not None:
            ws[p] = nw
        if ninfl is not None:
            fl[p] = ninfl
        return (tuple(pcs), tuple(ws), disk, tuple(fl))

    cur = pc[p]
    if cur == IDLE:
        out.append(("start", put(WREL)))
    elif cur == WREL:                       # the last release must have completed
        if mine_landed:
            out.append(("rel-done", put(DEFER if p == 0 else RAISE, nw=0)))
    elif cur == DEFER:                      # index 0 only
        if peer[1] == 1:
            out.append(("defer", put(DEFER)))
            out.append(("defer-bound", put(RAISE)))
        else:
            out.append(("no-defer", put(RAISE)))
    elif cur == RAISE:
        val = (1, 0) if p == 0 else (1, w[p])
        # --broken: read the peer before the raise has completed (negative
        # control: the checker must find the violation)
        out.append(("raise", put(CHECK if BROKEN else RAISEW, ninfl=(val, False, False))))
    elif cur == RAISEW:
        if mine_landed:
            out.append(("raised", put(CHECK)))
    elif cur == CHECK:
        if peer[0] == 0:
            out.append(("enter", put(CRIT)))
        elif p == 0:
            out.append(("wait", put(CHECK)))
        else:
            out.append(("lose", put(LOWER)))
    elif cur == LOWER:
        out.append(("lower", put(LOWERW, ninfl=((0, 1), False, False))))
    elif cur == LOWERW:
        if mine_landed:
            out.append(("lowered", put(BACKOFF)))
    elif cur == BACKOFF:
        if peer[0] == 0:
            out.append(("retry", put(RAISE, nw=1)))
        else:
            out.append(("backoff", put(BACKOFF)))
    elif cur == CRIT:
        out.append(("exit", put(RELEASE)))
    elif cur == RELEASE:
        out.append(("release", put(IDLE, ninfl=((0, 0), False, False))))
    return out


def bakery_steps(s, p):
    """Lamport's bakery for two, register = (choosing, number).  Control."""
    pc, w, disk, infl = s
    q = 1 - p
    out = []
    mine_landed = infl[p] is None
    peer = disk[p][q]

    def put(npc=None, nw=None, ninfl=None):
        pcs = list(pc); ws = list(w); fl = list(infl)
        if npc is not None:
            pcs[p] = npc
        if nw is not None:
            ws[p] = nw
        if ninfl is not None:
            fl[p] = ninfl
        return (tuple(pcs), tuple(ws), disk, tuple(fl))

    cur = pc[p]
    # reuse the names: RAISE = choosing=1, RAISEW its wait, LOWER = read the
    # peer's number and publish ours, LOWERW its wait, CHECK = wait loop
    if cur == IDLE:
        out.append(("start", put(WREL)))
    elif cur == WREL:
        if mine_landed:
            out.append(("rel-done", put(RAISE)))
    elif cur == RAISE:
        out.append(("choosing", put(RAISEW, ninfl=((1, 0), False, False))))
    elif cur == RAISEW:
        if mine_landed:
            out.append(("chosen", put(LOWER)))
    elif cur == LOWER:
        mine = peer[1] + 1
        if mine > 4:
            # the real swap refuses a ticket past its bound (-EOVERFLOW) and
            # releases without entering; clipping it instead makes two tickets
            # tie at the cap
            out.append(("overflow", put(RELEASE)))
        else:
            out.append(("ticket", put(LOWERW, nw=mine, ninfl=((0, mine), False, False))))
    elif cur == LOWERW:
        if mine_landed:
            out.append(("published", put(CHECK)))
    elif cur == CHECK:
        pch, pnum = peer
        if not pch and (pnum == 0 or w[p] < pnum or (w[p] == pnum and p == 0)):
            out.append(("enter", put(CRIT)))
        else:
            out.append(("wait", put(CHECK)))
    elif cur == CRIT:
        out.append(("exit", put(RELEASE)))
    elif cur == RELEASE:
        out.append(("release", put(IDLE, ninfl=((0, 0), False, False))))
    return out


def landings(s):
    pc, w, disk, infl = s
    out = []
    for p in (0, 1):
        if infl[p] is None:
            continue
        val, l0, l1 = infl[p]
        for d, landed in ((0, l0), (1, l1)):
            if landed:
                continue
            nd = [list(disk[0]), list(disk[1])]
            nd[d][p] = val
            nl0, nl1 = (True, l1) if d == 0 else (l0, True)
            fl = list(infl)
            fl[p] = None if (nl0 and nl1) else (val, nl0, nl1)
            out.append((f"land{p}->disk{d}", (pc, w, (tuple(nd[0]), tuple(nd[1])), tuple(fl))))
    return out


def successors(s, steps):
    out = []
    for p in (0, 1):
        for name, t in steps(s, p):
            out.append((p, name, t))
    for name, t in landings(s):
        out.append((None, name, t))
    return out


def main():
    model = "bakery" if "--bakery" in sys.argv else "onebit"
    steps = bakery_steps if model == "bakery" else onebit_steps
    zero = ((0, 0), (0, 0))
    init = ((IDLE, IDLE), (0, 0), (zero, zero), (None, None))
    seen = {init: None}
    edges = {}
    dq = deque([init])
    bad = None
    while dq:
        s = dq.popleft()
        if s[0][0] == CRIT and s[0][1] == CRIT:
            bad = s
            break
        succ = successors(s, steps)
        edges[s] = succ
        for p, name, t in succ:
            if t not in seen:
                seen[t] = (s, p, name)
                dq.append(t)
    if bad:
        trace = []
        cur = bad
        while seen[cur] is not None:
            prev, p, name = seen[cur]
            trace.append(f"  host{p if p is not None else '-'} {name}")
            cur = prev
        print(f"{model}: MUTUAL EXCLUSION VIOLATED after {len(trace)} steps:")
        print("\n".join(reversed(trace)))
        return 1

    def can_reach(pred, allowed=lambda p, name, t: True):
        # states from which a state satisfying pred is reachable using only
        # allowed edges (backward fixpoint)
        rev = {}
        for s, succ in edges.items():
            for p, name, t in succ:
                if allowed(p, name, t):
                    rev.setdefault(t, []).append(s)
        good = {s for s in seen if pred(s)}
        dq2 = deque(good)
        while dq2:
            t = dq2.popleft()
            for s in rev.get(t, ()):
                if s not in good:
                    good.add(s)
                    dq2.append(s)
        return good

    live = can_reach(lambda s: CRIT in s[0])
    dead = [s for s in seen if s not in live]
    if dead:
        s = dead[0]
        print(f"{model}: DEADLOCK reachable, e.g. pcs={[NAMES[x] for x in s[0]]} disk={s[2]} inflight={s[3]}")
        return 1

    trying1 = {RAISE, RAISEW, CHECK, LOWER, LOWERW, BACKOFF}
    # host 1 reaches CRIT without host 0 entering, and with host 0's deferral
    # bound never cutting a deferral short (the bound exists only for a peer
    # that died with want set)
    reach1 = can_reach(lambda s: s[0][1] == CRIT,
                       lambda p, name, t: not (p == 0 and name in ("enter", "defer-bound")))
    # Starting points: host 1 lost a race (its want is on host 0's disk) and
    # host 0 has not yet raised again.  host 0 may enter once more if it had
    # already raised; this asks about every later entry.
    starved = [s for s in seen if s[0][1] in trying1 and s[2][0][1][1] == 1
               and s[0][0] in (IDLE, WREL, DEFER) and s not in reach1]
    if starved and model == "onebit":
        s = starved[0]
        print(f"{model}: host 1 can be STARVED, e.g. pcs={[NAMES[x] for x in s[0]]} disk={s[2]} inflight={s[3]}")
        return 1
    print(f"{model}: {len(seen)} states; mutual exclusion holds, no deadlock"
          + ("; host 1 always reaches CRIT before host 0 can enter again" if model == "onebit" else
             f"; host 1 starvable from {len(starved)} states without host 0 entering (FIFO by ticket instead)"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
