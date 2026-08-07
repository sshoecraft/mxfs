#!/usr/bin/env python3
"""Reconstruct a shared directory's cross-node publish ledger from a storm run.

Usage:  tests/sf_storm_ledger.py <run_dir> [round]

Given a tests/logs/sfstorm_* directory that captured a failure, this finds the
parent inode of the failing round(s) (recorded by the harness as pino=) and
prints every node's publish of that inode in PUBLISH ORDER, so the write that
dropped a peer's committed name is visible directly.

The ordering key is `vep=` — the dir's visibility epoch, which advances on each
cross-node EX handoff — with the in-file order as a tiebreak.  This is the same
reconstruction that named the fence_during_write clobber byte-exactly: the
publish whose name list SHRINKS relative to the previous one is the corruptor,
and its dgen/lgen tell you which staleness predicate let it through.
"""
import os
import re
import sys
from collections import defaultdict

DIRWRITE = re.compile(
    r"P56-DIRWRITE ino=(?P<ino>\d+) daddr=(?P<daddr>-?\d+) incore=(?P<incore>\d+) "
    r"mode=(?P<mode>-?\d+) logged=(?P<logged>\d+) relflush=(?P<rf>\d+) "
    r"dgen=(?P<dgen>\d+) lgen=(?P<lgen>\d+) vep=(?P<vep>\d+) sfc=(?P<sfc>\d+)"
    r"(?: nl=(?P<nl>\d+) sz=(?P<sz>\d+))?(?: held=(?P<held>-?\d+))? comm=(?P<comm>\S+)"
    r"(?: realns=(?P<realns>\d+))? write=\[(?P<names>[^\]]*)\]"
)
LOSS = re.compile(
    r"mxfs-SFSTORM-LOSS rank=(\d+) round=(\d+) pino=(\d+) nlink=(\d+) "
    r"visible=(\d+) expected=(\d+) missing=\[([^\]]*)\]"
)



def collect(run, pino, rnd, start, slot):
    """Every captured publish of `pino` inside round `rnd`'s time window."""
    lo = hi = None
    if start:
        lo = (start + (rnd - 1) * slot - 1) * 10**9
        hi = (start + (rnd + 2) * slot + 1) * 10**9
    pubs = []
    for name in sorted(os.listdir(run)):
        if not name.startswith("dmesg_test"):
            continue
        node = name[len("dmesg_"):-len(".log")]
        with open(os.path.join(run, name), errors="replace") as fh:
            for idx, line in enumerate(fh):
                m = DIRWRITE.search(line)
                if not m or int(m.group("ino")) != pino:
                    continue
                g = m.groupdict()
                ns = int(g["realns"]) if g["realns"] else 0
                if lo is not None and not (lo <= ns <= hi):
                    continue
                pubs.append({
                    "node": node, "idx": idx,
                    "dgen": int(g["dgen"]), "lgen": int(g["lgen"]),
                    "vep": int(g["vep"]), "relflush": int(g["rf"]),
                    "mode": int(g["mode"]), "comm": g["comm"],
                    "sfc": int(g["sfc"]),
                    "nl": int(g["nl"]) if g["nl"] else -1,
                    "sz": int(g["sz"]) if g["sz"] else -1,
                    "held": int(g["held"]) if g.get("held") else -9,
                    "realns": ns,
                    "names": g["names"].split(),
                })
    return pubs


def order(pubs):
    """True cross-node order when realns is present; else vep + file order."""
    if pubs and all(p["realns"] for p in pubs):
        pubs.sort(key=lambda p: p["realns"])
        return pubs[0]["realns"]
    pubs.sort(key=lambda p: (p["vep"], p["idx"]))
    return None


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    run = sys.argv[1]
    want_round = int(sys.argv[2]) if len(sys.argv) > 2 else None

    # Round timeline, so a publish can be attributed to the round that was
    # running when it happened.  Inode numbers are reused constantly, so
    # without this window an earlier test's writes to the same ino appear in
    # the ledger and every real publish looks like it "dropped" their names.
    meta = {}
    try:
        with open(os.path.join(run, "meta.txt")) as fh:
            for line in fh:
                k, _, v = line.strip().partition("=")
                meta[k] = v
    except OSError:
        pass
    start = int(meta.get("start", 0))
    slot = int(meta.get("slot", 2))

    losses = {}
    for name in sorted(os.listdir(run)):
        if not name.startswith(("dmesg_test", "storm_test")):
            continue
        with open(os.path.join(run, name), errors="replace") as fh:
            for line in fh:
                m = LOSS.search(line)
                if m:
                    rnd, pino, nlink, vis, exp, miss = (
                        int(m.group(2)), int(m.group(3)), int(m.group(4)),
                        int(m.group(5)), int(m.group(6)), m.group(7).split(),
                    )
                    losses.setdefault(rnd, (pino, nlink, vis, exp, miss))

    if not losses:
        print("no SFSTORM-LOSS markers found in", run)
        # fall back to the harness' textual verdicts
        for name in sorted(os.listdir(run)):
            if name.startswith("storm_test"):
                with open(os.path.join(run, name), errors="replace") as fh:
                    for line in fh:
                        if "FAIL" in line and "pino=" in line:
                            print("  ", name, line.strip())
                            break
        return

    # Summary mode: classify EVERY failing round by mechanism instead of
    # printing ledgers.  Counting failing ROUNDS is too noisy to A/B a fix
    # (same build, same params, alternating passes measured 3 and 8), but the
    # mechanism mix is a much more sensitive signal: it says WHICH vector a
    # change moved, not just whether the total drifted.
    if want_round == -1:
        tally = {"DROPPED-BY-PUBLISH": 0, "NEVER-PUBLISHED": 0,
                 "NO-PUBLISH-CAPTURED": 0}
        droppers = {}
        for rnd in sorted(losses):
            pino, nlink, vis, exp, miss = losses[rnd]
            pubs = collect(run, pino, rnd, start, slot)
            if not pubs:
                tally["NO-PUBLISH-CAPTURED"] += 1
                continue
            order(pubs)
            seen, first_drop = set(), None
            for p in pubs:
                cur = set(p["names"])
                if seen - cur and first_drop is None:
                    first_drop = p
                seen |= cur
            names_ever = set()
            for p in pubs:
                names_ever |= set(p["names"])
            never = [m for m in miss if m not in names_ever]
            if never:
                tally["NEVER-PUBLISHED"] += 1
            elif first_drop:
                tally["DROPPED-BY-PUBLISH"] += 1
                key = (f"mode={first_drop['mode']} rf={first_drop['relflush']} "
                       f"comm={first_drop['comm'].split('/')[0]}")
                droppers[key] = droppers.get(key, 0) + 1
            else:
                tally["NO-PUBLISH-CAPTURED"] += 1
        print(f"{run}: {len(losses)} failing rounds")
        for k, v in tally.items():
            print(f"  {k}: {v}")
        for k, v in sorted(droppers.items(), key=lambda kv: -kv[1]):
            print(f"    dropper {k}: {v}")
        return

    rounds = [want_round] if want_round else sorted(losses)
    for rnd in rounds:
        if rnd not in losses:
            print(f"round {rnd}: no loss recorded")
            continue
        pino, nlink, vis, exp, miss = losses[rnd]
        print(f"\n=== round {rnd}: parent ino={pino} nlink={nlink} "
              f"visible={vis} expected={exp} missing={miss} ===")

        lo = hi = None
        if start:
            # The round's creates happen in its own slot; its verification
            # happens two slots later.  Take a small margin either side.
            lo = (start + (rnd - 1) * slot - 1) * 10**9
            hi = (start + (rnd + 2) * slot + 1) * 10**9
            print(f"    window: +{(rnd - 1) * slot - 1}s .. +{(rnd + 2) * slot + 1}s "
                  f"from storm start")

        pubs = []
        for name in sorted(os.listdir(run)):
            if not name.startswith("dmesg_test"):
                continue
            node = name[len("dmesg_"):-len(".log")]
            with open(os.path.join(run, name), errors="replace") as fh:
                for idx, line in enumerate(fh):
                    m = DIRWRITE.search(line)
                    if m and int(m.group("ino")) == pino:
                        g = m.groupdict()
                        ns = int(g["realns"]) if g["realns"] else 0
                        if lo is not None and not (lo <= ns <= hi):
                            continue
                        pubs.append({
                            "node": node, "idx": idx,
                            "dgen": int(g["dgen"]), "lgen": int(g["lgen"]),
                            "vep": int(g["vep"]), "relflush": int(g["rf"]),
                            "mode": int(g["mode"]), "comm": g["comm"],
                            "sfc": int(g["sfc"]),
                            "nl": int(g["nl"]) if g["nl"] else -1,
                            "sz": int(g["sz"]) if g["sz"] else -1,
                            "held": int(g["held"]) if g.get("held") else -9,
                            "realns": int(g["realns"]) if g["realns"] else 0,
                            "names": g["names"].split(),
                        })
        if not pubs:
            print("  (no P56-DIRWRITE captured for this inode — dmesg ring may "
                  "have wrapped, or the dir never published in shortform)")
            continue

        # True cross-node order when realns is present (all nodes NTP-synced);
        # fall back to vep for builds that predate the stamp.
        if all(p["realns"] for p in pubs):
            pubs.sort(key=lambda p: p["realns"])
            t0 = pubs[0]["realns"]
        else:
            pubs.sort(key=lambda p: (p["vep"], p["idx"]))
            t0 = None
        seen = set()
        for p in pubs:
            cur = set(p["names"])
            dropped = sorted(seen - cur)
            seen |= cur
            flag = f"   <== DROPPED {' '.join(dropped)}" if dropped else ""
            when = f"+{(p['realns'] - t0) / 1e6:8.2f}ms" if t0 else f"vep={p['vep']:<4}"
            print(f"  {when} {p['node']:<8} vep={p['vep']:<3} dgen={p['dgen']:<3} "
                  f"lgen={p['lgen']:<3} mode={p['mode']} rf={p['relflush']} "
                  f"sfc={p['sfc']} nl={p['nl']:<3} sz={p['sz']:<4} held={p['held']:<2} "
                  f"comm={p['comm']:<14} n={len(cur):<3}{flag}")
        never = [m for m in miss if not any(m in p["names"] for p in pubs)]
        if never:
            print(f"  NEVER PUBLISHED by any node: {' '.join(never)}")

        # The corrupting publish is only half the story: the node published a
        # stale fork, so the interesting question is what its ACQUIRE did.
        # Dump that node's acquire-side decisions for this inode in the window
        # leading up to the write.
        first_drop = None
        seen2 = set()
        for p in pubs:
            cur = set(p["names"])
            if seen2 - cur:
                first_drop = p
                break
            seen2 |= cur
        if first_drop:
            print(f"\n  --- acquire-side trail on {first_drop['node']} "
                  f"(the first publish that dropped names) ---")
            tags = ("P63-HANDOFF", "P62-RELOAD-FORK-SHRINK", "P56-RELOAD-MERGE",
                    "P174-STALEGEN-ADOPT", "P-RELOAD-IDENTICAL", "P3-REFUSE",
                    "P178-REBASE", "P21-RB ", "P65-EPOCH-ADOPT", "P146-RELDUR",
                    "P51-REL", "P9-SFREFRESH", "P-SFDIR-REVERT", "P138-WAIT")
            path = os.path.join(run, f"dmesg_{first_drop['node']}.log")
            hits, pending = [], []
            try:
                with open(path, errors="replace") as fh:
                    for line in fh:
                        if f"ino={pino} " not in line and f"ino={pino}\n" not in line:
                            continue
                        if not any(t in line for t in tags):
                            continue
                        pending.append(line.rstrip()[:210])
                        if len(pending) > 25:
                            pending.pop(0)
                        if "P56-DIRWRITE" in line:
                            hits = list(pending)
            except OSError:
                pass
            for line in (hits or pending)[-18:]:
                print("   ", line)


if __name__ == "__main__":
    main()
