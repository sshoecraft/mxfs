---
name: ccloop-c7ee71c6-sess29-measurement-traps-that-nearly-convicted-the-wrong-path
description: Four measurement traps from sess29: dmesg-ring retention faked a zero, an unscoped census made both A/B arms identical, cumulative counters, ambiguou…
metadata:
  type: project
tags: [mxfs, method, rule4, sess29, measurement]
---

# sess29 — four traps, each of which produced a confidently wrong reading

## 1. A dmesg ZERO can be a retention artifact, not an absence

sess28 attributed the stranded demoter claim to the P152 trans-free punt. I
"refuted" that in minutes: `dmesg | grep -c P152` on test23 — the node with all
224 bails — returned **0**, while three nodes that DID punt had 0-1 bails.

That refutation was wrong. The P152 line had aged out of the ring while the
recent bail flood survived; state.md already records that **log retention varies
~60x per node**. The punt was the cause all along, later proven directly by a
`punt=0x1` bit carried in the inode.

**Rule: never treat `grep -c` == 0 on a ring buffer as evidence of absence.**
Carry the fact in state (a flag on the object) and print it at the point of
damage, or scope to a marker and confirm the window is intact.

## 2. An UNSCOPED census makes both A/B arms identical

My first census read the whole dmesg ring. Control and fix arms both reported
`bail=25 strand=1 punt=5` — byte-identical — because the ring still held the
control arm's lines. It looked like the fix did nothing.

`tests/demoter_strand_census.sh <n> mark` now stamps `MXFS_DEMOTER_WINDOW` and
the census counts only what follows the last marker.

## 3. Module-param counters are CUMULATIVE since module load

`P215-DEFER` / `P216-CLAIM-RECYCLE` come from atomics, not the log, so they do
not respect the dmesg window at all. Comparing them across arms needs a **fresh
prep per arm** (module reload zeroes them). The windowed dmesg counts and the
cumulative atomic counters must not be read the same way.

## 4. A probe that prints ONE slot of a TWO-slot predicate is ambiguous

`mxfs_foreign_demoter()` is true if EITHER demoter slot is set, but
`P34J-RELOAD-DEMOTE-BAIL` printed only slot 1's `pid/comm/line` — and those
stamps SURVIVE that claim being cleared. Slot 2 had no stamps at all. So a
strand in slot 2 reported slot 1's stale site and a pid that had nothing to do
with it. Fixed by stamping slot 2 identically and printing `held=` for both.

**Rule: a probe for an OR-predicate must name which disjunct is true.**

## 5. Wrapper timeouts must be the honest sum of their stages

`tests/demoter_punt_ab.sh` at a 400 s cap was killed mid-run; its stages sum to
~480 s (exposure 176 s + 3 runs + census). The kill left `run.sh` children
holding `/tmp/mxfs_run.lock`, which then blocked every later prep with "another
run.sh holds the lock". `timeout` kills the wrapper, not the process group —
clear the holders with `fuser -v /tmp/mxfs_run.lock` and `kill -9`.

## GPT (RULE 5) review points worth keeping

- **An age-based foreign clear cannot prove abandonment.** `xfs_iunlock` does
  `up_write(&ip->i_lock)` BEFORE `mxfs_dlm_ilock_end`, so a live retaining task
  is briefly indistinguishable from an abandoned claim; nothing bounds that
  window (preemption, host descheduling). Grace raised 200 ms → 5000 ms and
  demoted to a pure safety net; the owner-driven clear is the mechanism.
- **A bit cannot represent a nesting count** — hence `i_dlm_punt_n[2]`.
- `xfs_ilock_demote` ends ILOCK-EXCL via `downgrade_write` WITHOUT going through
  `xfs_iunlock`'s EXCL path; the later shared unlock still reaches
  `mxfs_dlm_ilock_end`, so the owner-clear still fires, but any future work on
  `i_lock` lifetimes must audit every `down/up/downgrade` site.
- Comparing reference-less `task_struct *` values is UAF-safe but **not
  ABA-safe** — a recycled `task_struct` address can false-match. The suggested
  end state is a tokenized drain context with a held task reference and explicit
  handoff, replacing the two-slot design.
