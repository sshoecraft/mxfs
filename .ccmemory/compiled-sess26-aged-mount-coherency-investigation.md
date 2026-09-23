---
name: compiled-sess26-aged-mount-coherency-investigation
description: sess26 aged-mount coherency campaign: repro recipe, a self-inflicted demoter regression, and 5 measurement traps that produced false verdicts first
metadata:
  type: project
tags: [compiled, coherency, aged-mount, dlm, measurement-methodology, sess26]
---

## Topic

sess26's investigation of the aged-mount coherency failure
(D-MOUNT-DEGRADES-WITH-USE / D-DIRENT-INODE-TYPE-MISMATCH, v0.11.222-225) and the
chain of measurement-integrity traps that investigation walked into before any
of its instruments could be trusted.

## The defect and its repro

state.md's open item said heavy tests needed re-running after a storm on the
current build but gave no recipe. [[aged-mount-coherency-repro-recipe]]
supplied one: on ONE mount, without re-prepping, run ~12x `dirent_durability`
@32/caw plus 2-3 full correctness boards, then `cache_coherency` +
`strong_consistency`. Result: aged mount FAILs `cache_coherency` 0/32
(`checks=654 passed=653 failed=1` on every node, identically) and
`strong_consistency` 17/32; a fresh prep of the *same build* minutes later
PASSes both cleanly. Single-node runs on the aged mount pass 530/530 — the
failure needs 32-way concurrency. Ruled out as causes: the sess26 demoter
change (`foreign_clear=0`, `contest=0` throughout) and a timeout/straggler
artifact (run completed inside budget, one check fails identically
cluster-wide). Not yet identified by session end: which of the 654 checks
fails — next step was to capture the failing check's text on an aged mount
and compare against the `rename_visibility` signature sess22 tied to
D-DIRENT-INODE-TYPE-MISMATCH.

## A self-inflicted regression found along the way

Generalizing the foreign-drain-defer predicate in `mxfs_foreign_demoter()`
from its original one-slot form to a two-slot form dropped the self-exemption
check. [[demoter-predicate-self-exemption-invariant]]: the broken form
`(d1 && d1 != current) || (d2 && d2 != current)` defers to a foreign drain
even when `current` itself owns the other slot — a state measured 30-152
times per run, not an edge case. Cost: `cache_coherency` FAIL 0/32
(**timed out** at its 60s budget — presenting as `NO_TERMINAL_RECORD`, the
exact shape of a wedged-node false lead from sess24), `strong_consistency`
FAIL 25/32, `posix_multi` FAIL 1/32. Fix restores self-exemption first, then
falls through to the general two-slot check: `if (d1==current || d2==current)
return false; return d1 || d2;`. This regression is explicitly NOT the aged-
mount defect (see above) — a separate bug the same session's own change
introduced and fixed in-flight. Lesson: before blaming infrastructure for a
barrier criterion reading 0/32, check whether a predicate on the reload/defer
path changed.

## Measurement traps hit while chasing the repro

Three separate instruments this session produced a confident wrong verdict
before being validated against a known invariant.

1. **Genuine vs. artifact `dirent_durability` loss** —
   [[dirent-durability-failure-mode-discriminator]]. `durable_loss=8` appears
   in both a real loss and a straggler-timeout artifact; the discriminators
   are `late_ok` (nonzero in a healthy run; 0 means reconciliation never got
   to run) and the wall (~116-124s genuine vs 240s/240s cutoff artifact).
   Cause of the artifact: residual cluster state from a harness run an outer
   `timeout` had killed mid-iteration — rule is `MXFS_FORCE_PREP=1
   ./run.sh N caw prep_cluster` after killing any harness mid-run.

2. **Loser-vs-peers differential, invalidated by rank1 role** —
   [[differential-invalid-when-loser-is-rank1]]. The same differential
   technique that correctly found the P6-MIDTENURE lead for
   D-SILENT-MKDIR-LOSS (ordinary-peer loser) produced a false lead
   (AG-wait/inactivation-defer backlog) when the loser was rank1: its
   coordinator role alone produces x20-x158 departures from peer median on
   perfectly healthy runs. Rank1-failing must be compared against
   rank1-passing (same node, same role, different run), never against peers.

3. **Probe counts are per-module-load and capped** —
   [[probe-counts-are-per-module-load-and-capped]]. Retrying the
   rank1-vs-rank1 method above by diffing a late-in-mount-life failing run
   against a just-after-prep passing run produced rows that were pure cap
   saturation (`P170-CLWR` 800 vs 0 — 800 is its documented cap), not
   behavior. Comparing probe counts across runs is valid only when both runs
   sit at the same ordinal position after a fresh module load; comparing
   node-vs-node *within one run* is always valid.

4. **Kernel log source choice, corrected mid-session** —
   [[kernel-log-retention-varies-per-node-pick-best-source]]. An earlier
   sess26 claim ("dmesg retains ~112s, journalctl -k retains ~50min, always
   use journalctl") was itself wrong: retention varies up to ~60x, in *either*
   direction, per node, because both are size-capped rings and nodes log at
   wildly different rates. Fix: per node, pick whichever source still holds
   the most lines after the last window marker, and report which
   (`win_src=`). Never concatenate both sources to scope a window, and never
   derive different views (scoped text vs. token counts) from separately
   re-queried sources — capture once, count locally.

5. **Global refcount balance for the unmount inode leak, disproven** —
   [[unmount-leak-global-refcount-balance-cannot-work]]. A per-inode
   grab/release balance (`P205-REFBAL`) was built to attribute an unmount
   inode leak; two instrumented rounds still left `net=78` unexplained
   against `icount=1`, because VFS-side references (`dput`->`iput`, `evict`,
   `d_splice_alias`'s error-path `iput`) move the count without passing any
   MXFS-owned chokepoint. Conclusion: no count-based scheme confined to the
   filesystem can attribute one surviving reference — Linux gives no reverse
   map from refcount to holder. Not a calibration gap, unsound in principle;
   do not rebuild it. What the captures did establish, usable for a targeted
   follow-up: three leaked inodes were all directories, `icount=1`,
   `dentries=0`, attribution converging twice independently (via
   `iget_caller` and `P203-LEVEL[1]`) on `xfs_lookup`'s hand-off. Proposed
   narrower experiment: count `xfs_lookup` reference hand-offs vs. dentry
   count at unmount (`lookup_handoffs > 0 && dentries == 0 && icount == 1`),
   accounting for `d_splice_alias`'s legitimate no-dentry `iput` path.

## Generalized lesson

Sanity-check every new counter/differential against a known invariant
*before* reading a verdict off it. Here the tells were, respectively: a
completed run inside budget with identical cluster-wide failure (not a
straggler), `net == icount` failing by 77 on the first capture (balance is
unsound), round numbers landing exactly on documented caps (saturation, not
signal), and a role (rank1) correlating with the measured departure at least
as strongly as the failure did.
