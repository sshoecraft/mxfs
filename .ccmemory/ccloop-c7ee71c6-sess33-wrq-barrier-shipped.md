---
name: ccloop-c7ee71c6-sess33-wrq-barrier-shipped
description: 0.11.286 writer-quiescence barrier (i_mxfs_ilk_wr_held census) shipped default-ON, GPT-reviewed; 6-lap green, deferred=0, exposure caveat 1/1
metadata:
  type: project
---

# sess33 — writer-quiescence admission barrier shipped (0.11.286)

## What shipped
`atomic_t i_mxfs_ilk_wr_held` (xfs_inode.h, next to rd_held): outstanding
ILOCK_EXCL census. inc open-coded post-acquisition in `xfs_ilock` +
`xfs_ilock_nowait` tails ONLY — **never inside mxfs_ilk_note_lock**: the 3
raw forensic callers (reload path 21852/24071/24517) release via raw
up_write that bypasses note_unlock; counting them leaks the census up and
permanently disables the barrier (found in pre-implementation audit).
dec in `mxfs_ilk_note_unlock` EXCL branch (callers: xfs_iunlock,
mxfs_iunlock_rwsems_raw — both release xfs_ilock-taken locks).
xfs_ilock_demote ILOCK_EXCL: dec wr + inc rd AFTER downgrade (overshoot =
safe direction). WARN_ON_ONCE underflow + !=1 on inc. Init at the 30154
DLM-field block. `mxfs_relbar_close_or_defer`: conditional census-0 wait
before EACH durable pass, ONE shared 40-iteration (~40ms) budget
(GPT refinement), atomic_read_acquire; wrq_ok/wrq_tmo counters in P220 dump.
Knob `mxfs.relbar_wrq` (1 default; 0 = legacy .283 trylock arm).

## Why sound (GPT-reviewed, approved with prerequisites — all satisfied)
- pend++ (xfs_trans_log_inode) requires local ILOCK_EXCL; CIL insert
  completes before the holder's dec (program order) → census 0 ⇒ log_force
  captures every FINISHED mutator, including DLM-uncounted classes
  (other-resource admissions, PR-admitted timestamp updates) that P15
  ex_holders==0 cannot see — that's why the count lives at the rwsem level.
- Ledger snapshot protocol verified: flush_seq=pend@iflush-copyin
  (xfs_inode.c:7289), durable=flush_seq at confirmed home iodone
  (xfs_inode_item.c:1107, comment documents the not-up-to-pending rule);
  23231 is the documented reload-adopt reconcile (P177).
- Census 0 = observation not stable state (queued writers uninc'd);
  defer/requeue backstop unchanged. Raw-site audit: all real raw write ops
  are reload take/release pairs, uncounted both sides.

## Validation (all on 286, one module load, ~7200 unlocks/node = ~232k fleet)
Full 11-criterion board + 2 extra aged-mount rotations ALL PASS healthy:
dd 64-66s ×3, dir_reuse 110-112s ×3, cache 22-28s ×3, strong 5s, posix 8s,
mmap 5s, membership 5s, fairness 17s, zsl 30s, fence 21s, crash 71s.
WARN=0 (8 nodes sampled). obligation=0 at every unlock. **deferred=0 whole
batch** vs 6-119 on .276-283; epoch_obligation 30→93-115/node (mid-tenure
opens continue, all close by unlock). Enforce engaged ONCE: wrq_ok=1 →
closed in place. EXPOSURE CAVEAT: the intermittent unlock-time-open regime
(10-41/lap in sess32) did not recur in 6 laps → convergence win is 1/1;
legacy-arm control lap under zero engagement is byte-identical by
construction (helper early-returns pend==durable) — skipped, reasoning
recorded. Watch wrq_tmo/deferred on future boards; a defer-regime lap will
settle N/N.

## Also this session
0.11.285's pending dd validation cleared: PASS 65s 32/32 on quiet-enough
host (load ~10.5/56 cores; the sess32 FAIL was at 348%-CPU game load 16-23).
EX-refusal stays.
