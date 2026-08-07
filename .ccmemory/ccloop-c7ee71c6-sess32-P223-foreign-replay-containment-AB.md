---
name: ccloop-c7ee71c6-sess32-P223-foreign-replay-containment-AB
description: 0.11.273 foreign-replay containment A/B via new tests/foreign_replay_ab.sh: live replay REAL (t+~105s), P223 skips 11 vs 0, both arms 40/40+40/40 ack…
metadata:
  type: project
---

# sess32 — foreign-replay containment shipped + A/B'd (0.11.273)

## What shipped (build DCE99A318A889A0EA172BAF)
- `mxfs.foreign_replay_untagged_apply` (default 0): live foreign-slice replay
  SKIPS buf/dquot/quotaoff/icreate image records (P223-FR-UNTAGGED-SKIP,
  capped notice) — they carry no authority token and their only gate was a
  cross-slice XFS_LSN_CMP, which is meaningless (per-node slices number LSNs
  independently). INODE records still replay (di_changecount gate is
  node-independent and correct). Gate at xfs/xfs_log_recover.c foreign block;
  knob defined in xfs_mxfs_dlm.c.
- `mxfs.stale_stage_unlanded_shutdown` (default 1): P222's unlanded arm now
  fails closed — P224-UNLANDED-STALE-FATAL (capped 100) + xfs_force_shutdown
  (SHUTDOWN_CORRUPT_INCORE) → lease loss → peer fence → journal recovery.
  GPT condition-1. Never observed (sskip_unlanded=0 ever). 0 = legacy
  count-and-skip for A/B/fault-injection.
- Ledger: D-FOREIGN-REPLAY-UNGATED-IMAGES recorded (critical, OPEN — stays
  open until the full token protocol lands).

## KEY DISCOVERY: no criterion drives live foreign replay
crash_consistency is guest-side only (header admits it needs host
orchestration for a true node-KILL) and fence_during_write leaves no dirty
slice. Measured 0.11.273: zero "foreign replay of dead slot" lines across
both criteria, all 32 nodes. The board was NEVER exercising this machinery.

## New harness: tests/foreign_replay_ab.sh <nodes> <victim 2..N> [apply]
Durable workload on victim (40 mkdir + 40 4K files + syncfs) → virsh destroy
→ poll survivors ≤180s for replay → harvest P223 + visibility from test1 →
virsh start victim (NOT re-prepped; caller runs prep_cluster). ~200s/arm +
prep between arms (victim ends unmounted; knob-verify aborts on a node
without the module).

## A/B result (same build, same workload shape, victims test9/test10)
| arm | P223 skips | replay | acked visibility from survivor |
|---|---|---|---|
| apply=0 containment | 11 | complete t+106s | dirs 40/40 files 40/40 sizes 40/40 |
| apply=1 legacy      | 0  | complete t+102s | dirs 40/40 files 40/40 sizes 40/40 |

Interpretation: replay pipeline REAL (62s disklock detect + election +
replay); containment physically active (11 records refused); on this shape
the refused records were REDUNDANT — the destage kick lands created/freed
metadata home within ~ms of commit, so acked dirents were already at home
when the node died. The containment residual (held-at-death UNLANDED dir
blocks) needs a kill inside the ms landing window or a victim with the
destage kick suppressed — narrow in practice. The corruption direction
(false-APPLY over survivor rewrites) needs survivor writes to the same
blocks between death and replay — the deferred purge blocks exactly that
for held resources, so legacy's danger is mainly RELEASED-tenure records
and the mount-time/rejoin path (still ungated — next step).

## Next (GPT order)
1. Mount-time adopted-slice image suppression (rejoin path: a returning or
   claiming node full-replays a dirty slice with upstream gates — ungated
   today; disklock init precedes xfs_mountfs so slice-already-replayed is
   knowable at recovery time).
2. D root fix: inodegc must reacquire publication authority before
   dirty/attach/stage (GPT design, see sess32 ruling memory).
3. B EX-side gate (separate knob, ISTALE excluded).
4. C full protocol: authority tokens in log records + durable held-set
   manifest + IMAGE_REPLAY_DONE marker.
