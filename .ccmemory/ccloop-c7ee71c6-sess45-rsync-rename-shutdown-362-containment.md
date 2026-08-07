---
name: ccloop-c7ee71c6-sess45-rsync-rename-shutdown-362-containment
description: sess45 pt2: NEW critical rsync-rename dirty-cancel 17-node shutdown; GPT-ruled containment shipped 0.11.362 (P217 preflight -ESTALE + probes + stamp-…
metadata:
  type: project
tags: [ccloop, rsync-rename, containment, 0.11.362, session-state]
---

# sess45 part 2 — rsync-rename mass shutdown: found, ruled, contained; laps in progress

## The event (0.11.361, ~14:00Z)
During a same-invocation lap (zsl fairness membership scaling dlm_scaling
rsync_paired crash_consistency) at 32/caw: 17 of 32 nodes INDEPENDENTLY hit
`xfs_trans_cancel` DIRTY, Caller xfs_rename+0x48c → 0x8 shutdown → withdrawal,
all comm=rsync, within ~20s (per-node first-error lines identical; NOT a
cascade). 17 ≈ one side of every rsync pair +1. Intermittent: rsync_paired
green 3× earlier same day same build. faddr2line → xfs_inode.c out_trans_cancel
label. Pre-death context: P165-AFFINE-STALE storm on temp+final names,
P64-N1F1 present=0, P3L-DIRLOG-BIRTH same daddr ×3/60ms. P216-B (Option-B
gate) count on a dead node: ZERO — gate not directly implicated.

## Root family + the gap
Documented family (compiled-shortform-lostupdate-sess8-9):
`xfs_dir_removename -ENOENT mid-trans → dirty cancel → 0x8`. The shipped
pre-dirty revalidate (xfs_inode.c ~6146) guards SRC always, TARGET only for
RENAME_EXCHANGE. rsync's temp→existing-final rename = non-exchange
xfs_dir_replace path = UNGUARDED.

## GPT ruling (sess45, in ledger entry D-RSYNC-RENAME-DIRTY-CANCEL-MASS-
SHUTDOWN-361): priors (a) pre-existing stale-base family via target gap
65-80%, (b) sess45 reload stamp relocation as P32E-window amplifier 15-30%,
(c) brace fixes <10%. NO binary rollback; instrument failing helper + micro-
revert lever; containment = FULL target-expectation preflight (both
polarities), strictly pre-dirty, -ESTALE (do_renameat2 retry_estale re-walks
both names and RETRIES — user never sees the errno; vanished target degrades
to successful plain rename), src stays -ENOENT.

## Shipped 0.11.362 (41070DFD73787A93E05F8CF)
- P217-RENAME-TGT-PREFLIGHT: non-exchange full target check → -ESTALE,
  WARN_ON_ONCE(dirty) on abort path.
- P217-RENAME-DIRTYCANCEL at out_trans_cancel: errno + XFS_TRANS_DIRTY +
  names + pre/post src-dir cookie (iv/bytes/fmt/dgen/valid_epoch captured at
  preflight) — separates below-locks image swap from helper-order failure.
  (Fixed compile: whiteout var is du_wip.ip, not wip.)
- mxfs.reload_stamp_at_commit (default 0): restores pre-sess45 reload stamp
  TIMING (same values, commit point vs install-complete) — the amplifier A/B
  lever. In reload: b_stamped_early skips the install-point stamp.

## Lap protocol (task #3)
Lap = 32/caw zsl fairness membership scaling dlm_scaling rsync_paired
(~4.5-5min; ONE lap per tool call — two laps + sweep blew the 600s cap
twice). Arms: default vs reload_stamp_at_commit=1 (runtime 0644, echo to
/sys/module/mxfs/parameters/ on all nodes). Watch per lap: P217-RENAME-TGT-
PREFLIGHT>0 = family present + contained (no shutdown) = producer hunt next;
P217-RENAME-DIRTYCANCEL>0 = containment gap, read the cookie; P-WITHDRAW>0 =
shutdown recurred. Historical rate ~1 event/4 laps. Laps so far on 362:
2 clean (arm A), lap3 cut by outer timeout mid-flight (check leftovers/
PENDING marks before next lap).

## Session ledger state
37→38 defects (new critical opened). CLOSED today: P195 (FIXED+VERIFIED
0.11.361), UV-COUNT-MISS (DISPROVED, degraded-member reproduction). OPEN: 11
of 38. crash_consistency NOTERMINAL: run.sh now appends last_phase_census
(kill-time per-node dmesg CCph tail) to the reason on any NO_TERMINAL —
untested pending next natural occurrence; the two NOTERMINAL events today
had empty stdout tails (ssh buffering — that's why census reads kmsg).
Rig: 32/caw on 0.11.362 all mounted.
