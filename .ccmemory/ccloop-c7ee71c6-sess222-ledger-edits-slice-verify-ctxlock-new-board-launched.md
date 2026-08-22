---
name: ccloop-c7ee71c6-sess222-ledger-edits-slice-verify-ctxlock-new-board-launched
description: sess222: ledger caught up — #20 fix+verify evidence recorded, #18 ILOCK-over-CAW-poll arm proven, NEW D-RECOVERY-CTXLOCK-HOLD-HB-STARVATION (high), 4…
metadata:
  type: project
---

# sess222 — ledger catch-up + first honest post-slice-fix board

## Ledger edits (all in tests/criteria/OPEN_DEFECTS.json, open now 32 / 20 critical)

1. **#20 D-LOG-SLICE-SHARED-MULTIWRITER**: recorded sess220 fix
   (identity slot→slice mapping via checked helper, mount + foreign-replay
   guards refusing slot >= log_node_count, mkfs -n error-not-clamp,
   32-slice rig via prep_fs.sh MXFS_LOG_SLICES=32) and sess221 load-kill
   verify PASS (slot 30 → "slice 30/32", P163-RECOVERY-COMPLETE, 0
   NOSLICE/replayerr fleet-wide). Owed for closure: full 32/caw board on
   0.11.479 + GPT-ruling extras (mixed-version gate, slot-reuse race,
   no-stale-clear-after-find_tail-fail).

2. **#18 D-NOINO-RELFENCE-AIL-FREEZE-474**: sess221 occurrence recorded —
   the "ILOCK held across CAW poll" arm is now PROVEN LIVE, single-node
   variant: rm in xfs_inactive_truncate held ILOCK blocked in
   caw_wait_for_grant on a victim-held AG0 grant; AIL froze on the item
   needing that ILOCK (P129-CLSKIP ILOCK_NOWAIT_FAIL); detector forced
   shutdown (xfs_mxfs_dlm.c:19526) 17s before purge would have freed the
   grant. Second facet ledgered: wedge detector cannot distinguish
   unbounded wedge from bounded in-flight-recovery wait — must become
   recovery-aware (or a2 removes the blocking wait).

3. **NEW D-RECOVERY-CTXLOCK-HOLD-HB-STARVATION (high)**: recovery owner
   holds disklock ctx->lock ~35s across recovery stage 3→5 (P-HB-SLOW
   slot=0 write_ms=0 lockwait_ms=34978, unblocked same ms as
   P163-RECOVERY-COMPLETE) — >half the 62s lease; withdraw stamp delayed
   16s. If purge ever exceeds lease → recovery owner self-fences mid
   recovery → owner cascade. Suspects: mxfs_disklock_purge_node
   (disklock.c ~2029, 65536-slot FUA scan), recovery_complete
   (v5_mount.c ~3449). Precedent fix: sess38 read_all disklock.c:2332
   (drop lock across I/O).

4. **474 arm B fold-in (sess215-218)**: b2+b3 landed 0.11.478 + board
   27/27 + single-victim and no-load multi-victim verified (sess215);
   under-load multi-victim CASCADE repro on .478 via unreplayable slot-30
   slice (sess216, kretprobe-proven -EIO at xfs_log_recover.c:1091
   sess217) — root-caused to shared slices (#20, fixed). REMAINING holes
   recorded: (i) unreplayable slice = infinite retry, no
   classification/escalation; (ii) b2 gate is COARSE — one stuck slot
   gates ALL victims' sweeps/purges fleet-wide (should be per-slot);
   (iii) hole (c) c1+c2 not landed.

## In flight
Full board ./run.sh 32 caw on 0.11.479 (sv 977E252C3ABEF4192431F53),
launched ~21:05Z as background task. First honest crash_consistency
board post-slice-fix (all prior 32/caw crash_consistency PASSes replayed
8-writer soup slices). Prep restarted test28 fine, 32/32 VMs up.

## Trap noted
`./run.sh ... | tail -80` in background buffers ALL output until EOF —
interim output file stays empty. Monitor via criteria.json mtime /
virsh instead, or don't pipe through tail next time.
