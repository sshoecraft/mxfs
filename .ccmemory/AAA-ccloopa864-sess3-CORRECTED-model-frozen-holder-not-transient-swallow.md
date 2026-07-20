---
name: AAA-ccloopa864-sess3-CORRECTED-model-frozen-holder-not-transient-swallow
description: sess3 CORRECTION: dir_reuse@32/caw P72-SWALLOW (DEMOTING+mode=NL) is MOSTLY the NORMAL deferred-release window (ilock_end→defer to xfs_trans_free), N…
metadata:
  type: project
---

# sess3 CORRECTION — the "stuck DEMOTING orphan" model was mostly WRONG

## What I got wrong (RULE 4 self-correction)
- P72-SWALLOW-DEAD (state=DEMOTING mode=NL work_busy=0) fires 7k-57k times but is **mostly the NORMAL deferred-release window**: mxfs_dlm_ilock_end (xfs_mxfs_dlm.c:~21083) sets state=DEMOTING then defers bast_process to xfs_trans_free (mxfs_inode_dlm_defer_bast); work_busy==0 until the trans commits and mxfs_trans_drain_inode_unlocks runs bast_process. A BAST arriving in that window swallows via P72 — TRANSIENT, self-resolves. NOT a stuck orphan.
- My scan_mine=1 forensic captures (r2) were these transient holder-in-DEMOTING windows (they resolved; test progressed to r18).
- FIX v1 (83F6743A, demoter==NULL gate) never fired (demoter set). FIX v2 (054C3372, 16-strike demoter override) FIRED but on transient/phantom-DEMOTING waiters (mine=0, hex_or=peer bit) → force-clear + reset-to-NONE + stale=true ABORTED legitimate deferred releases → **LIVELOCK: 57593 swallows (7x baseline), wedged r4 (REGRESSION vs baseline r18)**. → `mxfs_caw_orphan_reclaim` param now **DEFAULT 0**.

## The REAL wedge (frozen holder) — matches resume P-ACQ-STUCK
Baseline (forensic build 72B8FF8C, force-clear off) wedges ~r18 default modargs, FAIL nodes_pass=0/32. ~31 nodes stuck in transient DEMOTING while ONE node is the FROZEN holder: holds ino131 EX on disk (hex 0x4000000 = slot26 recurred in FIX2 logs), incore NONE/NL, "gen advancing" (peers CAS the slot) but its bit NEVER clears. Since incore=NONE/NL + held_raw=EX, bast_notify → NONE/NL path → P135-ORPHAN-RELEASE fires (inode_held==1) → queues bast_process → bast_process's unlock CAS (mxfs_dlm_caw_unlock_gen) tries to clear but **the release CAS is starved by the 31-peer acquire CAS storm on the same slot LBA (constant miscompare)** → release fails, bit persists, loop → wedge. (HYPOTHESIS — being instrumented.)

## DIAGNOSTIC RUN (build 8DE9D5F3, v0.10.49, RUNNING as DIAG)
- Force-clear OFF (param 0) → baseline, should wedge ~r18.
- Forensic reworked: full-chain scan + log ONLY when held_raw>=EX (the actual holder) — so the FROZEN holder is captured THROUGHOUT the wedge (cap 8000, was 200 exhausted at r2). Non-holders sampled first 400 only.
- Watcher tests/drc_orphan_watch.sh captures: P-ACQ-STUCK (dlm_caw.c:1557 dumps holder slot gen/hex/waiters/yield when acquire>15s), P70-BP (bast_process ENTRY/EXIT), P135-ORPHAN-RELEASE, P6ZC-REL-NOANCHOR (unlock outcome), P138-BAST. Log scratchpad/drc32-DIAG.log pid diag.pid; out orph_diag.

## NEXT (when DIAG wedges)
Capture the frozen holder: its P-ORPH-FORENSIC (held_raw/scan_mine/state), its P70-BP EXIT (does bast_process run? what exit?), its P6ZC/unlock outcome (does the CAS fail?), and P-ACQ-STUCK (is gen advancing = CAS storm?). This NAMES why the release never completes. THEN design the correct fix (likely: give the release CAS priority via yield_to / a bounded-but-winning unlock, NOT a force-clear; or reduce the acquire storm). Do NOT re-enable force-clear without a gate that excludes the transient deferred-release window (mode==NL+DEMOTING is NOT sufficient — it IS the normal window).

## Build/run mechanics unchanged. Files this session: dlm/dlm_caw.{c,h} (+self_held_scan +force_release_self), dlm/v5_mount.{c,h} (+2 wrappers), xfs/xfs_inode.h (+i_dlm_p72_strikes), xfs/xfs_mxfs_dlm.c (forensic, param caw_orphan_reclaim DEFAULT 0, P72 strike-override force-clear [inert at param 0], MXFS_P72_ORPHAN_STRIKES), tests/drc_orphan_watch.sh.
