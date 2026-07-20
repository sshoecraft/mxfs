---
name: AAA-ccloopa864-sess3-FIX-orphan-forcerel-build-83F6743A
description: sess3 FIX v2 (v0.10.48 srcver 054C3372): P72-ORPHAN-FORCEREL force-clears stuck-DEMOTING orphan CAW bit, with a STRIKE-OVERRIDE (16) of the leaked i_…
metadata:
  type: project
---

# sess3 (ccloop a864) — dir_reuse@32/caw FIX (strike-override), VERIFYING

## CRITERIA: only gap = dir_reuse_coherency@32/caw (all else PASS). Forensic build 72B8FF8C wedged at **r18** with DEFAULT modargs (MXFS_DEV=/dev/mapper/mpatha) → criteria.json recorded FAIL 2026-07-11T04:22:22Z. Must flip to PASS.

## ROOT (PROVEN, RULE 4, forensic build 72B8FF8C)
P-ORPH-FORENSIC at BAST-swallow: `ino=131 site=0 state=3(DEMOTING) mode=0(NL) ex=0 pr=0 pin=0 held_raw=5(EX) scan_mine=1 nslots=1`. Bit is cleanly findable (NOT dup/hint). Orphan = a release (ilock_end deferred to xfs_trans_free, or inline) left the node stuck in DEMOTING with mode=NL and its on-disk EX bit set; bast_process's seq-gated unlock ignored its return. P72-SWALLOW-DEAD storms 3000/node (mode=0 ex=0 pr=0 pin=0). 31 peers block 360s → rc=-110.

## FIX v1 (83F6743A) FAILED TO ENGAGE — WHY (2nd RULE-4 loop)
P72-SWALLOW fired 3000×/node but P72-ORPHAN-FORCEREL=0. Gate `i_dlm_demoter==NULL` was the blocker: the stuck orphan has demoter set to a **stuck INLINE bast_process** (blocked past mode=NL so demoter=NULL at 13636/27260 never runs; work_busy==0 because inline, not workqueue). So demoter!=NULL persistently.

## FIX v2 (v0.10.48 srcver 054C3372, RUNNING run FIX2)
Key insight: mode==NL guarantees Phase-2 drain already ran (data durable) → force-clear is data-safe even with a stuck demoter. Replaced the `demoter==NULL` hard gate with a STRIKE-OVERRIDE:
- New field `i_dlm_p72_strikes` (xfs_inode.h, init 0). `#define MXFS_P72_ORPHAN_STRIKES 16`.
- P72 handler (xfs_mxfs_dlm.c ~14312): orphan shape = state==DEMOTING && mode==NL && ex=pr=pin=0. On shape: claim if `demoter==NULL || ++p72_strikes >= 16`; on claim reset strikes + demoter=current + force_release_self (scan-based unconditional CAS-clear, mxfs_dlm_caw_force_release_self) + state=NONE mode=NL epoch++ demoter=NULL stale=true + wake. Shape-but-below-threshold → swallow (P72-ORPHAN-WAIT log), accumulate strikes. Non-shape (mode==EX etc.) → legacy re-queue. param caw_orphan_reclaim (default 1). 16 strikes ≈0.5s (31 waiters ~1/s) >> transient live drain (1-2 BASTs), << 360s timeout.

## VERIFY (running): watch nodes' dmesg for `P72-ORPHAN-FORCEREL ... cleared=N` (fix engaging) + progress past r18 → r24 PASS. Run FIX2: nohup timeout 5400 env MXFS_DEV=/dev/mapper/mpatha ./run.sh 32 caw dir_reuse_coherency (log scratchpad/drc32-FIX2.log pid fix2.pid; watcher tests/drc_orphan_watch.sh out orph_fix2). If PASS: rerun 2x default for 100%; also confirm no corruption (readdir/leaf-hash checks are in the test itself). If still wedges: pull P72-ORPHAN-FORCEREL/WAIT + dlmtr from holder node.

## Files changed this session: dlm/dlm_caw.c (+self_held_scan, +force_release_self), dlm/dlm_caw.h, dlm/v5_mount.c (+2 wrappers), dlm/v5_mount.h, xfs/xfs_inode.h (+i_dlm_p72_strikes), xfs/xfs_mxfs_dlm.c (forensic + param caw_orphan_reclaim + P72 strike-override force-clear + MXFS_P72_ORPHAN_STRIKES). tests/drc_orphan_watch.sh (new).
