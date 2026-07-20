---
name: AAA-ccloopa864-sess1-PACE-war-and-use_free-corruption
description: sess1 mid2: pace war data (fastpoll/jitter/close_release/reaper/sweep A-Bs); REAL bug resurfaced: r2 create use_free EFSCORRUPTED (bestfree stale) on…
metadata:
  type: project
---

# dir_reuse@32 — pace experiments ledger + the resurfaced use_free corruption

## Builds this session
- v0.10.34 = binval-retire fix (P3B probe) — killed the P97 wedge family ✓ KEEP.
- v0.10.35 = random jitter in caw_inode_backoff (was (retry+node*5)%7 phase-lock). Softened later to 0-inclusive. Neutral-to-mild ✓ keep.
- v0.10.36 = close_release (file-close PR demote; NO-OP for dir_reuse — verify uses STATS not opens) + acquirer fastpoll (2ms first 64ms; unlink 45→30ms) — but suspected of amplifying the 31-waiter dir-EX convoy (peers' create waves 90→175s?? unproven).
- v0.10.37 = idle-PR timer reaper (arm at ilock_end +800ms) — **REFUTED**: releases storm the slot table DURING verify (verify 66→416s, PR acquires 2.5-5s incl 5.16s ≈ yield stale timeout, test1 rc=-110-style shutdown at ilock_begin:20318). Default 0 now.
- v0.10.38 = dir-EX-BAST sweep: on losing a PR-held dir to peer EX, s_inodes-walk release all idle REG PR grants (rate-limit 3s). WORKS when it fires (test5 released 3199 in one pass; r1 rm=39s vs 105-190s) but PR-only trigger missed most rounds (peers hold dir EX after their create wave).
- v0.10.39 = sweep trigger widened to EX-held dirs + caw_inode_fastpoll runtime param (default 1). srcversion TBD.

## Round-wall ledger (rank1, test1)
- v34: 222/240/261 (create 16-44, verify 47-54, rm 159-176; rm = 3200 unlinks × 45ms BAST-strip of 31 stat-PR holders/file)
- v36+fastpoll: r1 224 r2 249 (rm 140-152, P138-WAIT 25-37ms)
- v38+sweep: r1 **112** (rm 39!) then r2-r5 315/293/281/277 — plateau ~280. r2+ [create-done→verify-done] ≈175s = WR-BARRIER WAIT for peers' create waves (rank1's own creates 2s under MHT tenure).
- CAW slot table at r6: live=161 tomb=3426 (plateau ~3200, tombstones ARE reused; hint fast path exists) — NOT unbounded growth; slot-table not the slope driver.

## THE REAL BUG RESURFACED (r2 create, test5, run 225612Z v0.10.38)
`XFS Internal error xfs_dir2_data_use_free at xfs_dir2_data.c:2436` during create of node5_f1 (FIRST r2 create on test5, t=1825.71) → P-CR3-CANCEL error=-117 trans_dirty=1 → SHUTDOWN_CORRUPT_INCORE. Dir 131 fmt=2(leaf) nx=4 size=12288, 3 data blocks (71169688, 79542584, 92101928) whose CACHED content at shutdown = CURRENT r2 peers' names (P11-FLUSH-CLEANSKIP dumps) ⇒ data blocks fresh; suspect = STALE LEAF bests[] (leaf-vs-data disagree = the bestfree double-alloc family; CLAUDE.md "must read fresh leaf+data"; P6L leaf scan was the 8-node fix). watch_ino probes (P9/P13/P11/P49/P10/P-DIRWR) ARE armed on 131 by the suite — forensics available in /root/dmesg.stream per node.
- 16/caw passed 17/17 on this machinery; 32 reopens the window (more handoffs/leaf churn).
- NOTE: prior runs' r2-r3 always died SOMEHOW (v34: P97 wedge [FIXED]; v37: reaper storm [reverted]; v38: use_free). The use_free may also have been the underlying trigger in earlier partial views.

## Next experiment (in flight at handoff)
Clean A-run on v0.10.39: modargs `dirwr=1 dirland=1 close_release=0 caw_inode_fastpoll=0` (sweep on, jitter soft, binval fix in) → (1) round walls r1-r4 (expect rm~40 every round via wide trigger; peers' create wave back to ~90s if fastpoll was the amplifier), (2) does use_free reproduce → root-cause with armed probes: extract leaf lineage (P49-STALEBASE / P10-RDBLK / P13-LADD around the failing create), compare leaf bests vs data platter via envelope read (+196688 sectors ×512 +byte offset... NB daddr→img: (daddr+196688)*512).

## Ops notes
- Kill discipline: killing timeout+run.sh leaves per-node launcher orphans holding /tmp/mxfs_run.lock → `pkill -9 -f <run_id>` + pkill -9 -f './run.sh 32' + per-node pkill dir_reuse_coherency; THEN verify fuser /tmp/mxfs_run.lock.
- After every kill: sweep SSH-dead nodes (wedged umounts) + power-cycle + mpath_up 32 BEFORE next launch.
- dmesg.stream per node /root/ = full history (suite starts it); scp to scratchpad for python forensics.
