---
name: ccloop-c7ee71c6-sess48-FOSSIL-ARM-VERIFIED-8-clean-cycles
description: sess48 CLOSE: P53 fossil-nu arm FIXED AND VERIFIED on 0.11.394 — 8 clean cycles (5@32 3@8) + matrix×3, ledger 361 updated; next = remaining 3 critica…
metadata:
  type: project
---

# sess48 disposition: fossil-nu arm VERIFIED; what's next

## Verified state (0.11.394, srcver 1497466E196335D79C7DE89)
8 consecutive clean soak cycles: 32/caw c1 (61 NUFIX heals), c2 (+matrix), d1, f1, f2 (+matrix); 8/caw e1/e2/e4. All sweeps: P53=0 shutdowns=0 fossilwr=0 liveskew=0 mid-run relleak=0. Matrix 9/9 ×3, reap guard ×3. Pre-fix cadence was ~1 fatal/2 cycles (391-c3, 392-c2, 393-c3). Ledger `tests/criteria/OPEN_DEFECTS.json` entry D-RSYNC-RENAME-DIRTY-CANCEL-MASS-SHUTDOWN-361 now carries `evidence_sess48`: fossil arm FIXED AND VERIFIED (roots: 391 clmerge bli_dirty restore; 394 reuse-carried fossil → P-CREATE-NUFIX), rename/dirent-erasure arm remains the OPEN portion (different mechanism, P217 detector standing).

## Ledger after this: 11 OPEN of 39, 4 critical
- **D-FOREIGN-REPLAY-UNGATED-IMAGES** (critical): foreign journal-slice replay applies buffer/dquot/icreate image records gated only by (LSN?) — stale-image application risk.
- **D-INODE-CLUSTER-PUBLISH-WITHOUT-AUTHORITY** (critical): node writes whole 16KB cluster carrying stale foreign-slot images.
- **D-CROSSNODE-OPEN-UNLINK-DATA-LOSS** (critical): B's unlink of file A holds open truncates/frees it (POSIX violation).
- D-RSYNC-RENAME-361 (critical): rename arm (revalidate-target gap in xfs_dir_replace path — see gpt_ruling_sess45 in entry: instrument first-failing rename helper rc+dirty+name+expected-ino).
- majors: D-32NODE-SHARED-DIR-CREATE-PACE (42×), D-READDIR-PEER-CACHED-DIR-PACE (1.2s/dir), D-CRASH-CONSISTENCY-32-NOTERMINAL-354; high: D-DIRVIEW-NONCONVERGE-SESS25; minors: D-MATRIX-UNMEASURED, D-RELOAD-FREED-ADOPT-BOGUS-IMODE; D-AGI-UNLINKED-CROSSNODE (root proven sess40, check status field).

## Rig facts (see sess48-rig-lap-budget memory)
run.sh outer timeout ≥580s (sequential 32×15s preflight); co-tenant load waves (Wow.exe etc + 2 other claude sessions) starve guests — gate laps on load<45, count only PASS laps; kmsg ring rotates marks out in ~hours (sweep promptly, tail 200000); after any killed run.sh: pkill workload + fuser -k -m /mnt/shared per node. Cluster currently 32/caw on 394, healthy. sysrq armed fleet-wide for next wedge.

## Session-48 files touched
xfs/xfs_mxfs_dlm.c (store v4/v5 + discrim + purge + query), xfs/xfs_iunlink_item.c (P53 QUERY hook), xfs/xfs_inode.c (clmerge fix), libxfs/xfs_inode_util.c (P-CREATE-NUFIX), pal/linux/xfs_buf.c (site 4 + verified retire), tests/iunl_soak_sweep.sh (new), CHANGELOG 387-394, awareness xfs.md/pal.md appended.

## Criteria answer
STILL NO — 11 OPEN of 39 (4 critical). Continue: extend soak opportunistically; next attack per severity = the three non-rename criticals (foreign-replay gating audit is code-heavy and load-tolerant — good hot-window work; open-unlink data loss has openunlink_matrix as its harness — currently passing, needs the specific cross-node repro from its entry).
