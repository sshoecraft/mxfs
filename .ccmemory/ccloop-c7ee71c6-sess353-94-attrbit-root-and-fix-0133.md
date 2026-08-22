---
name: ccloop-c7ee71c6-sess353-94-attrbit-root-and-fix-0133
description: sess353: #94 false-refusal ROOT = lazy per-node ATTRBIT add (mkfs lacked it); fix LANDED 0.13.3 sv F7E9E19DF7CC718EBFC32EA (mkfs preset + mount gate)…
metadata:
  type: project
---

# sess353 — #94 closure attempt: ATTRBIT root cause + 0.13.3 fix

## What happened
- Deployed 0.13.1/0.13.2 (probe build), wrote tests/sbclean_fence_idle.sh
  (idle-victim fence closure test, self-contained incl. victim power-cycle
  + prep_node rejoin). Two runs: classifier FALSE-REFUSED, sbreason=7
  (CONTENT), quarantine reproduced both times.
- SBCLEAN-CONTENT-DIFF probe (kept in tree, fires on verdict 7): first
  diff off=101 base=a5 img=b5 → sb_versionnum low byte → victim image has
  XFS_SB_VERSION_ATTRBIT (0x0010), replayer baseline lacks it.

## Root (proven)
mkfs_mxfs versionnum 0xB4A5 (no ATTRBIT) but features2 0x018A has ATTR2 →
first xattr-bearing create anywhere (XFS_ICREATE_INIT_XATTRS; AppArmor
security xattr on the rig) hits !xfs_has_attr → xfs_add_attr + xfs_log_sb
(xfs_inode_util.c:348, xfs_bmap.c:1075) — lazy PER-NODE uncoordinated
cluster-wide SB feature transition. Victim's slice carried those 2 SB
images; content compare correctly refused (fail closed).

## GPT ruling (sess353 transcript)
1. Preset ATTRBIT in mkfs (0xB4B5) — no v5 hazard, matches stock mkfs.xfs.
2. Classifier + mask UNCHANGED — never mask versionnum (clean-skip would
   drop a real feature transition).
3. Old format: version-gate/refuse cluster mount rather than fixup.
4. NEW BROADER DEFECT to ledger: per-node divergent m_sb + whole-SB
   logging → any peer SB txn (incl. lazy counter sync) overwrites another
   node's persistent non-counter SB changes. Containment for current
   profile: FORBID all runtime non-counter SB mutations in cluster mode
   (attr/quota/log_incompat-LARP/growfs/label/NEEDSREPAIR), reject before
   mutating m_sb. If ever coordinated: protocol must cover EVERY whole-SB
   producer, not just feature-changing txns.
5. Q3: with ATTRBIT preset + no rt/quota/LARP, only icount/ifree/fdblocks/
   lsn/crc vary in routine idle SB syncs — current mask is complete.

## Landed 0.13.3 sv F7E9E19DF7CC718EBFC32EA (built, NOT deployed)
- tools/mkfs_mxfs.c:110 XFS_SB_VERSIONNUM 0xB4B5 (comment explains).
- xfs/xfs_mount.c xfs_mountfs ~890: m_mxfs_dlm && !xfs_has_attr →
  -EINVAL refuse (old-format gate).
- NOTE: tools were missing at session start (make tools needed after make
  clean) — prep_cluster fails FS_PREP_FAIL without them.

## State at handoff
Cluster DIRTY (AG0 quarantined run 2, slot 2 frozen, test2 fenced).
Next: ledger the new defect, prep_cluster (deploys 0.13.3 + new mkfs),
rerun sbclean_fence_idle.sh ×2, then #92 races 6/7, full board.
