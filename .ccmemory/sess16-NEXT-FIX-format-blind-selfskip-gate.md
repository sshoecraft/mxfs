---
name: sess16-NEXT-FIX-format-blind-selfskip-gate
description: sess16 NEXT-FIX target: mxfs_dlm_reload_inode self-skip gate (xfs_mxfs_dlm.c ~5189-5275) is FORMAT-BLIND — decides keep-in-core vs adopt purely on ge…
metadata:
  type: project
---

## sess16 precise NEXT-FIX location for the 2/tcp crash_consistency sf<->block oscillation lost-update [[sess16-HEAD-status]] [[sess16-FORMAT-DIVERGENCE-shortform-vs-block]].

## THE GATE: mxfs_dlm_reload_inode(ip, expect_ftype, post_release) at xfs/xfs_mxfs_dlm.c:5042.
- ~5189: `peer_modified_since_load = S_ISDIR && !i_mxfs_self_created && i_dlm_dir_gen > i_dlm_dir_loaded_gen`.
- ~5211: `mxfs_dir_disk_superset = S_ISDIR && (post_release || peer_modified_since_load)`.
- ~5213: SELF-SKIP block: `if (!mxfs_dir_disk_superset && (in_ail||dirty||ili_fields||pin)) { i_dlm_stale=false; return; }` — KEEPS in-core, skips reload.
- A CLEAN inode (no mods) always falls through to adopt (5284 buffer-inval, then dip read, then xfs_idestroy_fork + repopulate ~5948).

## THE BUG: `dip` (struct xfs_dinode, decl 5049) is NOT assigned until AFTER the gate (read from the cluster buffer post-5284). So the self-skip decision is **FORMAT-BLIND** — purely gen-based. Under inode-number REUSE, i_dlm_dir_gen/i_dlm_dir_loaded_gen are unreliable (recycled vs fresh incarnation), so `peer_modified_since_load` is a FALSE NEGATIVE → a node (test1) with its own shortform adds in-flight self-skips and KEEPS its stale SHORTFORM view even though a peer (test2) already grew the dir to BLOCK format on disk. test1 then writes its shortform dinode → on-disk dir downgrades block→shortform → durable entry loss; test2 then adopts the shortform (P62-RELOAD-FORK-SHRINK shrink=1) and the oscillation loses entries.

## FIX DIRECTION (next session, full budget — this is the MOST regression-prone function; many reverted reload fixes in [[sess9-root-durable-revert-and-publish-only-regression]] etc.; ALWAYS full ./run.sh 2 tcp x3 + watch cache_coherency/strong_consistency/dlm_fairness/rename):
1. Make the self-skip DISK-FORMAT-AWARE: read/peek the on-disk di_format BEFORE the self-skip decision (or move the gate after dip is read). 
2. FORMAT MONOTONICITY: if disk di_format is a strict UPGRADE over in-core (disk EXTENTS/BTREE while in-core LOCAL/shortform), do NOT self-skip — adopt the block disk image (it is a strict superset; a dir only grows sf->block by ADDS) and RE-APPLY this node's in-flight committed-not-durable adds (extend the merge_ours mechanism ~5935, currently shortform->shortform only, to cover shortform-in-core -> block-disk). 
3. DOWNGRADE GUARD: never adopt a disk shortform over in-core block/leaf (a shrink) unless post_release (real removes, drained). 
4. CAUTION: the resurrection bug (sess8) — a shortform in-core may carry a committed-not-durable DELETE; adopting disk could resurrect it. For create-only crash_consistency there are no deletes, but the full suite has them — gate the force-adopt on "no delete in flight" or preserve the merge/delta re-apply. 
Repro = tests/cc_blockdir_probe.sh (per-iter dmesg-clear + ino capture added this session; reuses ino; fails <15 iter). Cluster on instrumented 03A6D084 (== baseline 17DCD050 behavior + P16/P35E-names/lseq-wseq dumps, dirwr-gated). Fallback 17DCD050 = 15/16. test2 rmmod-busy on redeploy → virsh destroy+start test2; verify both srcversions after every deploy.
