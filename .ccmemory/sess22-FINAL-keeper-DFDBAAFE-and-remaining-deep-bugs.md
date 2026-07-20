---
name: sess22-FINAL-keeper-DFDBAAFE-and-remaining-deep-bugs
description: sess22(ccloop) FINAL: keeper build DFDBAAFE (reorder-remove + leaf holeskip + leaf bail, leaf_rebuild DEFAULT-OFF). 8/tcp dir_reuse: NO shutdowns, fl…
metadata:
  type: project
---

## sess22 (ccloop) FINAL — keeper DFDBAAFEDF522386BEE70B9

### THREE fixes this session (all KEEP, all in xfs/libxfs/):
1. **Reorder xfs_dir_remove_child non-dir path** (xfs_dir2.c) — removename FIRST while trans clean. Eliminates the remove-path dirty-cancel SHUTDOWN (was 0/8 cascade). THE active win. [[sess22-FIX-remove-reorder-eliminates-dirty-cancel-shutdown]]
2. **Leaf rebuild hole-skip** (xfs_dir2_leaf.c) — skip db where bestsp[db]==NULLDATAOFF.
3. **Leaf rebuild bail-not-shutdown** (xfs_dir2_leaf.c) — on any data-read error return 0 (no mutation) instead of propagating into xfs_create's dirty trans.
Fixes 2+3 are DORMANT when leaf_rebuild=0 (default), so the effective default-params keeper == reorder fix only. Safe, no regression (2/tcp passed 12/12 pre-dir_reuse; 2-node dir_reuse 3× standalone PASS).

### leaf_rebuild=1 is HARMFUL — keep DEFAULT OFF (proven this session):
Even with holeskip+bail, leaf_rebuild=1 on 8-node dir_reuse: 1 PASS then FAIL with shutdowns = `ltbno+ltlen>bno xfs_free_ag_extent (xfs_alloc.c:2254)` = bnobt in-core DOUBLE-FREE (sess23/81 family) + `!(flags & XFS_DABUF_MAP_HOLE_OK)` dir-extent hole. The aggressive leaf relog + exhaustive data-block reads EXPOSE/trigger the deepest AG-alloc corruption. Net negative vs leaf_rebuild=0 (no shutdowns).

### 8/tcp dir_reuse STATUS with keeper (leaf_rebuild OFF):
NO shutdowns across many runs. Flaky PASS (~50-60%). Residual failure faces, all NO-shutdown now:
- **leaf-hash hole** (lookup_fail; BOTH nodes agree = DURABLE on-disk; a node destaged a leaf missing a peer's hashval = leaf-block lost-update RMW-on-stale-leaf). Most frequent.
- round-1 create-visibility miss (readdir=700, one node's 100 entries missing from DATA = data-block create lost-update).
- +1 phantom (readdir=801, the reorder skip leaves a leaf-hash-hole entry unremoved — symptom of the leaf-hash hole).

### REMAINING DEEP BUGS (the 130-session core, NOT fixed this session):
1. **leaf-block lost-update** (leaf-hash hole) — the dominant dir_reuse residual. Needs the clobbering node to read the peer's durable leaf before its addname RMW. leaf_rebuild was the intended remedy but is harmful. Need a SAFE leaf-coherence-on-modify mechanism.
2. **AGI CRC shutdown** (flaky, in-FULL-suite only — 3× standalone 2-node dir_reuse PASS): xfs_agi_read_verify CRC fail on a structurally-VALID AGI during ifree → on-disk AGI written/read with stale CRC under cumulative suite AG-meta churn. [[sess22-AGI-crc-shutdown-ifree-fua-write-no-crc]]
3. **bnobt double-free / data-block double-alloc** (xfs_alloc.c:2254 ltbno+ltlen>bno; data block 0x78 CRC garbage) — deepest, exposed by leaf_rebuild but present underneath.

### NEXT SESSION: pick ONE — the leaf-block lost-update is the highest-frequency 8/tcp blocker. Instrument the clobber point (P21F-RELFLUSH-LEAF at xfs_mxfs_dlm.c:1634 already logs a releaser landing a SHORT leaf count) to catch WHICH node lands the short leaf and whether its in-core leaf was a kept-stale (P36-EVICT-LOCKED / undestaged-keep) vs a fresh-read-stale. Then make the modify-path leaf coherent WITHOUT the harmful full rebuild. Also must run FULL ./run.sh {1,2,4,8} tcp for the criteria.
