---
name: sess35-round1-refutations-and-addname-coherent-experiment
description: sess35: round-1 dir_reuse loss — epoch-never-0 alone did NOT fix (iter5 fail). REFUTED: kept-stale-base (staleprt=0) + stale-bmap (P37=0 all nodes).…
metadata:
  type: project
---

## sess35 — round-1 dir_reuse loss: refutations + next experiment.

### Build 734EAB23 = epoch-never-0 fix (dlm.c dg_grant_ex epoch 0→1) + P37-STALEBMAP ungated.
- Round-1 repro (drc_repro_loop.sh 15 "" 2): iters 1-4 PASS, **iter5 FAIL** round1 readdir=799 (lost node8_f1, all coherent). **Epoch-never-0 alone did NOT fix the round-1 loss.**

### DECISIVE REFUTATIONS this session (RULE 4)
1. **Read-side KEPT stale prior-tenure base: REFUTED.** 60691 EVDECIDE in failing window, ZERO staleprt=1 (b_epoch<cur_mep while undurable=1). [Caveat: staleprt needs cur_mep!=0; 94% had cur_mep=0=valid_epoch=0 = first-tenure, no prior tenure to be stale against.]
2. **Stale in-core bmap (evict walks too-few extents): REFUTED.** P37-STALEBMAP-MODIFY = 0 on ALL 8 nodes (probe ran 44-75×/node). In-core dir bmap NEVER behind durable disk for same gen → evict walks all current blocks.
So: the modifying node always has a current image + keeps no obviously-stale base, yet a dirent is durably lost (all-coherent). Points to GPT option (ii): live-slot overwrite via stale bestfree WITHIN a current-looking block, OR write-side stale-destage (sess28's "second mechanism").

### EXISTING addname coherence machinery (xfs_dir2_{node,leaf,block}.c addname → use_free)
- mxfs_dir_addname_coherent_refresh called in ALL 3 format paths (node:1977, leaf:1229, block:446). Enabled by `mxfs_dir_addname_coherent` = DEFAULT 0.
- mxfs_dir_addname_epoch_refresh (node path only, P28-ADDNAME-EPOCHSTALE + P28-PLATTER MATCH/DIFFER diag for ino<=256) = DEFAULT 0. Gated on mep!=0 — was crippled by epoch-0 bug.
- sess28 note (xfs_mxfs_dlm.c:4622): coherent=1 ENGAGES (P28C-STALE ~1/run) but does NOT eliminate loss → a SECOND mechanism (write-side stale-destage or concurrent-EX double-grant) remains.

### CURRENT EXPERIMENT (build 734EAB23 + params)
drc_repro_loop.sh 15 "dir_addname_coherent=1 dir_addname_epoch_refresh=1" 2 — sess28 found coherent-alone insufficient, BUT sess28 had epoch=0 (epoch_refresh never fired). With epoch-never-0 the epoch_refresh path can now fire. Testing if the combo eliminates round-1 loss. P28-PLATTER will also now log MATCH (read coherent→write-side) vs DIFFER (read-side) for ino 131.

### IF still fails → write-side. Next: enable mxfs.dirwr dir-block write lineage, trace the lost block's writes for an ABA reflush (stale buffer re-pushed by xfsaild over peer's add); fix = retire dir BLIs more aggressively / GPT's ordered release publish (data→flush→leaf/freeindex→flush→inode→flush→advance gen).
See [[sess35-GPT-consult-round1-epoch0-disables-staleevict-fix]].
</body>
