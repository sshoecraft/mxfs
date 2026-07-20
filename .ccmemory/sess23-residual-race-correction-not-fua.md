---
name: sess23-residual-race-correction-not-fua
description: sess23(ccloop) CORRECTION to the breakthrough memo: the dir_tenure_evict=1 residual flaky single-entry loss is NOT FUA-stale-platter (FUA reads pierc…
metadata:
  type: project
---

## sess23 (ccloop) — CORRECTION on the dir_tenure_evict residual race

The [[sess23-BREAKTHROUGH-master-epoch-sync-flaky-pass]] memo floated a FUA-stale-platter hypothesis for the residual flaky single-entry loss. On reflection that is LIKELY WRONG and should not be pursued first:

- The `_XBF_FUA_FRESH` / `mxfs_pal_scsi_read_fua_bdev` mechanism exists *because* FUA SCSI READ(16) PIERCES the target/initiator cache to get the CURRENT data (CLAUDE.md design tension "LIO drops FUA"). FUA reads are the WORKING coherency primitive across this whole codebase; many sessions proved plain reads serve stale and FUA fixes them. So the evict's FUA re-read gets CURRENT data, not a stale platter. Do NOT change the evict to keep _XBF_FUA_FRESH (normal read) — that would regress general coherency.

- The residual: `comm=bash` (synchronous create RMW, not xfsaild), on a block read THIS tenure (b_mxfs_dir_epoch == synced master valid_epoch, so the epoch override correctly does NOT evict it), single entry, random round, NO cascade. If the FUA re-read returns current data, then at the moment the clobbering node read the base, the peer's entry was genuinely not yet visible on the target — an EX-serialization gap.

- MOST LIKELY ROOT (matches sess49 `sess49-residual-tcp-doublegrant-dir-resurrection-complete-diagnosis`): TCP DLM transient DOUBLE-GRANT (two nodes briefly hold EX) OR the EX-release→next-grant ordering letting the acquirer read before the releaser's drain landed. The P61-BLK0 `ex_pop`/`ex_nslots` probe (xfs_da_btree.c, instr-gated) is built to detect concurrent EX holders — NEXT SESSION: run dir_tenure_evict=1 with instr=1, at the failing round check P61-BLK0 ex_pop>1 (== double-grant, case B, no dir-layer fix helps → must fix DLM tenure serialization) vs ex_pop<=1 (== single holder, stale base → a remaining read/evict gap).

NEXT-SESSION PLAN (narrow): build B17FED9A is the base. (1) instr run to read P61 ex_pop at the residual fail → confirm double-grant vs single-holder. (2) If double-grant: fix TCP DLM EX serialization (sess49 territory). (3) If single-holder: the release drain didn't land before grant → enforce release→grant ordering in bast_work_fn/TCP grant path. (4) Once dir_reuse 8/tcp is reliable, make dir_tenure_evict DEFAULT-ON and validate full 8/tcp suite + 1/2/4 tcp (no regression) — the criteria need the param on.
