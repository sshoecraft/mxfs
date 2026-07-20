---
name: sess50-relepoch-writeback-gate-REFUTED-loss-is-at-modify-not-writeback
description: sess50(ccloop): relepoch writeback-reflush gate REFUTED (4/4 FAIL, loss at 0 skips). Durable dir loss is at MODIFY time, NOT xfsaild reflush. Redirec…
metadata:
  type: project
---

## sess50 (ccloop 4cb2d0a2) — relepoch cross-node writeback gate REFUTED; loss is at MODIFY time

### The fix I built (and its DEFINITIVE refutation)
Implemented GPT-5.5 "Fix 4/5": stamp each dir buffer with the owning inode's **i_dlm_epoch** (the RELIABLE local release counter — bumped on every grant-loss/stale, xfs_mxfs_dlm.c:9327; immune to the grant_gen/i_mxfs_ex_grant_seq handoff-underfire). At xfsaild writeback, skip a CLEAN dir buffer whose stamp `b_mxfs_relepoch < ip->i_dlm_epoch` (= this node released the grant since the image was coherent → a peer may have superseded it → flushing reverts the peer's add). Build A9C02659, default ON.
- Field `b_mxfs_relepoch` (xfs_buf.h), stamped at modify (mxfs_dir_data_track ~21984) + fresh-read (xfs_da_btree.c ~3871), reset on buffer reuse. Skip arm in mxfs_buf_xfsaild_skip_dir_write; enforce at xfs_buf.c P50-RELEPOCH-SKIP under param `dir_relepoch_skip`.
- **REFUTED: reliability loop 8/tcp = PASS=0 FAIL=4 of 4** (tests/drc_reliability_relepoch.sh). Runs alternated relepoch_skips=4 and **0**. RUN 2 and RUN 4 lost data with **ZERO** relepoch skips. (The first standalone clean run PASSED 8/8 but with 0 skips = a FLAKY fluke, not the fix.)
- Set `mxfs_dir_relepoch_skip = 0` (default OFF, dormant modarg) so the baked build (4E3733D0) does NOT regress 1/2/4. Code + instrumentation retained.

### WHAT THIS PROVES (the redirect):
The durable single-dirent loss does **NOT** go through an xfsaild reflush of a pre-release stale buffer — runs FAILED with 0 such skips. So the **writeback-side is NOT the loss vector** (catching 4 reflushes in runs 1&3 didn't prevent the loss either). The `xnode=1` detector hits (buf_cnt==wrcnt_max, disk_cnt==buf_cnt+1) from the earlier dataclobber=1 run are mostly BENIGN-transient (that run also passed). 

⇒ **The loss is at MODIFY time**: a node's addname RMWs a dir DATA block whose in-core base is missing a peer's durably-added dirent, producing a count-PRESERVING content-divergent block (own add present, peer's `node1_f9.md5` gone). This CONTRADICTS sess69's `P-TDS-RMW stale_base=0` (base-not-stale) — that detector likely measured the wrong block/condition, OR the loss is via dir2 data-block COMPACTION / block→leaf conversion during a full-block addname dropping an entry under concurrency.

### CLEAN failure signature (reconfirmed, build-independent): round-1 (or ~7) ALL nodes lose exactly ONE dirent (e.g. node1_f9.md5 / node5_f6.md5), readdir=799/800, LOOKUP_ENOENT + REREAD_MISS (durable). Then CASCADES to a STUCK 699/800 (or 0/800, dir fails to stat) for all later rounds — rm-rf+recreate does NOT clean the corrupted leaf/free structure. Storage = LIO-ORG, write-through, FUA reads on.

### NEXT (RULE 4) — investigate the MODIFY path:
1. Instrument the addname RMW base: at xfs_dir2_data_addname / xfs_dir2_node_addname, BEFORE inserting, scan the in-core block + compare to a coherent disk read — does the base LACK a dirent disk has (real stale base)? Capture which name, which node, the block daddr. (sess69's P-TDS-RMW=0 must be re-verified — it may have checked block-0 only, or post-RMW.)
2. Check dir2 data-block COMPACTION (xfs_dir2_data_freescan/compact) + block→leaf / leaf→node conversions during a full-block addname for a concurrency bug dropping an entry (count-preserving).
3. Check the LEAF-hash path: a leafn addname inserting a hash on a stale leaf/free-index block, overwriting/orphaning a peer's leaf entry (readdir walks data, so data must lose it too — but a stale free-index could misdirect the data allocation).

### REFUTED THIS SESSION (full list, do NOT retry): grant_gen writeback gate (gg_mismatch=0), dir_refresh_inplace=1 (whole-batch regression), dir_acq_lockwait=600 (LOCKED-SKIP hole not primary), relepoch writeback gate (4/4 FAIL, 0-skip losses). Case A allocator-overwrite ruled out (check_free EFSCORRUPTs, we see silent loss). See [[sess50-REFUTED-grantgen-and-tenure-counters-unreliable-handoff-underfires]] [[sess69-CONCLUSIVE-no-writeside-fix-buffer-content-reverted]].</body>
