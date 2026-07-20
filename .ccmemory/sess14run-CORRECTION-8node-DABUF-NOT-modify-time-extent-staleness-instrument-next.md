---
name: sess14run-CORRECTION-8node-DABUF-NOT-modify-time-extent-staleness-instrument-next
description: sess14(ccloop) CORRECTION: the 8-node create/lookup DABUF_MAP_HOLE is NOT modify-time extent-map staleness. My epoch-triggered prelock extent-reload…
metadata:
  type: project
---

## sess14 (ccloop) — CORRECTION on the 8-node create/lookup DABUF_MAP_HOLE root

### What I tried and what it proved
Hypothesis: the 8-node create/lookup DABUF_MAP_HOLE = fresh-leaf/stale-extent-map (mxfs_dlm_dir_modify_refresh evicts blocks ILOCK-held but can't reload the extent map). Fix attempt: a gated (default 0) `dir_modify_extent_reload` branch in mxfs_dlm_dir_modify_reload_prelock that reloads a non-SF dir's inode when its DLM epoch advanced.
RESULT: built (1A0A8F9C), ran full 8/tcp with it ON + TEST_TIMEOUT=600. **P14-MODEXT-RELOAD fired 0×; dir_reuse STILL 0/8; DABUF storm unchanged.** The epoch trigger (grant_epoch > valid_epoch) never matched for the non-SF dir.

### REFUTATION
This + sess68 ([[sess40-ABA-fix-REFUTED-clobber-is-current-incarn-stale-tenure]] family; P68-MAPDIVERGE=0 = full per-block daddr compare found maps AGREE at every modify-prelock) means the DABUF hole is **NOT modify-time extent-map staleness**. The in-core extent map matches disk when the modify starts. So the fresh-leaf/stale-map theory is REFUTED for create/lookup. (The readdir-path fix that DID work, sess14, addressed a different timing: the readdir bumped dir_gen before a bailable reload — that specific ordering bug is real and fixed; it does not generalize to create/lookup.)

### NEXT (RULE 4 — INSTRUMENT, do not guess again)
At xfs_da_btree.c xfs_dabuf_map `invalid_mapping` (the hole site, ~line 2815), add a probe (multi-node dir DATA fork, !HOLE_OK) logging: bno, dp->i_df.if_format, if_nextents, i_disk_size, i_dlm_dir_gen, i_dlm_mode, comm, AND the irecs[] returned (br_startoff/startblock/blockcount) — to see WHERE block `bno`'s reference originated and what the map actually holds. Determine if the offending block came from (a) a stale LEAF block re-read (b_mxfs_dir_gen logic re-fetched a leaf referencing a block that was since freed/never-existed in this incarnation — ABA daddr reuse), (b) an in-transaction xfs_trans_roll re-read mid-addname, or (c) a genuinely orphaned/double-mapped daddr. The 8-node storm (test4: 251-668 events) makes it easy to capture. ONLY then form the fix.

### Build state: 1A0A8F9C deployed = validated AA8C4934 runtime (1/2/4 tcp pass; 8/tcp 12/17 at 600s budget) + the inert default-off dir_modify_extent_reload param (kept as a documented dead-end, never fires). Reverting it changes nothing at runtime.
Criterion NOT met. See [[sess14run-SESSION-SUMMARY-and-next-priority]] [[sess14run-8tcp-FULL-MAP-12of17-at-600s-remaining-DABUF-createlookup-iscsi-conn-tdscaling]].
