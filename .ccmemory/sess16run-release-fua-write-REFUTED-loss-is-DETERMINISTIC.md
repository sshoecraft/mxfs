---
name: sess16run-release-fua-write-REFUTED-loss-is-DETERMINISTIC
description: sess16(ccloop) REFUTED dir_release_fua_write=1 (force release block to platter) — same loss. NOT a LIO write-cache durability gap. KEY: the loss is D…
metadata:
  type: project
---

## sess16 (ccloop) — dir_release_fua_write REFUTED; the loss is DETERMINISTIC

### Refutation
mht=50 + `dir_release_fua_write=1` (forces the released dir block to PLATTER via SCSI FUA write, bypassing the LIO target write-back cache): dir_reuse STILL FAILS 0/8, SAME loss (node1_f1.md5, node5_f40.md5). So the loss is NOT a write/read cache-coherency gap at the LIO layer.

### Full refutation list this session (the loss survives ALL of these)
- force_coherent=1 (FUA re-read every dir block, no cache hit) — FAIL
- dir_postread_reread=1 (FIX3 reliable grant-gen re-read) — FAIL
- b_mxfs_dir_epoch tenure trigger (my sess16 build 42178C17) — FAIL
- dir_release_fua_write=1 (release write to platter) — FAIL
→ The loss is NOT read-side staleness AND NOT a write-durability gap.

### THE KEY OVERLOOKED FACT: the loss is DETERMINISTIC
Across EVERY run and EVERY config, the lost names are ALWAYS the same: **node1_f1** (rank1's FIRST file) and **node5_f40** (rank5's 40th file). A timing race would lose RANDOM/varying entries. Deterministic loss of the FIRST-created entry strongly implicates a **dir FORMAT-TRANSITION drop** (shortform→block via xfs_dir2_sf_to_block, or block→leaf via xfs_dir2_block_to_leaf): the earliest entries live in the shortform/block image that gets reformatted; if a node performs the conversion from a base MISSING a peer's just-added early entry (or the 3-way merge mxfs_sf_merge doesn't cover the block/leaf conversion), that entry is structurally dropped — not clobbered by a later RMW. The count=126→77 P-DIRWR regression [[sess16run-BREAKTHROUGH-dir-EX-handoff-midtransaction-lostupdate]] may be a SEPARATE/downstream effect or the conversion itself rewriting the block.

### NEXT (RULE 4, decisive)
Determine never-written vs clobbered for node1_f1: dirwr=2 run, grep P-RELFLUSH/P-DIRWR `names=[...]` across all nodes for "node1_f1" — does ANY node ever durably write a block containing node1_f1? 
- If NEVER written by anyone → it's dropped at CREATE/conversion time (rank1's add of f1 didn't durably land, OR a shortform→block conversion by a peer omitted it). Focus: the shortform/block/leaf conversion paths (xfs_dir2_sf_to_block, xfs_dir2_block_to_leaf) under concurrent cross-node EX + mxfs_sf_merge coverage of NON-shortform conversions.
- If written then disappears → a later conversion/RMW rewrote the block from a base missing it.
Also: is node1_f1 lost on the OWNER (rank1=test1) too, or only peers? Earlier P21H-LEAFHOLE fired on test1 (owner) with f1 in data but not leaf → suggests f1 IS in test1's data block but its LEAF hash is dropped during a leaf operation. Cross-check: is the loss readdir-miss (data drop) or only lookup-miss (leaf-hole)? failrounds show BOTH readdir=751/800 (data short) AND lookup_fail=2 (leaf hole).

### Note on mht
This determinism means mht is NOT purely a race-frequency knob — mht=300 PASSES dir_reuse, so higher mht somehow avoids the deterministic conversion drop too (likely: fewer handoffs → the conversion happens entirely within one node's tenure from a complete base). Build 42178C17 (new logic gated off at default). See [[sess16run-GPT-design-tenure-scoped-dirbuf-coherency-FIX]].</body>
