---
name: sess26-BREAKTHROUGH-genperhandoff-plus-extentadopt-fixes-wholeblock-and-hole-residual-single-entry
description: sess26(ccloop) BIG PROGRESS: dir_gen_per_handoff=1 + dir_modify_extent_adopt=1 FIXES the whole-block clobber AND the DABUF_MAP_HOLE (extent_adopt ref…
metadata:
  type: project
---

## sess26 — best dir_reuse 8/tcp result in many sessions

### The working combination (build 965BDBD3, both levers as modargs; both DEFAULT 0)
`MXFS_EXTRA_MODARGS="dir_gen_per_handoff=1 dir_modify_extent_adopt=1"`
- **dir_gen_per_handoff=1** (NEW, xfs_mxfs_dlm.c): uncap the fast-path epoch gen-bump (`mxfs_dir_gen_per_handoff || dir_gen<=loaded_gen`) so i_dlm_dir_gen advances on EVERY cross-node handoff → read-path pre-read invalidation fires every handoff → fixes the whole-block (and most single-entry) data-block clobber.
- **dir_modify_extent_adopt=1** (existing, was default 0 / sess68 "MAPDIVERGE=0 at modify-prelock"): on an epoch-advanced modify, FUA-check the dinode + adopt the peer's grown extent map. With per-handoff re-reads now pulling in NEWER leaves, the map DOES diverge (a leaf references a block the stale map lacks) → adopt closes it → **DABUF_MAP_HOLE 511→0**. (Without adopt, gen_per_handoff alone gives 511× xfs_da_btree.c:2876 holes.)

### Results (clean reboot each, /root/drc_failrounds.txt cleared at start)
- Run A: **PASS 8/8**, 354s (normal speed = keeper), HOLE=0, all 24 rounds, 0 failrounds all nodes.
- Run B (validation run 1): **FAIL** — single round-13 `readdir=799/800 lookup_fail=0` on ALL nodes (one durable single-entry loss), HOLE=0, 355s.
- So: whole-block clobber + hole FIXED; residual = occasional SINGLE-entry lost-update (the long-standing readdir=799 deepest face). NOT 100% yet.

### DO NOT add dir_modify_extent_reload
gen_per_handoff + extent_adopt + extent_reload → HOLE=0 BUT round-14 BLOWUP (readdir=501/800 lookup_fail=229) + stalled at round 14. extent_reload (sess14 already flagged problematic) reverts blocks. Use extent_ADOPT only.

### Residual single-entry — next hypotheses (RULE-4)
Even with per-handoff data-block invalidation, one entry occasionally drops = a FREE-SLOT collision: two nodes write different dirents to the same slot. With coherent data blocks this needs the FREE-SPACE accounting (data-block bestfree[] OR the node-format FREE block, xfs_dir3_free_buf_ops) to be stale for one node, OR an epoch-handoff-detection MISS (the handoff bit/epoch edge-case under-fires so one handoff isn't invalidated). NEXT: (a) confirm the per-handoff invalidation covers the FREE block (xfs_dir3_free_buf_ops) — it's read via xfs_da_read_buf so should, but verify it's gen-stamped+invalidated; (b) instrument the round-13 single loss: at the losing creator's addname, is the chosen slot already occupied on disk (free-block stale) vs a post-commit destage? (c) check whether mxfs_v5_dlm_inode_dir_epoch ever fails to advance on a rapid same-pair handoff (epoch granularity).

### Tree: build 965BDBD3 = keeper + dir_gen_per_handoff (default 0) + prior sess26 inert levers. dir_modify_extent_adopt default 0 (currently). To make this the shipping config, both must flip to default 1 AND the single-entry residual solved AND 1/2/4 re-verified. [[sess26-PROGRESS-dir-gen-per-handoff-wholeblock-to-single-but-dabuf-hole]]
