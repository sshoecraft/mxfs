---
name: sess15-ROOT-concurrent-sf-to-block-conversion-double-alloc
description: sess15 REFINED: 2/tcp block-dir loss is a BLOCK-format concurrent-RMW lost-update (NOT sf→block conversion — P-H14 showed COMPLETE merge). force_evic…
metadata:
  type: project
---

## sess15 REFINED ROOT (supersedes the conversion-double-alloc framing below). Build CE99583D (dirwr=1). Criterion NOT met.

## WHAT IT IS: a BLOCK-format-dir concurrent-create lost-update of POST-conversion entries. Repro tests/cc_blockdir_probe.sh / cc_minrepro.sh: 2 nodes write 50 data+50 md5 into one shared dir; ~2 contiguous test2 entries (e.g. node2_f15,f16) durably vanish from BOTH nodes (gone from LUN, not eventual). Contiguous creation-order names = ONE dir DATA block's worth.

## NOT the sf→block CONVERSION: P-H14-INSTR (enhanced sess15 to dump in-core SF name list at xfs_dir2_sf_to_block START) showed the converting node had the COMPLETE merged set incore_names=[node1_f1-6 node2_f1-5] when it converted. So conversion freezes a COMPLETE fork; the lost entries (f15/f16) are added AFTER conversion, into block format. => the loss is a block-format data-block RMW lost-update, NOT conversion, NOT shortform.

## REFUTED this session (RULE 4, all instrumented):
- master DLM double-grant: P-DOUBLEGRANT=0, P-STALEMASTER-GRANT=0 (skew-proof master-side detector). The cross-node P106-EXGRANT/EXREL "overlap" was CLOCK SKEW.
- MHT batching window: inode_mht_ms=0 still loses.
- clean-cached-stale-block: new module_param dir_force_evict=1 (force mxfs_dir_evict_data_blocks on EVERY cross-node modify, not local-gen-gated) STILL loses → the clobber base is NOT a clean cached block (evict drops clean, skips dirty). KEPT in tree (harmless, default 1).
- sf_merge: sf_merge=0 still loses → the 3-way SF merge is not the cause of THIS (block-format) loss. The apparent block↔shortform "format oscillation" in P105 traces was an INODE-REUSE artifact (low ino reused across iters), NOT a real single-dir reversion.

## DEDUCTION (+ GPT-5.5 consult, RULE 5): EX is exclusive (no double-grant), releasing node drains data blocks + dinode durable, acquirer reloads + force-evicts clean blocks + plain-reads coherent LUN — yet the entry is lost. Since clean-evict didn't fix it, the clobber base is a block the clobbering node holds DIRTY (its own un-checkpointed adds, which evict skips) OR a release-side durability gap for the specific block. GPT ranked: (#1 conversion-incomplete — REFUTED here), (#2 release-side home-location durability gap for the data block: dinode says block-fmt but block contents/bestfree not flushed to LUN before release), (#3 dirty/daddr-aliased cached buffer surviving the DLM handoff to NL = a release-drain bug). GPT fix direction: per-EPOCH (not per-op) authoritative reload on cross-node acquire + ensure release drains the FULL inode metadata CLOSURE (every dir data/leaf/free/bmbt buffer, not just the dinode AIL item) before setting i_dlm_mode=NL; assert no dirty/pinned/in-AIL/delwri dir buffer remains at NL.

## INSTRUMENTATION ADDED (build CE99583D, KEEP): mxfs_dir_block_names() walks a dir2 DATA/BLOCK buffer listing live dirent names (defensive, bounds-checked); wired into P-RELFLUSH (now dumps names=[...] per flushed daddr). P-H14-INSTR dumps incore SF name list, gated dirwr. Next: cross-node P-RELFLUSH per-daddr compare (test2 flushes block w/ f15,f16; test1 later flushes SAME daddr without them = clobber proof) — BUT P-RELFLUSH is pr_warn_ratelimited + inode-reuse confounds; cc_minrepro.sh clears dmesg per-iter + never-reuse dirs to scope the trace. NEXT: confirm whether test2's release-flush of the block HAS f15/f16 (→ acquire-side stale RMW / #3) or LACKS them (→ release-side durability gap / #2); add a read-side names detector at the create's dir-block RMW base. Consider de-ratelimiting P-RELFLUSH for the trace. [[sess15-decisive-negatives-blockdir-loss]] [[sess14-cc-root-blockdir-concurrent-create-dirent-loss]]
