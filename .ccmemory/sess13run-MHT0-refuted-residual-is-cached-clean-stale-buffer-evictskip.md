---
name: sess13run-MHT0-refuted-residual-is-cached-clean-stale-buffer-evictskip
description: sess13(ccloop) MHT=0 REFUTED (made dir_reuse worse 318/400 vs 399). Residual root = cached CLEAN stale xfs_buf reused by addname w/o a read (FUA neve…
metadata:
  type: project
---

## sess13 (ccloop) — residual 1/400 is a cached-clean-stale dir buffer, NOT MHT

### MHT experiment REFUTED (GPT-5.5 rec #1)
Winning config + `inode_mht_ms=0`: dir_reuse 4/tcp got WORSE = 318/400 & 0/400 (vs 399/400 with MHT=300). No shutdowns (FUA holds). So MHT batching HELPS (fewer cross-node handoffs = fewer stale-base windows); disabling it regresses. Do NOT pursue MHT-disable for the residual.

### The residual mechanism (GPT-5.5 #D + dmesg evidence)
fua_always=1 makes every ISSUED metadata read coherent (FUA pierces LIO cache) — but a CACHED CLEAN `xfs_buf` is REUSED by xfs_dir2 addname WITHOUT issuing any read, so FUA never applies and the stale bestfree[] is used → free-slot double-alloc of ONE dirent (the second-wave .md5). Evidence: `P21S-EVICTSKIP-LEAF ino=131 daddr=1912 leaf_count=402 dirty=0 in_ail=0 pin=0 delwri=0 done=0 dir_gen=6 loaded_gen=6` — the clean cached leaf/data block coherent re-read (evict) is SKIPPED because the gen-gate sees dir_gen==loaded_gen (not stale). So the handoff invalidation does not cover this block.

### THE FIX (next, targeted): on a genuine dir-EX handoff (epoch advanced / post_release adopt), EVICT/invalidate ALL the dir's cached CLEAN data+leaf+free-index xfs_bufs (not just block0/extent map) so the next addname re-reads them — combined with scoped FUA on that re-read = coherent bestfree before placement. Audit `mxfs_dir_evict_data_blocks` / the P21S-EVICTSKIP-LEAF gate (xfs_mxfs_dlm.c) — find why it skips a clean block when a real handoff occurred (gen-gate dir_gen==loaded_gen too conservative). GPT-5.5 also: stamp buffers with di_gen incarnation (dir 131 is reused every round) so a clean buffer from a prior incarnation is never trusted. Must NOT evict DIRTY blocks (own uncheckpointed mods = resurrection/corruption — sess36/50).

### Winning config recap: `fua_disable=0 fua_always=1 dir_epoch_adopt=1 dir_epoch_convert_gate=1` → 399/400, 0 shutdowns. fua_always too slow (RULE-0); scope FUA to handoff dir-block re-reads later. See [[sess13run-WINNING-CONFIG-fua-plus-epoch-adopt-399of400]].</body>
</invoke>
