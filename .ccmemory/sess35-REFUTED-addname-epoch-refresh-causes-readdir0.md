---
name: sess35-REFUTED-addname-epoch-refresh-causes-readdir0
description: sess35 REFUTED: dir_addname_epoch_refresh=1 (+epoch-never-0) causes readdir=0 CATASTROPHE at round1 (zombie BLI reflush, no retire). Read-side addnam…
metadata:
  type: project
---

## sess35 — REFUTED: read-side addname refresh for round-1 loss. Residual is WRITE-side.

### Experiment (build 734EAB23 epoch-never-0 + params dir_addname_coherent=1 dir_addname_epoch_refresh=1)
- iters 1-2 PASS, **iter 3 = readdir=0/800 CATASTROPHE** (whole dir wiped at round-1 verify; missing names node8_f9.md5 etc REREAD_MISS).
- Cause: mxfs_dir_addname_epoch_refresh (xfs_dir2_node.c:2057-2079) clears XBF_DONE + xfs_trans_brelse + restart WITHOUT retiring the in-AIL BLI → zombie BLI reflushes stale → readdir=0 (the sess26 readdir=0 pattern). epoch-never-0 made it fire MORE → catastrophe.
- P28-PLATTER (now firing, ino<=256): MOSTLY incore_vs_platter=MATCH (test1 29 MATCH/0 DIFFER; test8 228 MATCH/3 DIFFER). MATCH = at addname the in-core block == platter (read coherent). Only 3 DIFFER (read-side stale buffer) caught+refreshed (EPOCHSTALE=1). So the read at addname is overwhelmingly coherent — the loss is NOT a read-side stale base at addname.

### CONCLUSION (converges with sess28): the round-1 dir_reuse loss is WRITE-SIDE.
- Read-side refutations stacked: kept-stale-base staleprt=0; stale-bmap P37=0 all nodes; addname in-core==platter MATCH; and read-side refresh is either insufficient (coherent alone, sess28) or CATASTROPHIC (epoch_refresh → readdir=0).
- DO NOT enable dir_addname_epoch_refresh (readdir=0). dir_addname_coherent alone is safe but insufficient.

### KEEP: epoch-never-0 fix (dlm.c dg_grant_ex, build 734EAB23) is correct/harmless (makes per-block machinery active) — but does NOT alone fix round-1. Keep it.

### NEXT (write-side): the durable all-coherent loss = the LAST write of the victim's data block lacked the entry. Mechanisms: (a) xfsaild ABA reflush of a non-retired stale dir-block BLI over a peer's add; (b) release-drain completeness gap (just-added dirent's block mis-skipped as already-destaged). Instrument: enable mxfs.dirwr dir3 data-block WRITE lineage (pal/linux/xfs_buf.c P35E/H27/H28), trace the victim daddr's write history for a stale (entry-missing) write submitted AFTER a complete one. Fix candidates: suppress xfsaild writeback of dir DATA/leaf buffers by a non-EX-holder (like P126 AG-meta / P60 bmbt write-suppress); or GPT's ordered release publish (data→flush→leaf/freeindex→flush→inode→flush→advance gen) + retire ALL dir BLIs at release.
See [[sess35-round1-refutations-and-addname-coherent-experiment]] [[sess35-GPT-consult-round1-epoch0-disables-staleevict-fix]].
</body>
