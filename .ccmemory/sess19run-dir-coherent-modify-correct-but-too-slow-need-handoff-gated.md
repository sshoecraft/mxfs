---
name: sess19run-dir-coherent-modify-correct-but-too-slow-need-handoff-gated
description: sess19(ccloop): dir_coherent_modify=1 + dir_release_invalidate=1 @ mht=50 = CORRECT (failrounds=0 thru round6) but ~5× too slow (~60s/round, per-addn…
metadata:
  type: project
---

## sess19 (ccloop) — the correctness fix exists but must be made handoff-gated (cheap)

### The two-sided coherency fix for low-mht dir_reuse:
- **RELEASE side: `dir_release_invalidate=1`** (handoff-gated, at EX release) → cuts mht=50 loss 18→~2. Cheap-ish (~305s, slightly over budget). Invalidates the RELEASING node's own cache so its next re-acquire cold-reads.
- **ACQUIRE side: `dir_coherent_modify=1`** (xfs_mxfs_dlm.c:1308) — before each addname, plain-read every dir DATA block and invalidate if disk has MORE dirents than cached (peer adds), SKIPPING own committed-unwritten work (no clobber). PROVEN: `mht=50 + dir_release_invalidate=1 + dir_coherent_modify=1` ran **failrounds=0 through round 6** (the residual single-dirent loss looked FIXED).
- **BUT dir_coherent_modify is ~5× TOO SLOW** (~60s/round vs ~13s; 24 rounds would be ~24min) — it re-reads EVERY dir block before EVERY addname = O(blocks × creates), NOT handoff-gated. RULE-0 FAIL. Killed mid-run.

### THE INSIGHT (path to the criterion): the correctness fix = invalidate the modifier's cached dir blocks so addname's bestfree reflects peer adds. dir_coherent_modify does this RELIABLY but per-addname (slow). dir_release_invalidate does it handoff-gated (fast) but only on the releaser's self-reacquire (misses the cross-node acquirer → residual 2). 
### NEEDED: a HANDOFF-GATED acquire-side coherent invalidation — fire dir_coherent_modify's per-block content-compare+invalidate ONCE per cross-node dir-EX acquire (gen bump / P63-HANDOFF), NOT on every addname. That gives dir_coherent_modify's reliability at dir_release_invalidate's cost. Implementation: gate the mxfs_dir_coherent_modify scan on (i_dlm_dir_gen > i_dlm_dir_loaded_gen) || MXFS_IF_DIR_RELOAD, and clear the trigger after, so it runs once per peer-modify episode. The existing gen-invalidation (xfs_da_btree.c:3176) is handoff-gated but uses XBF_TRYLOCK-SKIP + gen-stamp (lossy) — the content-compare (count fingerprint) in dir_coherent_modify is the RELIABLE signal; marry the two.

### REFUTED this session (all make it worse or too slow): force_coherent=1 (24/24), dir_release_fua_write=1 (2→4), trylock-retry+MXFS_IF_DIR_RELOAD backstop (2→11), dir_coherent_modify per-addname (correct but 5× slow). Common theme: aggressive/ungated reload clobbers OR is too slow; the fix must be handoff-gated AND surgical (skip own undurable work).

### Build 15447D0C KEEP (inode-skip fix, mht default 300, all dir_release/coherent params default off). Also still open: the dir-block FUA re-read thrash (~336×/block, DIRINVAL=0, eviction-based) hurts speed at all mht — orthogonal. See [[sess19run-PROGRESS-dir-release-levers-cut-lowmht-loss-18to4]], [[sess19run-FULL-8tcp-suite-13of17-mht-tradeoff-is-core-blocker]].
</body>
