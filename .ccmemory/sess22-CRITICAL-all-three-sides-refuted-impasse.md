---
name: sess22-CRITICAL-all-three-sides-refuted-impasse
description: sess22(ccloop) CRITICAL IMPASSE MAP for readdir799: ALL THREE sides refuted — WRITE-side suppression (sess11/23/69/sess22, corrupts/shuts down), RELE…
metadata:
  type: project
---

## sess22 (ccloop) — readdir=799 IMPASSE: all three sides refuted; do not re-try the obvious

Before implementing ANY readdir=799 fix, read this. The naive fixes on every side are PROVEN to fail/corrupt:

### WRITE-side (suppress the clobbering dir-block write): REFUTED ×4
- dataclobber>=2 (sess11/69): readdir=0 (suppresses legit removes).
- dir_ex_write_guard EX-held variant + dir_stale_incarn_skip (sess22): readdir 474/800 + 4-node SHUTDOWN.
- Root reason: a stale-base clobber write is BYTE-INDISTINGUISHABLE from a legit remove/conversion at submit time (sess69). NO write-side guard works.

### RELEASE-side (invalidate cached dir blocks on EX release): REFUTED
- dir_release_invalidate=1 (sess22): readdir 783/793 FAIL + 2-node shutdown.

### ACQUIRE-side (force-evict/refresh stale base before RMW): REFUTED (sess16, code comment xfs_mxfs_dlm.c ~2997-3005)
- A crc/content-differ acquire-side refresh "reverted our own committed-UNDESTAGED work back to disk (RESURRECTION) and REGRESSED mht=300 dir_reuse PASS to 0/8." Also STRUCTURALLY RACY: "the peer's newer write is often not yet on the LUN at our evict moment," so re-reading gets the OLD disk image anyway.
- WARNING: the naive "clear XBF_DONE on any clean DONE block with b_mxfs_dir_gen < i_dlm_dir_gen" (the dir_stale_evict I was about to build) IS this refuted acquire-side refresh. The bgen<dir_gen + clean gate seems safe (clean = no undestaged work) BUT the sess16 racy-LUN problem remains: at evict the peer's write may not be durable yet → re-read = same stale base. Do NOT just re-build it and expect a pass.

### The genuine difficulty (sess16/sess69 synthesis): the loss is a cross-node stale READ-CACHE HIT (fua=0) that poisons the RMW base, but you cannot reliably invalidate it because (a) at acquire the peer's durable write may not be on the LUN yet (racy), (b) at release you can't tell which blocks a future peer will need, (c) at write you can't tell clobber from legit. The in-AIL-undestaged "keep" exception (don't evict our own uncommitted work) is what preserves the stale base, but removing it causes resurrection.

### NOVEL directions for next session (NOT yet tried, think hard):
1. **EX-handoff barrier ordering**: make the RELEASE drain provably land on the LUN (not just submit) BEFORE the DLM grant is handed to the peer, AND make the acquiring peer's first read provably a MISS (hard-invalidate by daddr at grant-receipt, not at acquire-evict) — close the sess16 racy-LUN window by tying invalidation to the DLM grant message, not local buffer state.
2. **Per-block durable epoch on-disk**: stamp each dir block with a monotonic epoch on the shared LUN; a read that finds in-core epoch < a cheaply-readable shared epoch marker forces a miss. (Avoids the racy "is the peer's write here yet" by making staleness self-describing on disk.)
3. **Re-examine whether force_evict actually evicts the stale base**: instrument which exact daddr the clobbering RMW reads its base from, and whether that buffer was force-evicted or a read-cache HIT — confirm the sess69 fua=0 cache-hit on THIS build (post reorder+datascan-heal) before assuming the mechanism is unchanged.

Keeper D589FA5F. See [[sess22-dir-release-invalidate-also-refuted]] [[sess22-REFUTED-exheld-stale-write-suppression-harmful]] [[sess69-TRUE-ROOT-crossnode-stale-readcache-hit-poisons-rmw-base]] [[sess16run-acquire-side-refresh-cannot-work-must-be-release-side]].
