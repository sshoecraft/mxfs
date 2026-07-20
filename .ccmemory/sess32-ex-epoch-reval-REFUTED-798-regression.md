---
name: sess32-ex-epoch-reval-REFUTED-798-regression
description: sess32 REFUTED: EX-side epoch revalidation (build 5BD1CE5F, dir_tenure_evict+dir_evict_prior_tenure) made loss WORSE (798/800). Keep-guard bypass los…
metadata:
  type: project
---

## sess32 — EX-side epoch revalidation REFUTED (made it worse)

### Result
Build 5BD1CE5F + `dir_tenure_evict=1 dir_evict_prior_tenure=1` (EX-side read revalidation engaged, P16-PREREAD-EPOCHSTALE confirmed firing under EX): clean 6-iter run → iter1 PASS, **iter2 FAIL readdir=798/800 at ROUND 1** (all 8 nodes). 798 = TWO entries lost (baseline keeper loses ONE = 799). So the fix REGRESSED.

### Why it's worse
`dir_evict_prior_tenure` (epoch_stale) BYPASSES the in-AIL undestaged keep-guard (xfs_da_btree.c:3373). Under EX it invalidated a block holding OUR own un-destaged dirent → re-read from disk dropped our entry from b_addr while the AIL item still destages it → lost our own entry too (the sess43 hazard, exactly what GPT warned in point (d)). The safe variant (dir_tenure_evict alone, honors keep-guard) left WMneeded firing (didn't catch it) — because the stale base at RMW-read is itself in-AIL (our work), not a clean block.

### KEY unresolved contradiction (for next session)
P-WMERGE proves: at destage we hold EX, in-core b_addr LACKS the peer's f4, disk (plain-read) HAS f4. Under EX serialization, f4 was durable BEFORE we acquired EX (peer published pre-release). So a post-acquire FUA re-read (FUA is coherent on this LIO target — xfs_mxfs_dlm.c:17904) WOULD get f4. Yet b_addr lacks it => the block was served as a CACHE HIT (no read), cached in a PRIOR tenure (pre-f4), and NOT invalidated at acquire. acquire-evict (mxfs_dir_drain_evict_data_blocks) shows blocks done=0 (it DID evict) — so the surviving stale block likely came via a FAST-PATH EX upgrade (PR/NL->EX) that SKIPPED drain_evict, OR was re-cached stale mid-tenure.

### NEXT SESSION leads (RULE 4)
1. Verify whether a fast-path EX (re)acquire / PR->EX upgrade SKIPS mxfs_dir_drain_evict_data_blocks (instrument: does drain_evict run for every EX grant that precedes a losing RMW?). If yes → run acquire-eviction on ALL EX acquisitions (incl upgrades) = GPT's "acquire=invalidate" done right (clean blocks only, honor keep-guard).
2. OR release-side: ensure EX release waits AIL-empty for dir blocks (GPT: never let dirty=0/in_ail=1 survive a handoff).
3. Do NOT bypass the in-AIL keep-guard under EX (proven harmful, 798).

### Code state: xfs_da_btree.c EX-reval change is INERT at default (dir_tenure_evict=0 → original behavior); keeper 37A37B10-equiv preserved. reconcile (dir_stale_reconcile) also default-off + structurally inert. Build 5BD1CE5F. Cluster: reboot to clear params. CRITERIA NOT MET. [[sess32-FIX-ex-side-epoch-revalidation-build-5BD1CE5F]] [[sess32-PROVEN-owned-ex-disables-gen-mechanism-wmerge-root]]
</body>
