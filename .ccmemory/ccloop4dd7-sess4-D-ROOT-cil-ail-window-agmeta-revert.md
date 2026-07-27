---
name: ccloop4dd7-sess4-D-ROOT-cil-ail-window-agmeta-revert
description: sess4 root #5 PROVEN+FIXED v0.11.63: CIL→AIL async window made committed-unwritten bnobt look destaged → P117 stale-clean at deferred AG unlock → mid…
metadata:
  type: project
tags: [ccloop-4dd7, root-cause, cil-ail-window, bnobt-cntbt, ag-meta]
---

# ccloop-4dd7 sess4 root #5 — CIL→AIL-window AG-meta revert (PROVEN b62r4, FIXED v0.11.63 = 5DEE3351)

## The braid resolved (b62r4 `i != 1` xfs_alloc_fixup_trees, AG2 [11,1])
Full chain, all probes on test1 unless noted:
1. test2 delalloc-allocated [11,1] into ino 2097281's file at 38.444; test2's platter pair consistent (nr=1/nr=1) at 38.51; test2 released AG2 38.729 clean.
2. test1 acquired AG2, cold-read the correct pair 38.7238, and its rm (LEGAL — full lifecycle create(test2)→write→rm(test1); P34D adopted the current dinode) freed [11,1] (free#1, .7238) then [12,1] (free#2, .727).
3. free#1's tx committed → **deferred AG2 unlock at commit** ran the release-path P117-AGMETA-STALE-CLEAN, which judged the bnobt "clean" during the **async CIL→AIL window** (commit-record callback had unpinned the BLI but AIL insertion wasn't visible: pin=0, has_bli=1, li_empty=1, not-in-AIL) and cleared XBF_DONE.
4. free#2's btree read 3ms later cold-read the LAGGING platter bnobt over the committed-unwritten free#1 insert — `P110-BIO-OVER-LOGGED daddr=4186456 ops=xfs_bnobt pin=0 li_empty=1 has_bli=1 undest=0 — read proceeds` at .727064, 12µs after P145-FREE [12,1]. mxfs_buf_is_undestaged returned FALSE (its in-AIL clause missed the window) so the v0.11.61 read-guard let the DMA through.
5. free#2 then computed neighbors on the REVERTED base: [11,1] missing → right-merge [12,1]+[13,261640] → **[12,261641]** in bnobt (nr=1) while the cntbt (not re-read) kept [11,1] → the corrupt pair (bnobt {[12,261641]} / cntbt {[11,1],[12,261641]}).
6. Pair written mixed by both nodes' xfsaild over the next 400ms; test2's next allocator cold-read it and died (39.2926).

## FIXES (v0.11.63)
1. `mxfs_buf_is_undestaged` (xfs_mxfs_dlm.c ~25510): a live BLI that is unpinned and NOT in the AIL is
   the CIL→AIL transition = committed-unwritten → return TRUE (was false). BLIs are freed at write
   completion, so BLI-present ⇒ not-yet-written-since-last-log. This auto-arms the P110 read-guard for
   the window.
2. drain_meta_buffers skip arm (~28430): only `!pinned && !bip` takes the clean-skip/P117 stale-clean
   path; BLI-attached falls through to the blocking-lock + xfs_bwrite path (like pinned).

## GPT consult (RULE 5, gpt-5.6-sol) — key rulings kept for later hardening
- Free-intent owner tagging (ino/gen/fileoff/DLM-epoch), iext load provenance, pre-bunmapi generation
  revalidation + QUARANTINE (never skip-free after fork mutation), debug shared reverse-owner table.
- Correct release barrier: quiesce → xlog_cil_force_seq(exact seq) → commit-completion wait → sync AIL
  push → per-buffer locked census (not unlocked walk) → device flush → unlock. li_lsn compare only
  valid same-journal.
- NOTE: the illegal-free hypothesis DISSOLVED (the rm was legal); the b62r4 root was entirely the
  window+stale-clean+cold-read revert.

## State
Ladder on v0.11.62 reached 3/5 (b62r1-3) before b62r4. v0.11.62 = ECD8EA42 carried root #4 fix
(IOLOCK rwsem-first, see sess4-C memory). Ladder resets b63r1 on v0.11.63 = 5DEE3351.
P144/P145 probe caps (12000/8000) hampered forensics — consider raising for bnobt/cntbt only if the
family recurs. Open: task #2 (b55r2 platter regression — plausibly THIS root: mid-image writes +
revert = platter regression to older image; watch for recurrence), task #5 (PVE), task #6 (b58r1
stall — fix #4 in v0.11.62 addresses the proven b61r6 shape; needs clean soak to close).
