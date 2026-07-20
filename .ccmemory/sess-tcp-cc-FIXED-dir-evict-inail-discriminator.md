---
name: sess-tcp-cc-FIXED-dir-evict-inail-discriminator
description: FIX (build 1ED7A5FD): crash_consistency dir-entry-visibility FIXED — mxfs_dir_evict_data_blocks (reader/consumer_refresh) used coarse XFS_LI_IN_AIL→s…
metadata:
  type: project
---

## FIX (build `1ED7A5FD7AA0DD081826A62`, KEEP) — crash_consistency dir-entry visibility.
Root proven in [[sess-tcp-cc-ROOT-dir-entry-visibility-lag]]: test1 stat→ENOENT on node2's
later-created shared-dir entries after a barrier+drop_caches.

ROOT SITE: `mxfs_dir_evict_data_blocks` (xfs/xfs_mxfs_dlm.c ~L1864) — the READER-path eager
dir-block evictor called by `mxfs_dlm_dir_consumer_refresh` (run at top of xfs_lookup/readdir).
It computed `undurable` with a COARSE `XFS_LI_IN_AIL`→undurable term and SKIPPED any in-AIL
block (P-EVICT-SKIP). But a dir block whose last local mods are already write-submitted merely
LINGERS in the AIL until the log tail advances — skipping it left THIS node serving its own
stale base, missing a peer's newer dirents. The MODIFY-path sibling (sess101/v0.5.2, ~L2447)
AND the lazy xfs_da_read_buf hook (sess133) already use the proven cross-node-safe discriminator
`mxfs_dir_buf_is_undestaged(bp)` (= `b_mxfs_logged_seq != b_mxfs_written_seq`, plus pinned);
the reader-path evictor was LEFT BEHIND on the old coarse check.

FIX: changed `undurable` to `dirty || pinned || _XBF_DELWRI_Q || !XBF_DONE ||
(in_ail && mxfs_dir_buf_is_undestaged(dbp))` — i.e. an in-AIL-but-destaged block is now EVICTED
(force FUA-refetch of the peer's superset image) instead of skipped. Mirrors the modify-path
exactly. Low regression risk: genuinely committed-unwritten work (logged!=written) still kept.

## VALIDATION (full `./run.sh 2 tcp`):
- run1: crash_consistency 2/2 PASS (was reliably FAIL in-suite). cache_coherency FAIL 0/2 — but
  cache_coherency passes 3/3 STANDALONE on this build (NOT a regression; known flaky barrier
  desync, [[sess-tcp-flaky-confirmed-stall-is-blocker]]).
- run2: 15/16 — crash_consistency PASS, cache_coherency PASS; ONLY fail = tcp_dlm_scaling 1/2.

## REMAINING for 16/16 (both flaky, need same-run pass):
1. **tcp_dlm_scaling ~50%** = the proven TCP DLM double-grant ([[sess-tcp-tcp-dlm-scaling-DOUBLE-GRANT-proven]]).
   Now the dominant blocker. Fix = grant-generation token (re-affirm-not-remove+promote on
   same-sender re-request; gen-checked release ignores stale; client REJECTS unsolicited grant
   after release + sends RELEASE to avoid phantom-hang). Design fully worked out this session.
2. **cache_coherency occasional** = intermittent >30s FS-op stall → MQTT barrier desync cascade
   (fresh-mount, position 2). Logic correct (3/3 standalone). Same stall class as the others.

Fallback build if DLM fix regresses: 1ED7A5FD (this, cc fixed, 15/16) or 30D3C28E (pre-cc-fix).
