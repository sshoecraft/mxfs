---
name: sess16run-epoch-stamp-too-sparse-cachehit-blocks-unstamped
description: sess16(ccloop) prior-tenure evict override (dir_evict_prior_tenure, build EA41172C) ENGAGES but only 10-20x vs 6000 evicts — b_mxfs_dir_epoch is stam…
metadata:
  type: project
---

## sess16 (ccloop) — the epoch-stamp is too sparse to cover cache-hit staleness

### Test (build EA41172C, mht=50 dirwr=1)
Added acquire-side PRIOR-TENURE override in mxfs_dir_evict_data_blocks (param dir_evict_prior_tenure): force-evict a kept block whose b_mxfs_dir_epoch (non-zero) lags i_dlm_dir_valid_epoch (= prior-tenure stale base; safe per serialized-grants + Inv-1 drain). It ENGAGED: P16-PRIORTENURE-EVICT fired 10× (test2), 20× (test4). But dir_reuse STILL FAILED 0/8 (node1_f1/node5_f40).

### Root of the override's insufficiency (the final mechanistic gap)
P68-EVDECIDE showed ~6000 evict decisions, 3720 KEPT undurable (stale bases). But P16-PRIORTENURE fired only 10-20× → the override covers <1% of kept-stale blocks. Reason: `b_mxfs_dir_epoch` is stamped ONLY on a genuine fresh DISK read (dir_stamp_fresh in xfs_da_read_buf) and the gated-off postread re-read. The dominant kept-stale blocks are CACHE HITS (block0 is read constantly without re-reading) → their b_mxfs_dir_epoch stays 0 → the `epoch != 0` safety guard (required to avoid resurrection on ambiguous unstamped buffers) SKIPS them. So the epoch-stamp signal is too SPARSE to identify most stale cache-hit bases.

### The fundamental issue (now fully characterized)
Tracking "which epoch a buffer's CONTENT corresponds to" fails because buffers are reused via CACHE HIT without re-reading, and you cannot safely stamp a cache-hit with the current epoch (that marks stale content current — the lossy-dir_gen bug). The ONLY robust models:
1. **GPT tenure model (part 4)**: stamp every buffer with the tenure it was COHERENTLY read under; on EVERY read (cache hit included) CHECK buf.tenure == inode.current_tenure, else force re-read+restamp; inode.tenure bumped on every below-PR transition. The CHECK (not the stamp) is what catches cache-hit staleness. Needs reliable per-inode tenure that bumps on every EX/PR→NL.
2. **Release-side invalidate** that SURVIVES the re-populate window (GPT parts 1+2 REVOKING fence): the releasing node invalidates its buffers AND blocks re-population until re-acquire. dir_release_invalidate alone failed because the node re-reads (re-populates clean) between release and next-modify, then a peer modifies, then it cache-hits stale (sess69 caveat 2).

### NEXT SESSION
Implement model 1 properly: in xfs_da_read_buf PRE-read block (the un-gated invalidation path, NOT the gated postread), for a multinode non-root dir DATA-fork CACHE HIT, if the buffer's coherent-tenure stamp != the inode's current tenure → clear XBF_DONE (force re-read), where "current tenure" = a per-inode counter bumped reliably on every grant drop below PR (wire at the EX/PR→NL release sites + bast_process). Stamp the buffer's tenure ONLY when read fresh under the grant. This makes a cache-hit on a buffer from a prior tenure MISS → re-fetch peer's image. Override the undestaged keep-guard ONLY when tenure-stale (safe: tenure advanced ⇒ we dropped below PR ⇒ our work was drained). Validate at dirwr=0 across ~5+ runs (flaky race). Watch RULE-0 timing (extra re-reads) + resurrection canaries.

### Build EA41172C = safe baseline: ALL session params default OFF (dir_evict_prior_tenure=0, dir_nxshrink_fence=0, dir_postread_reread=0, P16 leaf-refresh removed) + KEEP MX-DOUBLEGRANT auditor (logging) + b_mxfs_dir_epoch field/stamps (inert, read only by gated-off code). Default-config behavior == 48C6A95E baseline. Criterion NOT met — marker not written. See [[sess16run-acquire-side-refresh-cannot-work-must-be-release-side]] [[sess16run-GPT-design-tenure-scoped-dirbuf-coherency-FIX]].</body>
