---
name: sess23-gpt5.5-grant-generation-coherency-design
description: sess23(ccloop): GPT-5.5 architectural design for dir_reuse readdir=799 — master-authoritative EX grant-generation stamped at release drain fence; KEE…
metadata:
  type: project
---

## sess23 (ccloop) — GPT-5.5 design for the dir_reuse content-divergent clobber

Consulted GPT-5.5 (RULE-5 justified: proven instrumented diagnosis + many distinct refuted approaches + architectural question). Verbatim-distilled design:

### The correct invariant
"A dir DATA buffer may be an RMW base only if its bytes correspond to the CURRENT DLM EX tenure, or it was dirtied during this same continuous EX tenure. A buffer from an OLDER EX tenure must not be an RMW base after any FOREIGN EX grant." KEEP only if dirtied in the current continuous EX grant-gen; do NOT key KEEP on `in_AIL && logged_seq>written_seq` (AIL bookkeeping is NOT a durability/ownership oracle — that is the bug).

### Decision rule at re-acquire (after a foreign EX held it)
- buffer modified in CURRENT tenure → KEEP
- buffer dirty/pinned/delwri/in-flight from BEFORE the handoff → Inv1 VIOLATION → wait or shutdown (should be impossible)
- else → INVALIDATE (refresh), EVEN IF AIL says undestaged

### Why master grant-generation > the refuted in-core epoch
The epoch failed because it is local cache state (can be stamped on stale bytes / re-stamped by a bad read path / doesn't encode a real cross-node happens-before). A master grant-gen is tied to serialized ownership transfer. Required properties: master-authoritative; monotonic per inode-lock resource; incremented on every EX ownership change; returned SYNCHRONOUSLY in the grant reply (not async BAST/AST); ORDERED AFTER the releasing node's drain; invalidated on DLM recovery (include a resource incarnation); resource key must include inode allocation incarnation (the test REUSES the dir inode#+daddrs).

### Main failure mode to avoid (GPT §5)
Granting the next EX BEFORE the previous owner's data is durable on the LUN → acquirer reads pre-peer image → RMW clobber. The release path must: stop new local dir mutations → commit+wait txns → wait unpin → write dirty/delwri dir blocks → wait write completion → flush bdev → STAMP release-gen/destaged → ONLY THEN complete the DLM unlock/downgrade. (Also: no future AIL push may write the old image after release — GPT §9.5.)

### Why "different node held EX since" UNDER-FIRES on TCP (GPT §6)
Edge/BAST/previous-owner-based detection misses: (1) voluntary release → peer acquires with no BAST to us; (2) only "previous owner" recorded → misses intermediate owners; (3) TCP per-connection ordering ≠ global; (4) cached EX→PR→EX / EX→NL→EX satisfied locally without a master round-trip. FIX: master keeps `ex_seq` + `last_ex_seq_by_node[]`; answer "did any node != me get EX after my last seen seq?"; return (resource_incarnation, current_ex_seq, foreign_since) synchronously. Prefer FALSE POSITIVES (extra reads) over false negatives (durable lost dirents).

### Why release-side invalidation SHUT DOWN (GPT §8) — confirmed sess23
Forcibly clearing XBF_DONE / staling a buffer at release while XFS still holds a live log item / AIL membership / callbacks / delwri refs trips verifier/AIL assertions → shutdown. "Safe for MXFS coherency" ≠ "safe for XFS buffer/log lifecycle." PREFER: release-side durable STAMPING (just set fields) + acquire/RMW-side hard refresh under buffer lock based on the grant-gen. sess23 CONFIRMED: the read-path epoch_stale (clears XBF_DONE on in-AIL during reads) is what shut down dir_evict_prior_tenure; the modify-evict (under our own EX) is safe.

### Why logged_seq>written_seq persists after a release drain (GPT §9)
9.1 written_seq advanced on some write paths but not all → lags. 9.2 I/O completion/iodone/unpin/delwri not fully waited. 9.3 buffer RELOGGED after the drain scan (drain not a true quiescence point). 9.4 AIL membership ≠ home-block non-durable. 9.5 a delayed/AIL-push of the old image can fire AFTER release. FIX: at the durability fence, authoritatively `written_seq=logged_seq` + clear undestaged under buffer lock; prevent new mutations + wait all active dir txns BEFORE the scan.

See [[sess23-tenure-evict-progress-and-gpt-grant-gen-design]] for what was built/tested (build 0EA92470, default-off dir_tenure_evict, gets to ~1 residual entry, no shutdown).
