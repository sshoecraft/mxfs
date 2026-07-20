---
name: sess23-fua-disable-refuted-residual-needs-generalized-probe
description: sess23(ccloop) FINAL: fua_disable=1+dir_tenure_evict=1 REFUTED (flaky, r21+r22-24 cascade — fua_disable catastrophic on LIO as documented). Best conf…
metadata:
  type: project
---

## sess23 (ccloop) FINAL — param space exhausted; residual needs direct instrumentation

### fua_disable REFUTED (combination)
`dir_tenure_evict=1 fua_disable=1`: flaky (one fluke PASS, then r21 loss + r22-24 got=0 CASCADE). The code comments (xfs_mxfs_dlm.c:16996, 17052) document WHY: on the LIO target, plain bio reads are per-initiator-cached and STALE across nodes; FUA reads (READ(16) FUA) pierce to the COHERENT shared target and are REQUIRED. fua_disable=1 alone = dir_reuse 0/400 catastrophic. So FUA reads get CURRENT data on LIO — my earlier "FUA reads stale platter" hypothesis is REFUTED (that was the SCST-target rationale, not this LIO cluster). Do NOT pursue fua_disable.

### Best config (carry forward)
Build **B17FED9A**, `dir_tenure_evict=1` (default FUA): dir_reuse 8/tcp = FLAKY PASS (clean 8/8 once; else ONE random-entry loss; NEVER a cascade/shutdown). dir_tenure_evict default-OFF in the build → keeper-inert.

### The residual is genuinely subtle — all of these are TRUE simultaneously:
- FUA reads get CURRENT shared-target data (LIO coherent, proven by fua_disable being catastrophic).
- The release fence (xfs_mxfs_dlm.c ~6981-7027) loops draining (log_force SYNC + ail_push_ag_sync + mxfs_dir_flush_data_blocks) until `!in_ail && !pinned && data_durable`, THEN unlocks → dir blocks landed before handoff (Inv 1 honored).
- ex_pop ≤ 1 → single holder, NO double-grant.
- My modify-evict syncs valid_epoch=master and evicts prior-tenure blocks (b_epoch<valid_epoch) → FUA-refetch current.
Yet a single entry is still durably clobbered ~1/run by comm=bash (the RMW). The epoch model says the clobbered block has b_epoch==valid_epoch (read THIS tenure) so it's NOT evicted — but if FUA gets current data, that read shouldn't be stale. The contradiction means the base staleness arises in a window the epoch can't see (e.g. an owned_ex CACHE-HIT read — owned_ex skips the read-time invalidation, xfs_da_btree.c:3154/3176 — that serves a cached XBF_DONE buffer whose b_epoch==valid_epoch but whose CONTENT predates a peer change the epoch didn't capture, OR a free/leaf-index slot-selection divergence).

### NEXT SESSION — decisive instrumentation (build it first)
P61-BLK0 only scans "node1" bytes (residual victim is usually node3/5/6/7) → useless for the residual. Build a GENERALIZED probe at the owned_ex dir-DATA read in xfs_da_read_buf (instr-gated): FUA-read the same daddr from the LUN, parse BOTH in-core and disk dirents, and log when the IN-CORE (RMW base) block is MISSING any dirent name present on disk (content-subset = stale base), with cache-hit-vs-miss + b_epoch + valid_epoch + master_epoch + comm. Run dir_tenure_evict=1 + that probe; at the residual fail round, it pinpoints (a) was the base a stale CACHE HIT (owned_ex skip) → fix: force a coherent re-read at the owned_ex RMW read too; or (b) content matched in-core==disk → the loss is WRITE-side (free-slot/leaf reuse) not read-base. Then fix accordingly, make dir_tenure_evict default-ON, validate full 8/tcp + 1/2/4 tcp.

See [[sess23-BREAKTHROUGH-master-epoch-sync-flaky-pass]] [[sess23-residual-is-single-holder-not-doublegrant]] [[sess23-gpt5.5-grant-generation-coherency-design]].
