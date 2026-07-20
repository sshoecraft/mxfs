---
name: sess23-STATE-keeper-18064D1D-1and2-tcp-pass-8-is-lone-blocker
description: sess23(ccloop) STATE: keeper 18064D1D (D589FA5F + dg_shadow eviction-immunity → reliable dir epoch). VALIDATED 1/tcp=16/16, 2/tcp=17/17, 4/tcp dir_re…
metadata:
  type: project
---

## sess23 (ccloop) — consolidated state at relay boundary

### New keeper: build 18064D1D (KEEP — strict improvement over D589FA5F)
Prior keeper + **dg_shadow eviction-immunity** (dlm/dlm.c): eviction recycles the COLDEST (lowest grant_count) inactive slot, so the hot shared-dir inode is never LRU-evicted → its cross-node handoff epoch stays reliable (was resetting to 0 under ~800-file-inode churn; now P64-MASTER-HANDOFF ×570, epoch→41). Default-on, low-risk (worst case = old behavior; cannot cause false handoff/corruption). Also carries `dir_tenure_evict` param (DEFAULT-OFF, keeper-inert): acquire/read-side coherency attempt (modify-evict + master-epoch sync + GPT-9.1 release undestaged-clear + read-path tenure_stale).

### VALIDATED this session (build 18064D1D, DEFAULT modargs)
- **1/tcp = 16/16 PASS**
- **2/tcp = 17/17 PASS** (full suite)
- **4/tcp dir_reuse_coherency = 4/4 PASS** (and prior keeper was 4/tcp full 17/17; eviction-immunity is strict improvement → 4/tcp full very likely 17/17 — re-run full to confirm next session)
- => the dir_reuse clobber is **8-NODE-SPECIFIC** (a contention threshold; ≤4 nodes pass cleanly).

### LONE BLOCKER: 8/tcp dir_reuse_coherency (flaky)
8-node concurrent same-dir create → durable content-divergent dir-DATA-block dirent clobber (1-17 entries lost, no cascade/shutdown). PROVEN: acquire/read-side invalidation is structurally racy (sess16 re-confirmed) — invalidating+re-reading the RMW base opens a TOCTOU window; more invalidation (reliable epoch + dir_tenure_evict) did NOT converge it.

### NEXT SESSION — RELEASE-side fix (proven-correct direction)
Per GPT-5.5 [[sess23-gpt5.5-grant-generation-coherency-design]]: ensure the releasing EX holder's dir writes are durable+VISIBLE before the master grants EX to the next node (close grant-before-durable), and/or tenure-level handoff serialization (next holder can't begin addname RMW until prior commit durable). Audit: does the GRANT path wait for the release ACK? does a downgrade EX→PR/NL skip the release fence's drain? late-xfsaild-ABA-push (GPT §9.5)? The release fence is xfs_mxfs_dlm.c ~6981-7027 (drains before unlock). The scattered multi-node loss (r21: node5+node7 .md5) reduces to the same stale-base-RMW under EX serialization (a node reads a base missing the prior holder's just-released entry).

Detail: [[sess23-ROOT-dg-shadow-epoch-unreliable-lru-evicts-hot-dir]] [[sess23-eviction-immunity-fixes-epoch-but-residual-is-acquire-side-racy]] [[sess23-BREAKTHROUGH-master-epoch-sync-flaky-pass]] [[sess23-residual-block-bypasses-evict-needs-ownedex-read-coverage]].
