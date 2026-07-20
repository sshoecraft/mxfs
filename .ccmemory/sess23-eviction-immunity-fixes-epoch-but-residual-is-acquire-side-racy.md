---
name: sess23-eviction-immunity-fixes-epoch-but-residual-is-acquire-side-racy
description: sess23(ccloop) build 18064D1D: dg_shadow eviction-immunity (evict coldest-by-grant_count, hot dir never evicted) MAKES THE EPOCH RELIABLE (advances t…
metadata:
  type: project
---

## sess23 (ccloop) — eviction-immunity makes the epoch reliable, but the residual is acquire-side-racy

### KEEP: dg_shadow eviction-immunity (build 18064D1D, default-ON, low-risk, correct)
dlm/dlm.c: added `grant_count` to dg_shadow_ent; eviction now picks the COLDEST inactive slot (lowest grant_count, tie-break oldest seq) instead of oldest-seq. The hot shared-dir inode (granted ~800x/round) gets a huge grant_count → NEVER evicted → its handoff epoch is preserved. VERIFIED: P64-MASTER-HANDOFF fired 570x and the master epoch advanced to 41 (previously suspected stuck near 0 from LRU eviction). This is a strict improvement (protects hot resources from LRU recycle) and should be KEPT regardless — but needs full-suite (1/2/4/8 tcp) regression validation since it's not param-gated.

### But it does NOT fix dir_reuse 8/tcp
With the reliable epoch + dir_tenure_evict=1 (modify-evict + master-sync + 9.1 + read-path tenure_stale all firing), dir_reuse 8/tcp STILL FAILS flaky: r21 lost 15 SCATTERED .md5 entries (node5: f27,f39-42,f44,f45; node7: f6,f7,f12,f13,f15,f17,f25,f26 — multiple blocks, two nodes), r24 lost node1_f42.md5 (1). No cascade. Variable magnitude (1-17 entries) across runs.

### CONCLUSION — the read/acquire-side invalidation is structurally racy
Even with the epoch advancing reliably and the invalidation (P23-TENURE-EVICT, tenure_stale) firing, the clobber persists. More invalidation did not converge it. This matches the documented sess16 conclusion [[sess16run-acquire-side-refresh-cannot-work-must-be-release-side]]: invalidating + re-reading the RMW base at acquire/read time is structurally racy — the re-read opens a TOCTOU window, and "the peer's newer write is often not yet on the LUN at our evict moment." The whole epoch/evict/read-invalidation family (sessions of work) treats the SYMPTOM (stale cached base) rather than the cause.

### NEXT SESSION — pivot to the RELEASE side (with the now-reliable epoch as a tool)
GPT-5.5's core recommendation [[sess23-gpt5.5-grant-generation-coherency-design]]: the fix is release-side ordering, NOT acquire-side refresh. Concretely, with the reliable epoch now available:
1. The releasing EX holder must make its dir-block writes DURABLE+VISIBLE on the shared LUN before the DLM master grants EX to the next node (close the grant-before-durable window). The release fence (xfs_mxfs_dlm.c ~6981-7027) drains before unlock, but verify the GRANT path waits for the release ACK and that a downgrade (EX→PR/NL) path doesn't skip the drain.
2. Consider serializing the dir-EX handoff so the next holder cannot begin its addname RMW until the prior holder's commit is durable (tenure-level serialization, GPT "serialize tenure not epoch").
Keep dir_tenure_evict default-OFF (flaky, doesn't converge). Keep the dg_shadow eviction-immunity (default-on, correct).

Builds: 18064D1D = 7EDF3278 (dir_tenure_evict read-path) + dg_shadow eviction-immunity. See [[sess23-ROOT-dg-shadow-epoch-unreliable-lru-evicts-hot-dir]] [[sess23-BREAKTHROUGH-master-epoch-sync-flaky-pass]].
