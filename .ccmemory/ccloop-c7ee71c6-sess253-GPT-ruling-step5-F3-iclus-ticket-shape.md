---
name: ccloop-c7ee71c6-sess253-GPT-ruling-step5-F3-iclus-ticket-shape
description: sess253 RULE-5 ruling (step 5 F3): keyed per-cluster {daddr} write accounting (no device-wide wait), generation-based flush proof, ticket-status enum…
metadata:
  type: project
---

# sess253 GPT ruling — step 5 (F3) implementation shape

Full text in sess253 transcript. Verdicts on my proposed shape:

- **A (amend)**: separate ICLUS class from dir counter = correct, but the release
  WAIT must be keyed by stable cluster identity {daddr}, NOT the device-wide
  aggregate (leaked/busy counter blast radius). Device-wide atomic is
  telemetry-only. Keyed entries: inflight + submit/complete generations +
  waitqueue, lifetime independent of the xfs_buf (do NOT free entries while a
  proof could span — freeing+recreating aliases generations; keep until
  unmount). Count every xfs_inode_buf_ops home write incl. retry paths; retain
  one logical-write token through resubmissions (no transient zero).
- **B (amend substantially)**: dirty-recheck alone misses submit+complete
  cycles between flush and recheck. Proof = settle → keyed inflight 0 →
  obligations 0 → capture generation → issue/join real flush → on completion
  verify inflight 0 + generation UNCHANGED + not dirty → final pre-CAS
  tripwire. Generation changed → bounce with NEW flush ticket. TRYLOCK failure
  = UNKNOWN (not clean): bounded retry, else proof_failed. proof_failed while
  gate off: telemetry release, never PROVED (rel_state stays DRAINING →
  cas_unproved counts it).
- **C (approve+amend)**: durable_fepoch stamp valid; write stamp+durable_seq
  coherently (ordering/seqlock); fua=0 ticket = flush_epoch strictly > stamp
  (epoch only advances on real successful flush in that mode); final pre-CAS
  must re-validate ticket covers CURRENT durable_seq. fua=1&&!protected:
  keep behavior BUT record NO_DURABILITY_DOMAIN ticket status, cas_noticket,
  and the cert must not read as complete proof (proof_complete=0).
  target_cache_protected is a domain declaration, never a flush fact.
- **D (amend)**: ticket_status enum {REAL_FLUSH_COMPLETED, TARGET_CACHE_PROTECTED,
  NO_TICKET/NO_DOMAIN, FLUSH_FAILED, STALE_TICKET} + record seq covered, stamp
  epoch, observed epoch, final keyed inflight, final gen, tripwire result.
- **E (keep 0)**: F3_COMPLETION_PROOF_READY stays 0 until F3 failures BLOCK
  release (step 6 defer worker). Telemetry-implemented ≠ ready.
- **F (approve)**: direct blkdev flush in fua=0 mode, no locks held across the
  wait, coalescing later. Coalescer may only join flushes submitted AFTER the
  captured completion set.

Hazards: quiescence mandatory (gen/tripwire detects); final pre-CAS tripwire
invalidates cert on any change; distinguish not-incore vs lock-unavailable;
fault hooks for stuck completion / completion-around-flush / trylock-fail /
flush-fail / accounting leak.
