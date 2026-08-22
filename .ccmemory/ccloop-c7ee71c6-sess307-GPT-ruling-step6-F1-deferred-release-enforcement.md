---
name: ccloop-c7ee71c6-sess307-GPT-ruling-step6-F1-deferred-release-enforcement
description: sess307 RULE-5 ruling (step 6 F1): defer on {still_dirty,proof_failed,tripwire} not F2/NO_DOMAIN; knob release_proof_enforce=1; ICLUS per-cluster wor…
metadata:
  type: project
---

# sess307 GPT ruling — build-order step 6 (F1 deferred-release enforcement)

Full text in sess307 transcript. Context: steps 1-5 landed as telemetry
(0.11.510 field-verified, cas_noproof_v2==0/124k). Step 6 makes deferral real.

## The ruling, condensed
1. DEFER predicate = still_dirty || proof_failed || tripwire(after its one
   bounce). NOT the F2-only ticket-absent case under fua_disable=1: that is
   persistence_domain=NO_DOMAIN, persistence_required=false — step 7 policy.
   Snapshot domain policy at mount/tenure; runtime fua_disable change must not
   alter requirement mid-tenure.
2. ONE knob `release_proof_enforce` covering both classes, DEFAULT 1 on the
   verification board (near-zero observed rate ⇒ enforce-off verifies nothing).
   Load-time/read-only after first mount. F*_READY stay hard prerequisites, not
   policy. enforce+not-READY = fail closed. Keep cause-specific counters.
3. ICLUS per-cluster delayed worker + state {ACTIVE,DEMOTING,WEDGED,RELEASED},
   release_epoch (ABA guard — every worker/proof/ticket/CAS bound to it),
   release_started/last_progress. Immediate first attempt, ~25ms retry,
   backoff to 1s max with jitter. Worker enters the NORMAL busy-serialized
   release path (no second CAS path): drain admitted ops, log force if pinned,
   targeted AIL push of cluster buf, retry make_durable, keyed proof, flush
   only after clean, tripwire, CAS only on full proof. No flush-per-tick.
   Disarm ONLY on successful CAS, explicit serialized cancel (epoch++), or
   teardown after safe sync. Never disarm on apparent disk_mode/busy change.
   Lock rules: no state lock across logforce/AIL/IO/flush/CAS; lifetime ref;
   no cancel_sync under a lock the worker needs; reclaim-safe wq.
4. Admission closure REQUIRED in step 6: fast admit + slow acquire require
   state==ACTIVE; new ops park on waitq; admitted ops finish; drain-needed
   internal ops get an explicit token, not a bypass. Waiters wake on release-
   done (retry acquire), valid cancel (ACTIVE), or wedge (-EIO/shutdown).
   Never reopen admission to escape a wedged flush.
   [sess307 adaptation, documented: DEMOTING entered at first DEFERRAL (proof
   failed under ic->busy), not at first BAST — preserves the designed MHT
   tenure-floor batching; pre-attempt window can't race the proof since the
   proof runs under busy and covered_active gates it.]
5. Bounds: WALL CLOCK — 60s without genuine progress OR 300s total DEMOTING.
   Progress = obligation/inflight decrease, unpin, dirty→clean, proof phase
   completed, successful required write/flush. NOT progress: seq/gen mere
   change, another BAST, failed flush, retry start, new dirtiness. Permanent
   IO error may wedge immediately. On wedge: WEDGED atomically, NEVER CAS,
   admissions stay closed, wake waiters terminal error, pr_err + cert snapshot
   + one-shot fence notification, force-shutdown the mount ONCE — but the
   wedged grant must NOT be released by unconditional release_all at teardown:
   narrow guard = wedged resource stays pinned until valid proof or node
   fenced (peers' death detection/recovery machinery takes over).
6. -EDEADLK stale-selfclear: NO exemption. Same DEMOTING/worker/bounds; the
   acquire path waits on state/epoch or returns controlled retry; suppress
   repeated selfclear per release_epoch; terminal error once on wedge.
7. relbar proof_failed exit: flip to existing DEFER/strand channel
   (bast_pending + MHT dwork), same bounds/wedge. Before F1_READY+F3_READY=1:
   worker holds lifetime ref; stale work rejected by epoch; no cross-tenure
   ticket reuse; permanent-vs-retriable flush error classification; waiters
   get error on wedge; unmount can't cancel-then-release-wholesale; count
   deferred_proof_failed separately from CAS-proof_failed (latter must be 0
   under enforcement).

## Hazards flagged
ABA across tenures; drain deadlock (admitted op parking on DEMOTING while
holding what its own drain needs); flush storms (jitter/coalesce); BAST
absence is not cancellation; unmount/work lifetime vs release_all; fault
boards must show proved-CAS or no-CAS for every injected failure.
