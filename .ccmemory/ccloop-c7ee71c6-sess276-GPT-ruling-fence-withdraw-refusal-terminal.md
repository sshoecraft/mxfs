---
name: ccloop-c7ee71c6-sess276-GPT-ruling-fence-withdraw-refusal-terminal
description: sess276 RULE-5 ruling: proof-of-fence self-withdraw via PR IN READ FULL STATUS, BAST backoff+coalesce, refusal→terminal EIO state (no partial writeba…
metadata:
  type: project
---

# sess276 GPT ruling — false-death incident fix set

Context: the sess276 dlm_fairness incident (see
ccloop-c7ee71c6-sess276-panic-fix-verified-false-death-wedge-scene).

## A. Fenced-but-alive victim self-withdraw (PRIORITY 1)
- Authoritative check = PERSISTENT RESERVE IN / READ FULL STATUS (not
  READ KEYS — key reuse ambiguity), own node/boot-incarnation key absent
  on the correct LU. PR IN is target-generated, not cached media.
- Repeated reservation conflicts = trigger for PR inspection + bounded
  fallback to withdraw if inspection fails/ambiguous.
- Withdraw is NOT a clean unmount: atomically enter hard-withdrawn state —
  block all FS+HB writes, cancel queued retries, stop PR re-registration,
  stop DLM/BAST participation, error out callers, detach with NO media
  writes (no log flush, no clean bit, no lock release). Racing survivor
  recovery is harmless if stale DLM msgs are rejected by epoch checks.

## B. Release-abort/BAST loop (PRIORITY 3)
- Coalesce/edge-trigger BAST re-arm: max one outstanding notification per
  holder/request epoch.
- Exponential backoff + jitter capped 0.5-1s when release aborts repeatedly
  with unchanged holder generation; reset ONLY on confirmed platter
  gen/epoch movement. Conflict/timeout/UNKNOWN must not immediate-re-arm.

## C. Refused replay slice (PRIORITY 2)
- Ruled (iii): NO partial "unaffected" writeback — isolation boundary
  unprovable (allocator/log/dir/SB/cross-AG state).
- Convert refusal to explicit TERMINAL recovery state: stop publication,
  EIO/withdraw mounts, operator recovery required; never purge victim until
  authorized replay or offline repair. Bounded+diagnosable, not hung.
- Lineage-token implementation (sess175 design, ledger #1) = release
  blocker, the real availability fix.

## D. D-482 instrumentation (PRIORITY 4 but SAME BUILD)
7-point timestamping per HB write: worker start / bio submit / blk-mq
queue+dispatch / mpath select / SCSI issue / SCST recv+start+complete /
initiator completion — discriminates thread wedge vs local queue starvation
vs fabric vs target starvation. Plus per-initiator SCST queue depth+latency,
CAW-vs-plain latency, watchdog stack from preallocated context.
KEY question: were the frozen gen=332 reads 120s-UNCOMPLETED reads or
fast reads returning stale? Use direct reads + correlate cmd IDs both ends.

## Landing order
Next build bundles A + B + D; C's terminal-state conversion second;
lineage tokens proceed as the reviewed release-blocking track.
