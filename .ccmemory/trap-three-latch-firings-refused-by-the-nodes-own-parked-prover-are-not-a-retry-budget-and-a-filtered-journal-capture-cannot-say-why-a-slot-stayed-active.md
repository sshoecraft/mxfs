---
name: trap-three-latch-firings-refused-by-the-nodes-own-parked-prover-are-not-a-retry-budget-and-a-filtered-journal-capture-cannot-say-why-a-slot-stayed-active
description: TRAP (D-0356, sess578→sess53): "the retire worker gives up after three retries" was the PR worker's latch refused by the node's own parked prover; th…
metadata:
  type: feedback
tags: [D-0356, fencing, departure, harness, evidence]
---

# Three refused latch firings are not a retry budget; a filtered capture cannot explain a slot left ACTIVE

**What happened (sess578, 0.81.2, D-0356).** A prover parked on its own fencing
intent was unmounted; the unmount returned 0 after the hold but its slot stayed
ACTIVE with the attempt standing. The record explained it as "the retire worker
gives up after three retries while the unmount waits" and asked for the retry
budget to be measured. Both halves were wrong:

- `P304-FENCE-RETRY attempt=1..3` + `P304-FENCE-PROVE-BUSY` are the **PR
  worker's** latch (`v5_fence_retry_worker_fn`) firing and being refused by the
  single-prover guard because the node's OWN parked prover held it; the worker
  was then joined by the shutdown. `P304-RETIRE-WORKER exiting` is the
  *settle* worker, a different thread, stopping in the same teardown. No retry
  budget exists anywhere on that path.
- The capture was `journalctl | grep 'P236-RELEASE\|P304-RETIRE\|...' | tail -16`.
  Why the slot stayed ACTIVE is said by `P277-SLOT-RETAINED-UNMOUNT-DIRTY`,
  `P278-LATE-RELEASE`, `P236-RELINQ-*`, `P302` — none in the pattern. Their
  absence was a gap in the capture, not evidence, and the harness that
  produced the lap did not save the journal at its VACUOUS exit at all.

**Measured on 0.87.14 (sess53, s53b/s53d).** With the gate available the
departing prover certifies, recovers the victim and releases RETIRE_PENDING.
With the gate refused (`fence_gate_inject_refuse=1`) its unmount waits ~110 s on
the dead victim's grants (root inode, SB summary lock) until the recovery-
blocked cutoff answers EIO, then departs **DIRTY** — no unmount record — so
slot and key are retained by the ordinary dirty-departure rule, not by any
worker giving up.

**Rules for next time.**
1. Attribute a probe line to the function that prints it before naming a
   mechanism; `P304-FENCE-RETRY` and `P304-RETIRE-WORKER` share a prefix and
   nothing else.
2. A VACUOUS/ABORT exit must save the full journal (`journalctl -k --since
   @MARK`), not a pattern-filtered tail; the lines that explain a negative are
   never the ones the pattern was written for.
3. A harness that virsh-destroys a node must power it on before ANY exit;
   `run.sh prep_cluster` treats rig nodes as external and aborts on a
   powered-off one ("unusable after power cycle").
4. Do not edit a harness file while a lap of it is running; bash reads the
   script incrementally from the current byte offset.
