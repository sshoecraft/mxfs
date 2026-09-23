<!-- sess480 RULE-5 ruling: criterion (2) failed as written (do not relabel); it is a release gate, not record verification. Plus D-401 tail-mechanism dis… -->
# sess480 GPT ruling — criterion (2), and what the D-401 tail actually means

Context: the 0.64.37 board came back `crash_consistency FAIL 91/90s nodes_pass=0/32
BUDGET_EXHAUSTED=32` with `checks=11 passed=11 failed=0` on every node and all 32
reaching durable — a pure wall-time failure, zero correctness faults. That blocks
criterion (2) of D-FOREIGN-REPLAY-UNGATED-IMAGES.

## On the criterion (the part that constrains what may be done)

- **Criterion (2) FAILED as written. Do not relabel it PASS.** No correctness
  failure does not equal meeting an unchanged 90 s requirement.
- It is defensible as a **release/candidate cleanliness gate** and poor as a
  **record-specific verification criterion** for UNGATED-IMAGES, because the row
  does not exercise that record's mechanism (foreign-slice replay gated on
  incomparable cross-slice LSNs), its outcome is controlled by a different open
  defect, and one board is a single sample of a distribution observed at both
  22 s and >90 s. Rerunning until green would be **selection, not verification**.
- Keep the statements separate and do not blur them: correctness sub-oracle
  passed / full row FAILED / criterion (2) not met / cause attribution to D-401
  not yet *proven* / UNGATED-IMAGES correctness not disproven by this row.
- **Pointing the criterion at a sharded directory cannot discharge it.** Sharding
  is opt-in via `MXFS_IOC_DIRSHARD_MKDIR`; only a change to *production defaults*
  such that an ordinary directory transparently gets the behavior would qualify.

### Distinguishing an ill-formed criterion from an escape attempt

A replacement case must not rest on the inconvenient result. It needs: original
intent/traceability (was "clean board" meant as defect verification or candidate
hygiene?); demonstrated **orthogonality** (the row's outcome is dominated by
D-401/cold state and its oracle has no sensitivity to foreign-slice gating);
repeatability from a **predetermined** run sequence on ONE build with controlled
cold/warm state, reporting failures (adjacent builds confound build and state);
and a valid replacement test that creates the actual hazard and **demonstrates
sensitivity — it must FAIL with the fix reverted**. Then independent sign-off,
dated and prospective, with the candidate still recorded as having failed the old
criterion. Cleanest outcome: split the concerns — a targeted UNGATED-IMAGES
criterion, plus "clean board" retained separately as a release gate.

## On the engineering (b): the tail is not explained by "contention"

p50 = 10 ms flat in N with multi-second tail outliers is a 100x+ outlier and
smells like a timer, not queueing. `mxfs_pal_cond_timedwait` on an off-CPU stack
is **not** evidence a timer fired — it may just be the primitive used to await a
grant. Need its **return reason** and the predicate transitions.

Discriminating signatures:

| mechanism | trace signature |
|---|---|
| ordinary queueing | wait ≈ sum of preceding holds; orderly owner progression; no fixed latency modes |
| slow-holder convoy | ONE abnormally long EX hold; many waiters share that same interval |
| lease/quantum | grants cluster at a fixed period or multiples; idle time while nominal owner does nothing |
| timeout→cancel→retry | timed-wait TIMEOUT returns, request generation increments, latency peaks AT the configured timeout |
| fairness over-rotation | very many ownership transfers, very few creates per grant |
| lost/delayed wake | grant arrived / predicate true but waiter still asleep; large grant→wake gap |
| scheduler convoy | owner descheduled holding EX; hold tracks off-CPU time |
| log/IO convoy | owner holds EX across log force or metadata I/O |

Highest-value experiments, in order: (1) run **without the 90 s deadline** — the
present distribution is right-censored and cannot show the tail; (2) measure
**useful creates per grant** (one grant doing 8 creates is a completely different
defect from 256 ownership transfers); (3) perturb the lease/timeout/quantum in a
diagnostic build — if the latency mode moves proportionally that is near
dispositive (diagnostic only, not a fix); (4) plot tail vs queue depth and N —
linear ⇒ queue/convoy, fixed peaks ⇒ timer, cliff at a configured value ⇒ retry.

Trace every operation (32 nodes x 8 creates is small): request id, queue depth
and position, grant decision/transmit/receive, cv wake, predicate-true, EX
enter/exit, downgrade, retry generation, timed-wait return code, wake reason, and
what the holder was blocked on.

## On cold-vs-warm (c)

Leading hypothesis: a **one-time cold operation performed while ownership of the
shared inode is serialized**, whose cost is amplified into a cluster-wide convoy
(directory block allocation/split, first log reservation/force, first mastering of
the DLM resource, connection init). Do not assume "cache warmth" merely because
later laps are faster.

Cheap discriminator matrix, same build/config/image: cold lap then immediate
repeats; **fresh directory on a warm mount** (if every new directory is slow, the
cold state is directory-specific — this is the cheapest and most informative);
same directory after remount; fresh directory after warming DLM/transport only;
cold directory after metadata pre-touch; restored filesystem snapshot for a truly
cold run.

**And: a warm 22 s pass is itself suspect until work execution is proven** —
predetermined unique operation ids, per-node attempted/succeeded counts, a durable
directory-entry inventory after each lap, and filesystem-side counters rather than
client success reports. A lap that skipped creates, reused prior artifacts or
short-circuited on existing names would look fast and mean nothing.

**Do not spend rig time rerunning the unchanged board hoping for the warm 22 s
outcome.** It would produce a formal PASS if the rules permit and almost no
engineering information.
