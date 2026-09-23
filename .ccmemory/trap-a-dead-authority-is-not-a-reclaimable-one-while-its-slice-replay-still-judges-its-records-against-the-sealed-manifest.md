---
name: trap-a-dead-authority-is-not-a-reclaimable-one-while-its-slice-replay-still-judges-its-records-against-the-sealed-manifest
description: TRAP (D-0981, 0.89.3): the orphan sweep's dead test (off the slot map, not in view) matched a fenced victim under replay; the mount's own sweep retir…
metadata:
  type: feedback
tags: [trap, tauth, ledger, recovery, d0981]
---

# A dead authority is not a reclaimable one while its slice replay still judges its records

D-0981 (s66e on 0.89.2, fixed 0.89.3, sess66). Found by the first ungated lap of `tests/d0980_barrier_killable.sh`, which mounted onto the LUN a `sole_survivor_gate_probe` lap had just left.

## The shape

- The probe's prover sealed a victim's fence-time manifest (stage FENCED) and was then refused at its own admission bound: the descriptor stayed FENCED with owner 0 — certified, unowned.
- The next mount declared the victim dead (P163-RECOVERY-PENDING, "purge deferred until slice replay completes"), claimed the lease in its first barrier round, and started the 6 s slice stability proof.
- Two seconds later its departure worker's ORPHAN SWEEP (`mxfs_dlm_takeover_orphans`, queued at DLM init and after every departure) classified the victim dead — `dlm_authority_dead`: not the occupant of any slot and not in view — took its ledger pages over and retired its records (`P-TAUTH-TAKEOVER-RETIRE ... cleared=1 via=orphan-sweep`).
- The replay's current-safety check then found the manifest's entry gone from the live ledger (`P-RMAN-POSTSEAL-MUTATION live{rc=-2}`), aborted -117 and published a TERMINAL FSWIDE quarantine. Every later mount refused in 22 ms.

The deferral ("purge deferred until replay completes") lived in the disklock purge path; the sweep is a different retirement path and never asked.

## Why it had never been seen

Every earlier lap started from the capture gate's `ensure`, which reformats the LUN. An unowned certified descriptor only exists on a LUN nobody reformatted after a refused prover. Precondition-shaped defects hide behind harness prep.

## The rule (Astra ruling 2026-09-19)

- **Dead is not reclaimable.** The protection interval is "recovery pending and stage < IMAGES_REPLAYED"; after that the completion ladder's purge and takeover are legitimate and a "until complete" predicate would refuse them.
- **Enforce at the destructive choke point** (`dlm_takeover_page`, before prepare/activate/purge, `-EAGAIN`), and pre-filter in the sweep for diagnostics. Sweep-only protection leaves the same hole through on-demand takeover.
- **Never weaken the verdict for a local mutator**: an absent record cannot say whether a foreign post-seal write landed. Prevent the mutation.
- Audit every retirement path on BOTH nodes: departure purge, on-demand takeover, boot/orphan sweep, settled/purged shortcuts, import filtering, page recycling, slot reuse, error unwind.

## What the fix relies on

The node's own recovery-pending marker names the victim before any dead test can pass (until then the frozen record keeps it the slot's occupant), so one marker lookup plus one descriptor read answers the guard without a platter scan per page. An incarnation no marker names is left to the ordinary dead tests.
