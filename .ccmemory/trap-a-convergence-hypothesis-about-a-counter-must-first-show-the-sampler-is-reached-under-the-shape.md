---
name: trap-a-convergence-hypothesis-about-a-counter-must-first-show-the-sampler-is-reached-under-the-shape
description: TRAP (s143/s144): H1 predicted a strike counter would converge too slowly under backoff; the lap showed ZERO samples — gates upstream parked the shap…
metadata:
  type: feedback
---

# A convergence hypothesis about a counter must first show the sampler is reached

## What happened (session 51 -> 55, D-THE-ONLY-STRAND-ESCAPE-TCP-HAS-IS-A-U8-COUNTER-TESTED-AGAINST-280)

The record restored a compiler-deleted 280-sample strike escape (a uint8_t counter) and then asked whether the restored mechanism could converge on TCP. Hypothesis H1 was written about CADENCE: the release-abort re-arm backs off from 25 ms to a 1 s cap on an unchanged gen, so 280 samples would take ~275 s and the escape could not free the strand inside its 7 s design dwell. The lap (s143b, in-flight strand held 20 s by `dbg_strand_hold_ms`) FAILed as H1 predicted — but the capture showed ZERO pipeline samples during the whole hold, not slow ones. `P15-REL-ABORT`=0, `P279-RELAB-BACKOFF`=0, `P15H-STRIKES`=0 until the acquirer exited.

The reason was upstream of the counter entirely: every gate between the peer's BAST and the strike sampler treats `i_dlm_acq_inflight > 0` as a live acquirer to protect — `__mxfs_dlm_bast_notify` parks the BAST (`P-ACQWIN-PARK`, `P-ACQWIN-DEFER`) and `mxfs_dlm_bast_dwork_fn`'s busy check re-arms without running the release. The in-flight shape never reaches the line whose convergence H1 was about. The abandoned shape (count 0) reaches it but the sess10 `P15-TCP-ORPH-PROCEED` arm fires at ~sample 5, long before 280. The branch has no reachable shape on TCP at all.

## The lesson

Before predicting HOW a counter, clock or strike escape converges under a shape, walk every gate from the trigger to the sampler and show the shape is admitted at each one. A prediction about cadence is only meaningful once "the sampler runs under this shape" is established — otherwise a FAIL that matches the prediction's outcome can confirm a mechanism that does not exist (H1's FAIL "matched" while its mechanism was wrong). Instrument the sample COUNT as a first-class number alongside the cadence; a zero there is the discriminator.

The same walk answers the related question "is this the ONLY escape for the shape?": the record's premise that the strike counter was TCP's only strand escape was false on both shapes, because a different arm fired first on one and the park handled the other.

## How to check quickly

- For the mechanism's probe line, `grep` the harness's capture for the PIPELINE's own per-sample line (here `P15-REL-ABORT ino=<n> `) inside the window, not just the escape's line. Samples=0 means the shape is gated upstream.
- Read every `return` / re-arm above the sampler that tests the discriminating field (here `i_dlm_acq_inflight`); the list of sites is `grep -n i_dlm_acq_inflight xfs/xfs_mxfs_dlm.c`.
