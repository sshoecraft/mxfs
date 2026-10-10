---
name: compiled-harness-assertions-must-target-the-property-not-the-gate-snapshot-or-downstream-effect
description: Fencing/lock harness measurement traps: assert the property not the gate, stamp snapshots with generation, read raw platter, assert anchors, widen ve…
metadata:
  type: feedback
tags: [compiled, measurement-integrity, harness, fencing, scsipr, verification]
---

# Harness assertions must target the property under test, not a gate name, a later snapshot, or a downstream effect

Six notes on one failure family: an instrument more specific, later, or more indirect than the thing it measures either fails a mechanism that works or passes one that does not. Each is a rule for what to assert and when to look.

## Assert the property, not which gate prints it

- [[trap-an-assertion-that-names-which-refusal-must-fire-fails-a-refusal-that-is-working]] (s83): a lap injected a retired fence kind and asserted `P236-REPLAY-REFUSED`; both arms failed with `replay_refusals=0`. The certificate is classified earlier, at the claim gate (`P236-CLAIM-UNCERTIFIED`, `dlm/disklock.c`), so the refusal worked and fired from a site the assertion did not name. The companion "slice was NOT replayed" assertion passed and would pass equally if the lap never got that far; counting only what did not happen cannot tell a working refusal from a stalled one.
- Fix: assert that a refusal happened at any legitimate site, that it names the revoked class and the kind actually on the platter, and that the slice is untouched. Naming one expected token predicts internal ordering; loosening the assertion afterwards is how a real regression later passes. A kernel-log window taken with no mark (counting a previous probe's event) is the same shape.

## An injector that is safe to repeat is repeated before the lap can look

- [[trap-a-retryable-injected-failure-is-retried-before-the-lap-can-snapshot-so-assert-on-log-order-not-on-a-later-capture]] (s137, `tests/fence_live_prover_faults.sh` modes 1 and 2): both failed the same four assertions (victim key still registered, PR generation unmoved, no P&A claimed, `may_have_run` clear). Not an MXFS defect: the prover logged INTENT, INJECT ("safe to repeat"), then the retry P&A, then CERTIFIED, all within milliseconds and the SAME term (no second `P236-FENCE-INTENT`). The injector sits correctly at the command-submission boundary (`dlm/scsipr.c:2062`) and is one-shot; any snapshot after polling dmesg describes only the winning attempt, and counting P&As between inject and next intent cannot isolate the injected one.
- Change subject, not scope. "Assert nothing happened" is wrong for a fault whose contract is recovery; assert nothing happened unrecorded: no P&A issued without a durable arm naming it (compare arm markers to P&A completions), no `P238-FENCE-UNRECORDED` or `-BLOCKED`, and the settled descriptor proves the prover's own term. Assert on log order, not a later capture.
- Never edit a harness while a sweep is executing it: bash re-reads a script by byte offset and later modes run from the same file.

## A snapshot is evidence about one instant

- [[trap-a-pr-snapshot-only-proves-anything-about-the-generation-it-was-taken-at]] (sess573, unmountable-volume defect): a correct stale-PR hypothesis was wrongly disproven by a capture at PR generation 2765 (0 keys, no reservation) while the failing mounts logged `P304-PREOBSERVE ... type=0x7 holder_key=0x0 gen=2757` and a reservation conflict. Eight generations of the investigator's own mounts and a module swap had cleared it.
- Rule: PR generation changes on every registration change and every MXFS PR probe prints `gen=`. A capture whose generation differs from the failing log line is about a different world and can neither confirm nor refute. Generalises: any "I looked and it was clean" disproof of a transient-state hypothesis needs a stamp tying the look to the event (generation, epoch, incarnation, LSN, boot id); otherwise it retires true hypotheses. Time-shifted twin of `trap-a-silent-instrument-and-a-clean-system-are-the-same-observation`.
- Finding once matched: the PR key derives from {host, boot, LUN}, so every mount of a host within one boot registers the same key, and a fence aimed at a dead incarnation's retained key lands on the live successor (`P305-RESV-SELF-GONE`, then self-fence). Initiator IQNs are distinct per node, so not a shared-nexus artifact.

## Read the platter, not the success code

- [[technique-a-successful-fsync-is-not-evidence-bytes-reached-the-lun-capture-the-extent-while-healthy-and-read-the-raw-block]] (s87): `PROBE_DATA rc=0 ms=1` from a PREEMPT-AND-ABORTed node proved nothing either way, and reading back through the same mount returns its own page cache.
- Procedure: while the FS is healthy, write, fill a whole block, fsync, `sync -f`, capture the physical offset via `FS_IOC_FIEMAP` (ioctl `0xC020660B`); baseline the block with `dd iflag=direct | od -c`; run the experiment; re-read the same block the same way. This turned rc=0 into `fenced-direct-wr` before the fix and `baseline` after.
- Add a control arm (same probe on a healthy node must SUCCEED, since a containment harness asserts failures and a broken probe satisfies all of them). Order the decisive raw read before the slow metadata arm so its DLM retry-budget timeout cannot abort the lap first; record the timeout as an outcome.

## Assert on the anchor, not on what it causes

- [[technique-verify-a-timestamp-anchor-by-asserting-on-the-two-timestamps-the-kernel-prints-not-on-the-downstream-behaviour]] (s87): the authority-lease deadline must derive from the heartbeat ISSUE instant, not completion delivery. "Withhold the completion, then a write is refused" also passes on a completion-anchored build once any other closer (periodic evaluator, bounced write) has closed the epoch; it proves stickiness.
- Park every other closer, then assert on the two kernel-printed timestamps: `deadline_ms - issued_ms == 30000` (a completion anchor would read 342039 vs 295959 here).
- Unreachable guard (refuse a renewal whose beat was issued after authority lapsed; an upstream check stops such a beat): remove the primary check for one cycle (`dbg_hb_skip_auth_check`), leaving the guard and all other tests intact. Never weaken the thing under test; remove what hides it.

## Unreachable trigger state: widen the final verdict under a knob

- [[technique-when-the-defects-trigger-is-unreachable-make-its-final-verdict-unconditional-under-a-knob-and-run-both-arms]] (sess603, allocator defect D-0946): ordinary churn never produced the deferred deadshell that the recycle gate's platter check required (16+ rounds at DEADSHELL=0; reproducer 3 hits in 16 death/rejoin laps). Do not fabricate the trigger state. Under a test-only knob take the chain's final verdict (read platter, fail if live) on every create-path recycle, using the product's own reader via a private bounce-buffer read that perturbs no cache.
- Run both arms: control (pre-fix) fired on the first re-pick at 2.2 s, same inode number 132 and signature (`disk_gen == ogen-1`) as all original occurrences; fix arm ran 4800 creates, ~770 assertions per round, live 0, with allocator refusal counter 90-240 per round proving the changed code carried it.
- Sound only if (1) the widened verdict is implied by the fix invariant (no open FREE obligation implies free image durable; see `docs/free-publish.md`) and (2) the knob reads real state and touches no product cache or log. Expose exact resettable counters: dmesg is print-budgeted (first 32, then 1 in 500) and showed PUBPEND_LINES=32 every round.
- Sibling: `trap-a-verification-condition-that-a-healthy-build-cannot-produce-is-vacuous-by-construction-inject-it-at-the-verdict` (input injected there; here input is real and only the verdict's reach widens, preferable when a real reader exists).
