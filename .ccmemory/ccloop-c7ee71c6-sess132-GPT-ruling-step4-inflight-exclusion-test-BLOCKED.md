---
name: ccloop-c7ee71c6-sess132-GPT-ruling-step4-inflight-exclusion-test-BLOCKED
description: sess132 RULE-5 ruling: the proposed in-flight exclusion test is BLOCKED for closure — 7 mandatory changes, incl. sg_persist alone is not RULE-6 evide…
metadata:
  type: reference
tags: [D-PR-FENCE-PREEMPT-WITHOUT-ABORT, rule5-ruling, fencing, test-design]
---

# RULE-5 ruling (gpt-5.6-sol, sess132): step-4 in-flight exclusion test is BLOCKED

My proposal: dm-delay under a second **vdisk_blockio** LUN on a separate IQN,
victim issues a held O_DIRECT write, survivor issues `sg_persist --preempt-abort`,
clyde polls the loop device, assert `t_land <= t_return`; A/B 0x04 vs 0x05.

**Verdict: do NOT close the defect with this test as written.** Four closure
blockers, plus wrong-answer risks. The A/B concept is sound as a *discriminator*
but by itself it is a target-stack qualification test, not RULE-6 closure.

## The four closure blockers
1. **`t_land <= t_return` is weaker than the ledger's unchanged criterion.**
   The ledger says "assert the victim's bytes are NOT on the platter". My
   assertion admits "P&A waits 30 s, victim write lands, P&A then returns
   success" — which prevents the post-return race but proves no cancellation.
   Must record **two separate properties** and classify explicitly; never
   silently score a pre-return landing as full PASS:
   - abort/cancellation criterion: `P is never observed, absent after full drain`
   - fence linearization criterion: `no victim modification after P&A completion`
2. **`sg_persist` does not exercise the patched MXFS call chain.** The defect was
   "MXFS called PREEMPT instead of PREEMPT AND ABORT", not "SCST mishandles P&A".
   An sg_persist PASS proves only that the target *can* provide the property when
   asked. It does not prove `fence_node()` reaches the patched function, uses
   `abort=true` at runtime, uses the right device/path/key, or does not report
   success before the PR command completed. `P236-FENCEKIND` is software
   self-report unless backed by an actual CDB capture.
3. **`vdisk_blockio` does not establish `vdisk_fileio`'s behaviour** (the shipped
   handler). NOTE: sess132 partially refuted this at the code level — both
   devtypes share `vdisk_task_mgmt_fn_done` and neither implements
   `task_mgmt_fn_received`, so the abort machinery is core. Still: measure on
   fileio. Ruled stack: `file -> loop (direct-io=on) -> dm-delay -> dedicated fs
   -> preallocated disk.img -> vdisk_fileio o_direct=1`. Preallocate the inner
   image; use a dedicated fs so delayed writes cannot stall /home or SCST's PR
   state file. There is NO credible low-risk way to interpose delay under the
   live 32-node LUN — do not try.
4. **A 1-second sleep is not evidence the write is in the target's task set.**
   Gate the P&A on an OBSERVED in-flight state. (sess132: SCST's own
   `scst_pr_abort_reg` TRACE_PR line prints the exact command count — use it.)

## Mandatory corrections (the ruling's own list)
- use "P absent after drain" IN ADDITION to temporal ordering;
- gate fencing on observed target-side in-flight state;
- avoid cross-host `t_return` comparison, or make it conservatively traceable —
  an SSH-observed process exit is LATER than the real ioctl return and can
  misclassify a post-return landing as pre-return. Prefer timestamping the P&A
  SCSI response on the same host that polls the backing store (conservative:
  can false-FAIL in the transit interval, cannot false-PASS);
- test vdisk_fileio, not only blockio;
- eliminate multipath/nexus ambiguity — single explicitly-selected session for a
  test LUN, or verified ALL_TG_PT semantics;
- **move W away from initiator timeout thresholds**: W=30 s is near the SCSI
  command timeout. Use W = 10-15 s AND raise the test device's
  `/sys/block/*/device/timeout` to >= 120 s. Record iSCSI replacement timeout,
  multipath retry policy, SCSI EH logs, victim command result+duration, session
  state. A valid run must not coincide with EH, logout, target/LUN reset;
- include actual MXFS fence-path evidence, preferably in the same end-to-end run.

## Observation-path corrections (Q3)
Buffered reads of the loop device are NOT sound — up to five cache aliases
(SCST's bdev, dm-delay, /dev/loopN, the loop backing file, the backing fs).
Use **aligned O_DIRECT reads against the device immediately below dm-delay**,
with `losetup --direct-io=on` CONFIRMED (not silently fallen back). Never read
the backing file buffered. Per trial: write+flush+read-back a baseline, fresh LBA
and unique pattern; afterwards wait > W, ensure the victim command terminated,
flush, final direct read, and do not tear down the dm target until all delayed
work has drained. A 50 ms poll bounds landing to an interval only — report
`last-read-without-P < t_land <= first-read-with-P`. "Landed on the platter" is
too strong for a file-backed device; the provable claim is "P became observable
in the backing store through a direct read".

## Sentinel guidance
A sentinel written THROUGH the same dm-delay is useless (fixed delay: the
victim's write was queued first and is released first). A below-delay sentinel
can demonstrate clobbering but must not erase the primary evidence — use a
separate phase or LBA, and treat continuous observation of P as primary.

## Wrong-answer risks to rule out explicitly
Write never admitted (PR rejected it before execution — capture PR full status:
victim key, survivor key, holder, type, I_T nexus, ALL_TG_PT); wrong path
preempted; initiator SCSI EH aborting the command instead of the target;
**SCST merely waiting rather than cancelling** (the expected outcome — classify,
do not score as PASS); SCST tearing down the task while a detached bio stays
live (the real bug this must catch); dm-delay flush/FUA reordering (validate the
delay stack standalone first: single write, no P&A, confirm nothing below before
~W and landing after ~W); a sentinel hiding P; A/B state contamination — rebuild
PR + data state per arm, fresh LBA/pattern, and run **0x04 -> 0x05 -> 0x04** so
the discriminator is shown not to have evaporated after the first trial.

## Ruled staged plan (Q6: yes, step 4 is the right priority)
1. Harness feasibility on a delayed **blockio** LUN, single path — prove the held
   write is genuinely queued, run 0x04, verify the forbidden post-return landing.
   NOT closure evidence; it validates the measurement method.
2. Repeat the A/B on a delayed **vdisk_fileio o_direct=1** LUN. Require 0x04 to
   fail and 0x05 to leave P absent (or classified per the two-property rule).
3. MXFS integration evidence: actual MXFS fence with on-wire capture proving the
   emitted PR OUT service action is 0x05, `fence_node()` success, final PR state.
4. Closure rerun of the UNCHANGED existing acceptance criteria; preserve A/B
   traces, command results, PR full status, SCST logs, backing-store reads.

Cheapest acceptable package (weaker, needs ledger-owner agreement): on-wire proof
from a real MXFS fence that the CDB is 0x05 + delayed same-handler fileio A/B via
sg_persist + existing step-2/3 results.
