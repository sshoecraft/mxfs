---
name: trap-a-fix-that-adds-an-expected-signal-breaks-the-harnesss-nothing-happened-assertions-and-they-must-be-split-by-cause-not-relaxed
description: TRAP (s87): the containment fix made the victim log a self-fence and shut down — which the harness's "B noticed nothing" and "zero shutdowns" asserti…
metadata:
  type: feedback
tags: [harness, measurement-integrity, regression-test]
---

# A fix that adds an expected signal breaks the harness that proved the defect

`tests/fence_late_detection.sh` was built around two negative assertions:

- **"B has noticed nothing"** — zero lines from any detector, which is what makes
  the lap non-vacuous. A lap where the victim detected its eviction the ordinary
  way has measured the path that already worked.
- **"zero shutdown / BUG / Oops"** — because on the broken build, containment
  failing meant the node kept running and wrote.

The fix (a local authority lease) makes the victim notice — locally — and then
withdraw, which forces a filesystem shutdown. Both assertions therefore FAIL on a
lap where everything worked.

## The wrong repair, and the right one

The wrong repair is to relax them: delete the detection assertion, or stop
counting shutdowns. That throws away the thing that made the lap mean anything.

The right repair is to **split them by cause**, keeping each as strict as before:

- `DETECT` keeps every LUN-dependent detector (a bounced write, a PR IN, a
  heartbeat CAS miscompare) and **excludes the new local one by its reason
  string**, not by its log-line name — the new detector reuses the same
  `P131-SELF-FENCE` line, so `grep -v` on the name would have hidden the old
  detectors too. Then add a POSITIVE assertion that the local one fired and that
  its reason is the expected one.
- The shutdown count excludes exactly one **call site** — the cluster-withdrawal
  entry point — and nothing broader. Which withdrawal it was is settled
  separately by the LUN-dependent count being zero.

Net effect: the lap got stricter, not looser. It now asserts *which* mechanism
contained the node, where before it only asserted that something did.

## The companion

Add a CONTROL in the same pass. Every assertion in a containment harness is that
a write fails, and a harness that has quietly broken its own probe satisfies all
of them. Run the identical probe on a healthy node first and require it to
SUCCEED — and put it before the injection, so it is measuring the same build in
the same state.
