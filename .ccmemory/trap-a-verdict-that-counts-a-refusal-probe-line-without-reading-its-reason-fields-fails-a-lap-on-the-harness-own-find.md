---
name: trap-a-verdict-that-counts-a-refusal-probe-line-without-reading-its-reason-fields-fails-a-lap-on-the-harness-own-find
description: TRAP (0.90.27, 8/cawd): 10 P240-QUAR-NSOP-REFUSE lines at +7 s, before any kill, comm=find incarn_stale=1 rblk=0 quar_flag=0: lap printed FAIL.
metadata:
  type: feedback
tags: [harness, multi-victim, verdict, probe, caw]
---

## What happened

`tests/multi_victim_containment.sh` counts every kernel-log line matching
`P240-RBLK-EIO-ABORT|P240-QUAR-NSOP-REFUSE` on a survivor as an operation
refused because of a quarantined victim, and fails the lap when the count is
not 0.  Queue `g27a` lap 4 (8/cawd, 0.90.27) printed FAIL on
`refused_ops=10` for test1 while both slices recovered (+83 s, +89 s), the
load stalled 4 s and met no error, and `chk_mxfs` exited 0.

The ten lines were one payload ten times, at **+7.14 s, six seconds before
the first kill**:

    P240-QUAR-NSOP-REFUSE op=lookup ino=50331776 rc=-116 comm=find
        incarn_stale=1 rblk=0 quar_flag=0 quar_map=0

preceded by `P201-TYPEFLIP-UNRESOLVED-FAIL ... comm=find — type flip
UNRESOLVED after 48 rounds; failing the lookup`.  `comm=find` is the
harness's own "load confirmed" check, walking the tree every node is
removing and re-creating.  The probe line has three reasons in one tag: a
quarantined domain (`quar_flag`, `quar_map`), a holder in blocked recovery
(`rblk`), or a stale incarnation (`incarn_stale`).  Only the first two are
what the verdict means.

## The rule

- A verdict that counts a probe line must read the line's own reason fields
  and its time.  Count `P240-QUAR-NSOP-REFUSE` only when `rblk`, `quar_flag`
  or `quar_map` is non-zero, and only after the first kill.
- Before reading a FAIL of this harness as a containment failure, read WHICH
  field of the survivor line is bad and look at the matching lines' `comm=`,
  reason fields and offset from T0.
- A lookup that races a peer's `rm -rf` and re-create can return ESTALE
  (-116) from the stale-incarnation gate; that is a separate question from
  death containment and must not be scored under it.

Evidence: `tests/evidence/multi_victim/20260929T170923Z_8cawd_g27a_c2/refused_ops_anatomy.txt`.
