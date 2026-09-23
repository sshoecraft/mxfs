---
name: trap-a-control-arms-expected-behaviour-written-from-reasoning-hides-the-second-defence
description: TRAP (sess586, D-0958): the drop_grant control asserted "H's write blocks 40 s for ever" from reasoning; measured, W's phantom reconcile released the…
metadata:
  type: feedback
tags: [trap, harness, control-arm, D-0958, tcp, dlm]
---

# A control arm's expected behaviour must be measured, not derived

**What happened (sess586, D-0958, tests/tcp_lockreq_blackhole.sh FAULT=drop_grant CONTROL_NO_CANCEL=1, lap s585d):**
The harness header and its control checks said that without LOCK_CANCEL the master's undelivered grant "stayed a blocker at H for ever" and asserted H's write of the file blocked for 40 s. That claim was written when the cancel was designed, from reading the code, and the control arm was never run before 0.84.1 shipped with it.

Measured: H's write blocked 10 s, then completed. W's log: `P-PHANTOM-RECONCILE ino=3731 — repeated no-mirror BAST; serialized reconcile release` then `P-PHANTOM-RECONCILE-SENT`. The pre-existing phantom reconcile (xfs_mxfs_dlm.c bast_notify: two no-mirror blocking notifications inside 15 s on a TCP mount queue a mirror-bypassing release) is a SECOND DEFENCE that retires exactly this orphan — as long as the notifications reach the requester over the transport that lost the grant.

**Why it matters:**
- The treatment arm (s585c) passed with the cancel doing the work in 3.5 ms and zero reconcile lines; the control FAILED two checks — not because the control was broken but because its expectations were fiction. Had I "fixed" the control by widening or dropping those checks I would have hidden that the pre-fix system was bounded at 10 s, and the CHANGELOG would have claimed a hang that never existed.
- What a control arm asserts is a measurement of the OLD mechanism, so it must name that mechanism (here: reconcile fired ≥1, no cancel) and report the wall, never assert a duration invented from reading code.
- The treatment arm must also assert the second defence did NOT fire (reconcile == 0), or a lap where both retire the grant proves nothing about which one the write waited on.

**Rule of thumb:** before shipping a harness with a control arm, run the control arm once and write its checks from what it printed.
