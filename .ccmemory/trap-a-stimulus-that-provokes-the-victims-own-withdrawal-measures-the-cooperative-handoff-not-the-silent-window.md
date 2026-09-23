---
name: trap-a-stimulus-that-provokes-the-victims-own-withdrawal-measures-the-cooperative-handoff-not-the-silent-window
description: TRAP (s130/s146): a lease-boundary lap's writer closed the victim's gate, the closure withdrew, the peer fired on the stamp; removing the writer chan…
metadata:
  type: feedback
tags: [trap, fencing, authority-lease, harness, measurement-integrity]
---

# The trap

`tests/authority_handoff_phase.sh` (s130 sweep, D-AUTHORITY-LEASE-RESURRECTION-CASES-ARE-UNVERIFIED) set out to measure the earliest instant a PEER completes a handoff against the victim's own authority deadline, expecting a 30 s margin (62 s dead window - 2 s sampling - 30 s lease). Four laps measured 0.9-1.6 s and a session spent a next-step wondering which of the three constants was wrong on TCP.

None was. The harness ran a 2 Hz writer on the victim so that `mxfs_authority_ok` would be called and close at the deadline. But a closure WITHDRAWS the mount (P290-AUTH-WITHDRAW → P-WITHDRAW-QUEUE), the withdrawal stamps the disklock slot WITHDRAWN, and the peer's monitor takes the `P163-WITHDRAW-SEEN` goto into `fire_dead` at its next 2 s pass. The "heartbeat expired after 14 checks" line was the equal-sample count at that instant, not a threshold — `dead_threshold` was 31 on both nodes. So every margin was one monitor pass after the victim's own closure: positive by causality, and silent about the silent window.

**Removing the writer did not help (s146a/b).** With no I/O at all the victim still closed at the deadline: the PR worker's periodic tick asks the gate every 250 ms precisely so that an idle node closes on time (`dlm/v5_mount.c`, "THE PERIODIC HALF OF THE LEASE"). A LIVE node therefore never presents the silent path; only one that cannot run its own tick does. The 0.89.66 instrument showed the window both times: 30.9 s from the peer's last sight of a beat to the declaration, the victim's stamp exactly 30.000 s before its deadline.

# The rule

- When the stimulus that makes the victim's clock observable is ALSO an input to the peer's detector, the lap measures the cooperative path. Read the peer's death line and the lines just before it: a WITHDRAWN stamp, a certificate, or an epoch change each reach the death without any silence.
- A "margin" measured on a causal chain (peer acts BECAUSE the victim closed) cannot be negative and therefore proves nothing about the boundary.
- To produce the silent shape, hold the CONVERSION of the closure, not the closure: `dbg_auth_withdraw_pause_ms` (0.89.66) keeps the lease evaluated and withholds only the withdrawal pump, so nothing stamps and the peer must wait out its full window.
- Print the detector's own window fields (`threshold= last_stamp_ms= last_seen_ms= now_ms=` on the death line) and classify the path in the harness (`path=withdrawn|certificate|epoch|silent` on the MARGIN line).
- Evidence: tests/evidence/20260921T104302Z_ahphase_0_s130e0 .. _1500_s130e3 (P_win.txt lines 35-38), 20260922T040055Z_ahphase_0_s146a, 20260922T040341Z_ahphase_1000_s146b.
