---
name: trap-a-harness-assertion-written-before-a-design-ruling-fails-from-a-measurement-that-no-longer-exists
description: TRAP (sess57, dlm_wait_signal): "did not spin (max stime<100)" FAILed on max_stime=none; the reader was gone at the signal because 0.82's abandonment…
metadata:
  type: feedback
tags: [harness, measurement-integrity, D-0958, D-0913, dlm_wait_signal]
---

# A harness assertion written before a design ruling fails from a measurement that no longer exists

**What bit (sess57, tests/dlm_wait_signal.sh, healthy lap s57b-9-ok).** The harness (sess518, D-0913) signals a reader blocked behind a peer's paused release and asserted that the reader "did not spin in the kernel while signalled (max stime < 100 ticks)". On 0.87.18 the lap printed `max_stime_ticks=none ... FAIL`. Every sample said `gone=1`: the reader had left its lock wait within two seconds of SIGTERM. Nothing was spinning — there was simply no live process to sample, and the harness turned the ABSENCE of a measurement into a FAIL about MXFS. Same class as D-A-TEST-HARNESS-CAN-REPORT-A-VERDICT-ABOUT-MXFS, produced by a stale expectation rather than a failed ssh.

**Why the reader was gone.** The remote-acquire abandonment protocol (0.82, D-0958 ruling, sess585) makes a killed task at a fallible boundary — a read is one — abandon its lock wait at once (`P958-ACQ-FATAL-SIGNAL`, `P958-ACQ-KILLED`, and for a REMOTE master `P958-ACQ-CANCEL-SENT`/`-ACK`). The sess518 harness predates that: it expected the reader parked in D with the signal pending until the peer's pause ended (the s518h evidence shows exactly that: `state=D stime=0 shdpnd=...4000` for 40 s).

**Second trap inside the fix.** Requiring `P958-ACQ-CANCEL-ACK` FAILed the next lap (s57c): an inode W masters itself is abandoned locally and sends no CANCEL at all (s57b-9 ino 3619 had a remote master and did send one; s57c ino 136 did not). Require the abandonment line, and that every CANCEL *sent* was acked.

**Rule.** When a harness's healthy lap FAILs after a design change, check first whether the assertion still measures anything: a verdict whose input is empty (`max_stime=none`, an absent process, a count over nothing) must be an ABORT ("nothing measured") or be re-derived from the current design, never read as the defect. And the vacuity check belongs in the harness: here, `timeout_rc=124` proves the signal reached a live reader; without it the lap ABORTs.

Evidence: tests/evidence/laps_s57/s57b-9-ok.log, tests/evidence/20260918T215603Z_waitsig_s57c, tests/evidence/20260918T215812Z_waitsig_s57f (PASS).
