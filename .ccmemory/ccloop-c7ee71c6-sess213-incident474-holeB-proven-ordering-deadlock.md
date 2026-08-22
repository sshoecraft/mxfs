---
name: ccloop-c7ee71c6-sess213-incident474-holeB-proven-ordering-deadlock
description: sess213: incident474 hole (b) PROVEN = replayer ordering deadlock (blocked on unpurged victim's EX, escalates to own shutdown); hole (a) as-designed;…
metadata:
  type: project
---

# sess213 — incident474 arm B fully characterized; board re-greened on 0.11.477

## Hole (b) PROVEN (the terminal cascade step)
From tests/evidence/incident474/test1.klog.gz: test1 (slot 0, elected replayer) was serially replaying ~8 victim slices when its recovery kworker (kworker/u10:5; P97-SWEEP adopted-bucket path) needed EX on ino 12585558. CAW slot 41094 showed gm=5 holder mask 0x10000 (slot 16, a wedged victim) 15:50:23→15:56:19 — never purged because that victim's purge is deferred until ITS slice replays, but the one replayer is blocked here. 3×120s base waits (rc=-110 at 15:52:18/15:54:19/15:56:19), then P34-ACQ-SLOW dur_ms=360605 attempts=4 → "DLM inode lock unrecoverable — shutting down filesystem" → last survivor gone. ZERO P-WAIT-EXTEND on test1: the "480s liveness-extension cap" framing was WRONG for the terminal step; it was base timeouts + fatal escalation to the replayer's own shutdown. Ledger field: hole_b_evidence_sess213 in D-WITHDRAWN-NODE-CASCADE-NONCONTAINMENT-474.

## Hole (a) reclassified AS-DESIGNED
Withdraw (mxfs_v5_dlm_shutdown_withdraw, v5_mount.c:4329) stops discovery + disklock HB and stamps WITHDRAWN; UDP lease renewals deliberately keep running until unmount (sess11 design comment v5_mount.c:4360) so mastership doesn't migrate pre-replay. Observed on .477 single-victim: 7m43s / 772 renewals received per survivor post-withdraw, all ignored via P164-DEAD-NOTE. Not a defect per se (log spam only).

## Hole (c) located, not terminal
P-WAIT-EXTEND (dlm_caw.c:5743) → v5_caw_holders_alive (v5_mount.c:1568) → mxfs_disklock_slot_live (in-memory monitor tracker). Wedged-but-not-yet-shutdown victim keeps disklock HB beating → oracle truthfully "alive" while fs unserviceable. Feeds pre-withdraw waits only.

## Single-victim containment VERIFIED (occurrence_sess213)
test6 withdrawal 17:49:51Z on .477: PR fence effective +4s, lease-death declared +64s, test1 replayed slice 27 in 10s, deferred purges ran, no stretched waits, 31/32 survivors passed rsync. Cascade requires MULTI-victim cross-holding.

## Rig state at session end
0.11.477 fleet 32/32, FULL board (27 real cells) PASS in chunks 18:05-18:30Z, rsync laps 1-12 PASS (fs aged ~45min), ailstuck_probe=1 fleet-wide (fence-scoped latch makes it safe). P129-CLSKIP why=IFLUSH_RAN err=0 = benign. No arm-A/fossil/silent-rsync re-trip in 12 laps.

## NEXT
RULE-5 GPT consult on containment fix set with hole (b) chain verbatim: replayer force-reclaim from CERTIFIED-FENCED holders (fenced ⇒ reclaim safe) vs replay-before-sweep ordering vs never-escalate-blocked-replayer-to-own-shutdown; plus hole (c) serviceability signal (victim self-reports wedge state in HB record); plus arm A fix candidates (D-NOINO-RELFENCE ledger). Ledger #17: silent mode still unrooted — keep stderr capture live on future laps.
