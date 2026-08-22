---
name: ccloop-c7ee71c6-sess234-21-gate-VERIFIED-and-mass-false-death-storm
description: sess234: #21 fail-closed gate VERIFIED (slot10 refusal, 0 publishes) BUT frozen grants cascaded into 20-node false-death storm; test29 PR-fenced LIVE
metadata:
  type: project
---

# sess234 — #21 gate verification + mass false-death storm (0.11.482, sv F6C92539D1851F1882306A5)

## Repro
`tests/incident474_load_kill.sh 32 test16 180` @ 2026-08-11T00:22:24Z; test16 (slot 10, node 346449043) virsh-destroyed ~00:23:30Z mid-rsync.

## Gate VERIFIED (the #21 P0 sess233 landing works)
test1 (slot 0, elected replayer, boot≈21:06:05Z so wall = ts+21:06:05):
- ts 11860 (~00:23:45Z): HB expired after 31 checks → fence already certified (P238-FENCE-DONE) → P238-RECOV-LEASE → replay attempt →
  **P227-FR-TORN-UNPUBLISHED slot 10: refused 3 committed untagged image(s)** → -117 → "refused as TORN/corrupt — NOT auto-retried".
- **ZERO P163-RECOVERY-COMPLETE fleet-wide after the kill** — nothing published. Fail-closed held everywhere.
- Latch is bounded, NOT infinite (#11-style storm absent). BUT: every NEW death re-arms ALL pending slices via the re-elect loop (v5_mount.c:1843 → dead_node_notify_fn clears torn), so slot 10 was re-attempted at 12220, 12245 during the storm — each refused again. Bounded per death event; acceptable but noisy under mass death.

## THE STORM (new critical defect evidence)
Chain: slot-10 refusal freezes its grants forever (by design until #1 tokenization) → fleet's post-load cleanup blocks on frozen grants (P-ACQ-STUCK ino=20974600 el_ms>110s on test1, starting ~00:29:33Z) → **20 LIVE nodes' HB sectors stop advancing >62s** (31×2000ms, FUA-confirmed not stale-cache) → mass lease expiry 00:29:45–00:31:01Z (test1 saw 20 deaths; test4 saw 36 lease-expiry events total) → survivors fence/replay live members:
- Slots declared dead (all CURRENT incarnations of LIVE mounted nodes): 5,7,8,9,11,13,14,15,16,17,18,19,20,21,22,23,24,30,31 (+10 real).
- 18 slices REFUSED TORN + latched (protection held — no publishes, no purges).
- Slots 6,12,15,18: P236-CLAIM-UNCERTIFIED (no incarnation stop observed → no preempt issued).
- **Slot 14 (test29, LIVE): P236-FENCE-CERTIFIED kind=PREEMPT_ABORT_DONE prover=3374620093(test5) — live member's PR key preempted; test29 now spews `reservation conflict error, dev dm-1 ... WRITE` (ts 13870) while still mounted.**
- Victims NEVER self-detected lease loss: every host has exactly 2 "claimed heartbeat slot" lines, both PRE-event (prep ~23:40Z + board remount ~00:12–13Z). No re-registration, no self-fence, no withdraw. They keep writing while fleet-consensus-dead.

## Disposition
- #21/# 6: verification evidence recorded (gate + latch work).
- NEW defect to ledger: mass false death of live members under frozen-grant stall; missing victim lease-loss self-detection; PR preempt executed against live member. Cross-refs: D-RECOVERY-CTXLOCK-HOLD-HB-STARVATION (sess222, suspected mechanism for HB stall), #13, #9.
- Platter protected ONLY by the new gate (refusals) — this storm on .481 would have mass-published torn slices.

## Rig state at session end of capture
test16 shut off; 31 nodes mounted but degraded (frozen grants, stuck acquires, test29 write-dead). Needs full VM restart + prep (mkfs) before next board run. clyde loadavg ~10.6 during event.
