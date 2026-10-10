---
name: trap-a-rejoin-read-stall-needs-an-aged-pair-so-a-control-arm-right-after-a-deploy-is-vacuous
description: TRAP: physical-pair rejoin read stall (hand-off FIFO starvation) needs several withdraw laps of aging; 6 control arms right after a deploy all passed…
metadata:
  type: feedback
---

The rejoined-host read stall on the physical DRBD pair (0.90.113: first read 69-95 s after `withdraw-p0`) reproduced 2/2 on a pair that had been through many withdraw/rejoin laps, and 0/6 in an A/B run right after `scripts/pve_pair_update.sh` restarted both units, with the fix OFF as well as on. The deploy resets the ledger/hand-off state: after it the rejoiner's swap lock fell to ~1 ms within 30 s of the join; on the aged pair it sat at 18-45 ms for 90 s+, with the census moving 3.7 pages/s against ~20.

**Why:** the stall is the rejoiner's single hand-off worker activating the survivor's view-change FROZEN stream while the survivor's FREEZE_REQs (each a parked request) wait behind it. Its length depends on how much the view change moves, which grows over repeated rejoins.

**How to apply:**
- A control arm is evidence only if it shows the precondition. Check `P-HRX-ASK-WAIT` / `P-TAUTH-PAGE-PARKED` counts in the arm's window, not just its pass/fail.
- To reproduce, age the pair with alternating `withdraw-p1 withdraw-p0` laps (the 4th lap stalled at 69 s with knob 0). Then run the treatment arm immediately on the same aged state (5/5 passed, 0 asks waited ≥1 s).
- `tests/pve_pair_failover.sh` collected step klogs before the verify, so a passing arm's reads were never in its evidence. It now collects again after the census, and a slow read leaves stacks (`tests/pve_read_stall_probe.sh`).

Fix: 0.90.114 `handoff_rx_ask_first` in `dlm/v5_mount.c`.
