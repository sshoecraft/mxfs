---
name: trap-pve-test-scripts-default-to-different-pairs-so-always-pass-pve-pair
description: TRAP: tests/pve_cluster_write_authority.sh defaults PVE_PAIR to nested pair A; most pve_* scripts default to the physical pair. Always pass PVE_PAIR.
metadata:
  type: feedback
---

The pve_* harnesses do not agree on their default pair:
- `tests/pve_cluster_write_authority.sh`: `PAIR_S=${PVE_PAIR:-192.168.120.137 192.168.120.192}` — nested pair A.
- `tests/pve_churn_fairness.sh`, `tests/pve_pair_profile.sh`, `scripts/pve_pair_update.sh`: default "192.168.1.80 192.168.1.81" — the physical pve1/pve2.

What it cost (2026-10-07, 0.90.100): a "physical-pair verification" churn launched without PVE_PAIR ran on nested pair A instead, at the same time as a fairness profile on pair A. The physical pair was never tested (its counters read 0), and the profile measured two overlapping churns as if they were one.

Rule of thumb: pass `PVE_PAIR="<addr> <addr>"` explicitly on every pve_* invocation, and before reading a result check that the evidence's host lines name the pair you meant. Two workloads on one pair at once contaminate both.
