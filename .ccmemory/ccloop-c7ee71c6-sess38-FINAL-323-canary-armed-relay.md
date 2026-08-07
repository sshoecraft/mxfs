---
name: ccloop-c7ee71c6-sess38-FINAL-323-canary-armed-relay
description: sess38 FINAL: cluster on 323 (P83 canary armed, defaults); AGI defect 10 clean repro attempts (tripwire standing); board 322 was 27/27; NEXT: board 3…
metadata:
  type: project
---

# sess38 FINAL — relay handoff

## Cluster/tree at boundary
- Cluster: 32/caw on **0.11.323 (62A92FF1)**, params at DEFAULTS (grace=40, instr=0, create_intent_ex=0). Healthy, converged.
- 323 = 322 + P83 probes ONLY (REMCHK instr-gated FUA compare at unlink-remove stitch; RELOAD canary UNCONDITIONAL at xfs_iunlink_reload_next — the standing tripwire for D-AGI-UNLINKED). Inert at defaults; regression risk ~nil, but 323 has NOT been full-boarded (322 was: 27/27 green).
- dirent_durability at grace=10 on 323: 10/10 PASS (fresh x4, aged x3 instr, aged x3 no-instr; one 240s/240s near-wedge lap, no DLM-wait signature) — race NOT re-tripped; original trip was 2/2 on 322. Ledger updated with all attempts.

## What sess38 proved/changed (details in the 2 earlier sess38 memories + CHANGELOG 319-323)
1. CREATEINT: correct-but-net-negative; default OFF (320).
2. PR-batch admission storms: FIXED (batch-completion-on-claim + guard relax, 322) — engaged, per-wait tails gone.
3. Turn economy quantified: 58ms p50/turn (drain-dominated); grace idle tail 40ms; discovery 2ms.
4. 322 board = FIRST ALL-GREEN 27/27 @32/caw. dir_reuse 2/3 (OPEN, bimodal).
5. NEW defect D-AGI-UNLINKED-CROSSNODE-RECOVERY-SHUTDOWN (#9, grace=10-exposed shutdown; canary armed).

## NEXT SESSION order
1. Full board on 323 (protects the canary build; expect =322 results).
2. dir_reuse margin: drain-cost/pipelining design (GPT first — log_force_seq shape REVERTED v0.3.38, do NOT retry; consider publish-before-notify pipelining of the release drain). Fixed round costs: presync 2.5s = 32-way flush congestion; rm 3s rank1-serial.
3. AGI defect: keep canary watch in every run; optional deeper repro (longer aging, board-mix at g10, or targeted 2-node bucket-collision unit: force two nodes to unlink same-bucket inodes concurrently — agino % 64 collision is constructible by ino selection).
4. Authority family (3 defects) — likely same root family as AGI defect; attack together with GPT design.
5. D-DIRVIEW-NONCONVERGE, D-MATRIX-UNMEASURED, D-READDIR-PEER-CACHED-DIR-PACE.

9 OPEN defects. Criteria NO.
