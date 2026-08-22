---
name: ccloop-c7ee71c6-sess295-503-convoy-quantified-GPT-ruling-fix-order
description: sess295: D-503 mechanism QUANTIFIED (convoy: 309ms fixed tenure x 32 rotation, per-create 5→50ms under load); GPT ruling = instrument timeline, nudge…
metadata:
  type: project
---

## sess295 — D-503 mechanism nailed from sess294's timeline; RULE-5 ruling obtained

### Refuted (RULE 4 2a)
"Holder sat on EX through 1-2 BAST retry periods" — WRONG reading of P34 dur_ms.
The P291-EXWIN grant chain (264 waiter-side wins in the 74s fail window) shows
CONTINUOUS, FAIR rotation: median handoff period 309ms, max 679ms, per-node win
counts 22-51 (even). No stuck holder, no unfair nomination.

### Proven mechanism (arithmetic closes)
- 32 nodes × 50 O_SYNC creates each into ONE shared dir (ino=26226559).
- Each node: ~8 tenures × ~6 creates/tenure ≈ 50 creates. Tenure ≈ 300ms
  (MHT bound + 15ms batch-grace). Per-create in-tenure cost ≈ 50ms during
  collapse vs ~5ms healthy → healthy fits 50 creates in 1-2 tenures; collapsed
  needs 8 rotations × (31×300ms) queueing ≈ observed 24-33s phases.
- P34-ACQ-SLOW dur_ms = queue depth × period (median adopt waited_ms 2219, max 15241).
- Release-side split: 268 mint (direct handoff CAS; adopt follows in 1-6ms) vs
  520 nom (ticket only; adopt ~225-330ms later = poll backstop). Mint requires
  !streak_yield && single nominee && zero holders in new image (PR readers block it)
  — dlm_caw.c:9012, caw_handoff_nominee_ok:5545, exwin log 5577/9290.
- P36-MHT-REARM ex=0 mode=0 lines are WAITER-side noise (acq_inflight makes dwork
  see busy); exh_ms tracks the local acquire wait, NOT holder tenure.

### GPT RULE-5 ruling (fix order)
1. INSTRUMENT FIRST: full mint/nom handoff timeline (nomination→unlock CAS→nudge→
   nominee read→adopt CAS→first op→last op→next release) + tenure decomposition
   (adoption-setup vs marginal-create vs release-drain). Must resolve the timing
   inconsistency: 300ms tenure + 300ms nom-poll should give ~600ms periods for nom
   handoffs, yet median is 309 — either poll overlaps outgoing tenure or the 520
   noms include retries/supersessions. B's value hinges on unlock→adopt idle time.
2. B (nudge fast-path): level-triggered, nominee-ONLY short retry ladder
   1/2/4/8/16ms after nudge; disk stays authority; send only after unlock CAS
   durable; keep 300ms poll as correctness backstop. Hazards: nominee-only (else
   CAS storm), gen/ABA, coalescing, dead-nominee skip.
3. D (sweep pacing): cap concurrent background release/drain per node/LUN,
   latency-feedback from foreground FUA/CAW; NEVER throttle BAST-driven or
   EX-demanded PR releases (else mint eligibility worsens); prefer releasing PR
   on locks with registered EX demand.
4. Measure marginal vs per-adoption cost (if truly 50ms marginal: 32×50×50ms=80s
   service-time lower bound — no scheduler fixes that; D is then mandatory).
5. Bounded op-credit batching (NOT wall-clock "extend toward MHT" — tenure is
   ALREADY at MHT so shape A as written is a no-op). Discrete modes: healthy
   300ms; high-adoption-cost 600-1000ms active-work cap; idle→quiet-age release;
   hard yield on BAST/lease deadlines. Peer-wait SLO: (W-1)×T ≤ L_peer.
6. Bounded EX/PR class epochs (drain PRs, several EX→EX mints per writer epoch,
   then bounded PR epoch) if PR coexistence stays the main mint blocker.
7. NO_TERMINAL_RECORD is a SEPARATE harness capture defect: supervisor should
   emit out-of-band TIMEOUT terminal records + incremental phase checkpoints;
   reserve capture time outside workload budget. (Candidate new ledger entry.)
Durable solution = B + D + bounded batching/class epochs.
D-32NODE-SHARED-DIR-CREATE-PACE is the same mechanism at lower amplification.

### Board chunk5 on .506 (sv 289E4A3F4164D39FFC7DF90), 32/caw, 00:51Z 2026-08-15
dirent_durability PASS 32/32 (66s/240s), dirent_publish_integrity PASS (3s),
dirent_type_integrity PASS (3s), open_defects FAIL by policy (36 open).
SOAK still not run on .506.

### Next
1) Land step-1 instrumentation (handoff timeline + tenure decomposition probes).
2) Then B, then D, re-measure between each (RULE 4).
3) Soak on .506; D-488 leg7 fault-inject + leg8; D-488 ledger rewrite.
