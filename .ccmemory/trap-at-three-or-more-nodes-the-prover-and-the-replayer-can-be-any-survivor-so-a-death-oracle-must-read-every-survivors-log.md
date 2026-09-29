---
name: trap-at-three-or-more-nodes-the-prover-and-the-replayer-can-be-any-survivor-so-a-death-oracle-must-read-every-survivors-log
description: TRAP (0.90.10, 4/cawd crash_audit FAIL): test3 fenced+snapshotted the victim while W=test1 replayed; the oracle read only W's log and failed a correc…
metadata:
  type: feedback
---

# At 3+ nodes the prover and the replayer can be any survivor

**Measured 2026-09-28, 4/cawd board, `crash_audit` FAIL (oracle 118 s, 1198 files
verified OK).** The two failed assertions were "fence certified exclusion
(P236-FENCEKIND proves_excl=1)" and "P-RMAN-SNAPSHOT taken for the victim's slot",
both counted on W=test1's kernel log. test3's log held them: `P304-FENCE-ARM slot=1
... prover=3546399278`, `P236-FENCEKIND ... kind=PREEMPT_ABORT_PROVEN_V1(23)
proves_excl=1`, `P-RMAN-SNAPSHOT slot=1 ... entries=1207`. test1 logged
`P238-FENCE-DONE slot=1 — this victim is already certified fenced by another
prover` and then did the replay (`foreign replay of slot 1 complete`, P163). The
filesystem was right; the harness assumed W proves. The same 4/tcp row PASSed the
same day only because test1 happened to win the prover race.

**Which node fences is a race among all survivors** (death detection, then the
durable `P304-FENCE-ARM`), and the replayer is elected separately. Nothing makes
the node a harness picked as "survivor" either of them.

**What follows for any death/fence harness at N > 2:**
- Pass every mounted member (tests/tcp_death_replay.sh: `TDR_MEMBERS=<csv>`;
  tests/death/crash_audit.sh derives test1..testN from `MXFS_NODES`, and
  tests/tcp_2node_death_chain.sh passes `MXFS_NODE_LIST`).
- Read prover-side and replay lines from a MERGED capture of every survivor
  (`wds`/`wdscap`, lines prefixed `[node]`, the rsx status record left bare so
  capture_require still aborts on a failed read); keep W's own capture for the
  workload/verify side only.
- An injection meant for "the prover" (fence_gate_inject_refuse, blocked_after_ms)
  must be armed on EVERY survivor, the prover found by its own transition line
  (P238-FENCE-BLOCKED), and cleared on every survivor afterwards.
- "The last member's unmount" is not W's at N > 2: unmount the peers first
  (crash_audit.sh does now), or the cold audit reads counters a mounted peer
  still holds in core.
- A 2-node PASS of such a harness says nothing about its N-node validity; the
  first N-node run is a harness run before it is a filesystem run.
