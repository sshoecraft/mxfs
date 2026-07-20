---
name: sess43-INFRA-and-multimode-trace-state
description: sess43 infra+state: drc_trace.sh harness, 64K dland ring (5F0C1457), non-ratelimited P13; loss has MULTIPLE modes (round-1 pure-create + round-24 rm-…
metadata:
  type: project
---

## sess43 (ccloop) — diagnostic infrastructure + multi-mode state. Read with [[sess43-KEY-loss-is-round1-pure-concurrent-create-not-reuse]].

### Build 5F0C1457 (keeper-FUNCTIONAL for 1/2/4 — verify before trusting): dir_owner_scan default 0; the only other changes are DIAGNOSTIC + storm-scoped: P13-NADD/LADD made non-ratelimited (capped 60000, ino<=256 + node* names only), dland ring 4096->65536 (~1MB static, only populated when mxfs.dirland=1). No behavior change to the lock/IO paths. (If paranoid about the extra dmesg volume on 1/2/4, the P13 cap + dland are harmless — but a clean re-verify of 1/2/4 tcp is owed before any criterion claim.)

### NEW infrastructure (RULE 3, in-tree, reusable):
- **`tests/drc_trace.sh [iters] [rounds] [nfiles] [modargs]`** — reboots 8 nodes clean each iter, runs 8/tcp dir_reuse with **DRC_STREAM=1** (rotation-immune per-node `dmesg --follow` → tests/tcp/drc_cap/stream_rank<R>.log, NFS-shared to dev host) + DRC_ROUNDS/DRC_NFILES via MXFS_TEST_ENV + EXTRA_MODARGS. On fail prints VICTIM + its P13 adds. The stream files survive the next reboot (live capture).
- 64K dland ring now holds a whole 24-round run (the 4096 ring rotated past the failing round's create wave — the test CONTINUES past a fail through all rounds, flooding the small ring with later teardown).

### MULTIPLE failure modes observed (do NOT assume one root):
- **Mode CREATE (round 1, round 21): pure concurrent same-dir create, NO reuse.** Victim added by creator (P13), then lost; the acquiring peer holds EX and evicts+RMWs the victim's block. This is the core coherency bug. node5/rank5's adds were the victim 3/4 traces (node5_f1, node5_f18.md5, node5_f42) — POSSIBLE rank5-specific angle worth checking (is rank5 a consistent loser? master/affinity?).
- **Mode BOUNDARY (round 24, the LAST round): rm-rf-reuse-boundary race.** rank5's round-24 create window was anomalously 0.27s (vs ~7s) — files from round 23 likely not fully rm'd by rank1, so dd/md5 truncated existing files (no dir adds, P13 silent), and the victim was rm'd by rank1's round-23 rm-rf but not recreated → genuinely absent at verify. May be a test-artifact of the last round racing teardown, OR a real free/realloc coherency race. Distinguish from Mode CREATE — don't conflate.

### CAVEAT (cost me time): per-node `dmesg [NNN.NNN]` timestamps are BOOT-RELATIVE, NOT cross-node comparable. Use round PHASE markers (create-start/done/verify-done/rm-done, coord-synced) for cross-node ordering, or the dland `t=` (ktime_get_real_ns, wall-clock) for fine global ordering.

### NEXT (decisive, RULE 4): run `tests/drc_trace.sh 8 24 50 dirland=1`; on a fail at an EARLY/MID round (NOT the last round 24 — re-run if it lands on 24), take the victim's round-N P13 add daddr, then with the 64K ring intact dump+grep `P-DLAND d=<daddr>` for round N globally (real-ns ordered): find the creator's write that includes the victim (count K), then the write that produces the final image WITHOUT it (count + sum) — its node/comm/incarn names the clobber path (create-wave RMW vs teardown). Then fix at THAT path. Also worth: a non-ring STREAMING dland mode (print each write to dmesg, caught by DRC_STREAM) to fully sidestep ring rotation.</body>
