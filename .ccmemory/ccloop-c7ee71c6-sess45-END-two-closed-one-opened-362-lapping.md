---
name: ccloop-c7ee71c6-sess45-END-two-closed-one-opened-362-lapping
description: sess45 END: P195 FIXED+VERIFIED, UV-COUNT-MISS DISPROVED, new rsync-rename critical contained (362) + 5 clean laps; 11 OPEN of 38; rig 32/caw on 362
metadata:
  type: project
tags: [ccloop, session-end, sess45]
---

# sess45 END — state for the relay

## SCORECARD (all evidence in ledger + per-topic memories)
1. D-DIRENT-PUBLISH-STALE-BASE-P195-360 (major) — **FIXED AND VERIFIED**
   (0.11.361): full GPT Option-B contract; boards green 32+8; 24 aged loops
   (predicted ~3 hits, got 0); storm 60r clean; 1 gate-arm all day (the
   backward-epoch != case); no pace regression. See
   ...-P195-CLOSED-361-option-b-shipped.
2. D-CACHE-COHERENCY-UV-COUNT-MISS-2332 (critical) — **DISPROVED**: one
   degraded member reproduces rank1 654/653/1 `uv exp=128 got=124` exactly
   (accidental perfect fsdown landing, faildist[1x1,343x1]); healthy fleet
   23×cc + 11×zsl green same day. See ...-UV-COUNT-MISS-DISPROVED-*.
3. **NEW** D-RSYNC-RENAME-DIRTY-CANCEL-MASS-SHUTDOWN-361 (critical, OPEN):
   17/32 independent dirty trans_cancel in xfs_rename under rsync_paired.
   Root family known (stale-base dirent erasure; revalidate target gap).
   0.11.362 containment shipped (P217 preflight -ESTALE restart + dirty-
   cancel cookie probe + reload_stamp_at_commit lever). 5 clean laps since
   (3 armA/2 armB), P217 0x, 1 lap hostload-excluded. Protocol in ledger.
4. crash_consistency NOTERMINAL: run.sh last_phase_census now captures
   kill-time kmsg phases (stdout tails are buffering-lost). Untested live.

## LEDGER: 11 OPEN of 38. Boards green both scales on 361; 362 = 361 +
containment/probes only (no behavior change off the rename error path).

## RIG: 32/caw on 0.11.362 (41070DFD73787A93E05F8CF), all 32 mounted,
marker current, reload_stamp_at_commit reset to 0 fleet-wide. Board rows
from the hostload-55 window re-run green.

## HOSTLOAD DISCIPLINE (cost a lap today): clyde runs an external game
server (Wow.exe/worldserver) that bursts to load 45-55. NO pace-sensitive
lap/A-B while 1-min load >30; hostload= stamp discriminates. Do NOT touch
those processes (user's).

## RELAY QUEUE (post-lap continuation)
- Lap the rsync sequence opportunistically (task #3 protocol).
- criticals: D-INODE-CLUSTER-PUBLISH-WITHOUT-AUTHORITY — GPT sess33 ranked
  work: implement write-unit authority via ICLUSTER routing (candidate
  mechanism named in entry tail); D-FOREIGN-REPLAY (certified replay,
  architectural); D-CROSSNODE-OPEN-UNLINK C9-tcp (blueprint in memory;
  tcp rig UNWIRED — host LUN + VM XML work needed first).
- high: D-DIRVIEW-NONCONVERGE (aged repro). majors: 2×pace,
  crash_consistency NOTERMINAL (census armed — next natural occurrence
  self-diagnoses). minors: MATRIX-UNMEASURED (tcp rig), BOGUS-IMODE.
  unknown: AGI-UNLINKED-CROSSNODE.
- P216-B-STATS + P217 sweeps after every big run; sudo -n serial logs after
  churn (UAF-family standing rule).

## DO-NOT-RE-DERIVE
- P195 machinery map + all six brace-bug sites: see the P195 memory.
- rsync-rename attribution priors + instrumentation design: GPT text in the
  ledger entry gpt_ruling_sess45.
- degraded_member_cascade needs >600s at N=32 — drive arms manually.
- remote nohup watchers SURVIVE ssh teardown (pkill explicitly; prefer
  clyde-side); run.sh@32 pre-assert >22s (fixed-delay drops hit it).
