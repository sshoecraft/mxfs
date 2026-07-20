---
name: AAA-ccloop7251-sess8-TCP8-DRC-DIRENT-LOSS-dossier
description: TOP FRONT: tcp@8 drc round-8 TOTAL dir image loss (800 dirents, all nodes) + divergent dir_gen views + AIL FLUSHING wedge + P71 underflow cycle. Evid…
metadata:
  type: project
tags: [ccloop-72513a13, sess8, tcp, correctness, dirent-loss, RULE4]
---

# tcp@8 dir_reuse_coherency round-8 catastrophic dirent loss — full dossier

## What happened (0.11.31 = 2A8C8F26, 8/tcp rung, run_id 20260719T125238Z)
At round 8 of 24 (rounds 1-7 clean), the shared drc dir (ino **17318208**, fmt=2)
went EMPTY cluster-wide at verify: readdir=0 of exp=800 on every rank AND
~5600 `mxfs-drc-CLASS ... LOOKUP_ENOENT REREAD_MISS` lines ≈ ALL 800 names ×
all 8 verifiers (nodes' own files missing LOCALLY too — test8 ENOENTs its own
node8_f9 it created that round). BARRIER_TIMEOUT=8 ended the test at 1380s.

## The three synchronized signatures
1. **Divergent dir generation views** at the round-8 create wave (t≈6238-6244
   on test1's clock): every node fired `P63-HANDOFF ino=17318208 ...
   post_release=1 fmt=2` but with WILDLY different dir_gen: test1
   dir_gen=14/loaded=13 (!!), peers dir_gen=57-63. Most peers show
   acted_gen=0 valid_epoch=0 (fresh acquires); test1+test6 have real
   acted_gen (18442/18682 vs grant_gen 18728/18721). test1 was acting on a
   STALE INCARNATION of the dir (dir-reuse resurrection family — CAW-side
   twin: AAA-ccloop8ba7-sess6-END stale-fork-resurrection).
2. **test8 AIL wedge**: P128-AILSTUCK loops (iter 90000+) on ONE inode
   cluster buffer (daddr 0xa7f908/0xa7f928 BUFs + INODE items 11027904/05/06,
   lsn=0x100007105, liflags=0x21 = IN_AIL|FLUSHING, pincount=0, bflags
   0x500020) — the documented `_XBF_DELWRI_Q` collision family (items parked
   FLUSHING forever when the buf sits on an mxfs drain list nobody drains).
3. **P71-UNDERFLOW cycle**: `ino=11027904/05/06 mode=EX state=1 dlm_mode=5
   comm=kworker/0:0` every ~5s forever after the failed verify — EX
   ilock_end underflow on the SAME inodes stuck in the AIL (teardown of the
   orphaned round-8 inodes is broken: dirents lost ⇒ inodes unreachable).

## Also red at 8/tcp (same rung): posix_multi FAIL=3 nodes (2 checks),
## fence_during_write 97s/60s (1 node). 2/tcp and 4/tcp drc: 24 rounds CLEAN.
## So the class opens between N=4 and N=8 on tcp.

## Evidence locations
- Bundle: `tests/logs/tcp8_drc_wedge_20260719/dmesg_test{1..8}` (3000-line
  tails; test8's has the AILSTUCK + UNDERFLOW cycle; all have the round-8
  drc-CLASS/FAIL + last P63/P65 lines).
- Rung log: `tests/logs/ladder_rung_8tcp.log`. Run dir artifacts:
  `/tmp/run_dir_reuse_coherency_*` on clyde (auto-collected on abort).
- test8 kernel clock is ~1000s ahead of peers (different boot) — pair events
  by phase markers, not raw ts.

## Repro
`scripts/rig.sh tcp 32` (if not up) then
`MXFS_FORCE_PREP=1 RULE0_CALIBRATE=1 ./run.sh 8 tcp prep_cluster` then
`RULE0_CALIBRATE=1 ./run.sh 8 tcp dir_reuse_coherency` (bg; breaks ~round 8
= ~8-10 min in; 2/4-node never break). Cluster after: WEDGED (kill leftover
dir_reuse procs on nodes; FORCE_PREP recovers).

## Hypothesis stack for next session (NOT yet instrumented — RULE 4 step 1)
- H1: rm-recreate reuses the dir inode; a node with a stale in-core dir fork
  (gen 14 vs 57) wins the round-8 create-wave EX at some point and PUBLISHES
  its stale (near-empty) dir block0/leaf as authoritative — wiping the other
  nodes' round-8 dirents (the disk-superset adopt claims "superset" but a
  divergent-gen writer's publish isn't superset).  Why is test1's gen stale?
  TCP-side epoch/gen consultation changed in sess7 (gg-consultation made
  TCP-only; CAW-era eager-demote publish / WAVE A may have altered TCP
  release ordering).  Instrument: log dir_gen/epoch at every EX
  publish+adopt on the drc dir (P63 fields exist — add a publish-side twin)
  and catch WHO wrote block0 with what gen at round 8.
- H2 (secondary wreckage): AIL FLUSHING items = inode-cluster buf on an
  mxfs list never drained on tcp; find which list (bflags 0x500020 decode)
  and which pipeline should have drained it.
- Consider RULE 5 GPT consult with this dossier if round-1 instrumentation
  doesn't converge — the family has deep prior context (P63/P65/superset
  adopt design was a GPT-reviewed CAW fix; its TCP interaction was not).
"""
