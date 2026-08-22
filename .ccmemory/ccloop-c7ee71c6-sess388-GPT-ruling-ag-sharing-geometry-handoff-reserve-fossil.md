---
name: ccloop-c7ee71c6-sess388-GPT-ruling-ag-sharing-geometry-handoff-reserve-fossil
description: sess388 RULE-5 rulings: AG-sharing pace = geometry (agcount>=nodes, 2x perf class; LUN 128GiB for 32 nodes), handoff protocol order, nonblocking inod…
metadata:
  type: project
tags: [sess388, ruling, ag-sharing, geometry, handoff, inode-reserve, fossil-next-unlinked, 474, pace]
---

## Context (sess388 measurements that triggered the consult)
- rsync_paired lap 2+ @32/caw: the 14 slow/exhausted nodes == the 14 nodes whose AG affinity
  (node_slot % agcount) collides (agcount=25 on the 50GiB LUN; 32x64MB log slices = 2GiB log
  must fit one AG -> agcount = device/2GiB). Exclusive-AG nodes 22-27s; shared-AG 34->60s+.
- Shared node: 40-58 fresh AG acquires (exclusive: 1), P12-ULBP 80x, P12-READOPT 80x,
  peer BAST->release wait med 110-240ms p90 2-3s max 9s SUM 43-90s/node.
- tests/rsync_stall_stacks.sh (new) 10Hz stack sampling: 27% AG CAW poll, 21% inode CAW poll
  (dialloc reserve on peer-cached freed inos), 9% slot scans, 6% inside __mxfs_ag_dlm_lock.
- #474 root proven+fixed 0.19.35: nonblock AG acquire parked on pag_dlm_acquire_lock (held
  by a sibling across its CAW poll) with ILOCK held -> AIL freeze -> relfence wedge.
- New defect: fossil di_next_unlinked read at iget on a reused+evicted inode -> P-IUNL-LOGSAME
  -> rename dirty-cancel shutdown (deterministic with identical rename order per lap).

## Rulings (gpt-5.6-sol)
1. GEOMETRY: legitimate sizing rule: agcount >= max_active_nodes (minimum); >= 2x for the
   advertised perf class. mkfs (-n already = node count) should compute/warn; mount/join warns
   loudly when active slots > agcount; expose collision map. nodes > agcount must stay
   CORRECTNESS-supported (no shutdown/deadlock/corruption) but pace is not promised.
   Verification: reformat >=64 AGs with NO lock-code change, 20-30 regenerated laps all <60s,
   zero shared home AGs, cross-node home-AG acquires ~0; retest 25 AGs for correctness+warning.
   GFS2/OCFS2: rgrp/allocation-group sharing is correct but sizing is a real perf parameter.
2. HANDOFF (order): (1) latch pending BAST and CLOSE local re-adoption (existing users finish;
   no new adoption; releasing node must not race to reacquire before the waiter: back off until
   ownership generation changes / peer cancels / fenced / waiter-validity timeout);
   (2) dynamic affinity steering when agcount > nodes (home-AG hint, contention metrics,
   hysteresis); (3) bounded batching: quantum ~20-50ms or 32-128 ops, hard local-admission cutoff
   50-100ms after BAST, BAST->release median <100ms p99 <250-500ms, time AND op limits (never
   only N ops); the current "halve quantum toward 1 under contention" is directionally WRONG;
   (4) drain telemetry/reduction without weakening publication ordering; (5) 3+ contenders need
   ticket/queue (min-hold alone is unfair). Verify: BAST->gate, BAST->release, post-gate
   readopts=0, ops/epoch, per-node bounded progress, 2- and 4-contender harness.
3. INODE RESERVE: nonblocking inode-lock probe BEFORE committing the allocation choice; prefer
   candidates this node holds EX on / own chunk color / recent-free ring; skip peer-held with
   short cooldown, bounded probes, spill to other chunk/AG; never a 1s wait under the AG lock;
   hints never affect correctness (inobt/finobt authority). Consider releasing cached EX of
   freed inodes in contended AGs. Verify: reserve timeouts exceptional, inode-poll share drops,
   no false ENOSPC, fragmented-AG spillover test.
4. FOSSIL next_unlinked: (iii) durability/publication gate is THE fix: removal-commit <
   NULLAGINO home-write completion (or globally-visible versioned overlay the reader MUST
   consult) < free/reuse publication < authority release; pin the dirty inode-cluster write to
   the authority-release fence ("flush skipped because authority released" must be impossible).
   (ii) store-at-iget keyed by (ino, gen/epoch, txn seq) is a valid defense for same-node
   evict/re-iget and a stale-home detector. (i) forcing NULLAGINO on nlink>0 at iget is UNSAFE
   (nlink=1 + non-NULL next can be an unlanded CURRENT unlink split). Verify: fault-inject each
   boundary incl. cross-node iget; thousands of unlink-free-reuse-evict cycles, 0 LOGSAME.
