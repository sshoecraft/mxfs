---
name: ccloop-c7ee71c6-sess390-readopt-close-two-failures-latch-design
description: sess390: closing AG re-adoption at ACQUIRE time failed twice at 25 AGs — arm 3 (blocking waiters) wedged 2 nodes, arm 4 (pinned re-adopt + nonblock r…
metadata:
  type: project
tags: [sess390, readopt, AG, handoff, livelock, PACE-388, ULBP, 0.21.3]
---

# sess390 — AG re-adoption closure: two measured failures, the storm root, the next design

## State at handoff
0.21.3 sv A0308D3A12C83AC1FB12A1C on the 32-node rig, 64 AGs. Defaults: noino_lifecycle_requeue=1 (measured clean), ag_readopt_window_ms=-1 (INERT — do not arm). Code for the gate lives in __mxfs_ag_dlm_lock's cached fast path: nonblock -> -EAGAIN (P-AGTRY-BASTPEND), RESFREE class (mxfs_ag_dlm_lock_resfree: pregrant + P271 seam) waits, everything else PINNED re-adopt (P12-READOPT-PINNED) + quantum_eff=1; stats readopt_closed/readopt_pinned/readopt_resfree.

## Arm 3 (0.21.0, window=50, blocking acquirers WAIT until cached&&bast_pending clears)
rsync improved for 26 nodes (14-44 s) but test24/test32 P-NOINO-RELFENCE-WEDGE: the INODE BAST worker (mxfs_dlm_bast_process -> filemap_write_and_wait_range -> xfs_bmap_btalloc -> blocking pass) holding ILOCK_EXCL waited in the loop (not in the agwait bracket, convoy_stalls=0) -> fence froze on its inode item -> shutdown. tests/logs/ag25_sess390_readopt_close_wedge.txt. GPT: never make a blocking ILOCK holder wait at the gate.

## Arm 4 (0.21.2/0.21.3, nonblock refused, blocking PINNED re-adopt, quantum 1)
readopt_closed 1.5-2.2 MILLION and readopt_pinned ~same in ONE lap on 13 nodes, fresh fs: every rsync allocation trylocks (refused) then blocking pass (pinned adopt) every ~3 ms (P12-READOPT-PINNED ag=0 comm=rsync holders=0 sched=1); hogging nodes finish rsync in 6-7 s, 12-15 peers sharing the AG never finish. 0.21.2 variant also spun the -488 restart protocol (pregrant re-adopted pinned -> trylock refused -> restart) until the RESFREE class was added (0.21.3: resfree=0 in the lap, so the remaining spin is the plain trylock->blocking pair).

## Root of the storm
P12-ULBP (last holder unlock with BAST pending) schedules the AG BAST worker asynchronously; a re-adopter wins the next holders 0->1 before the worker runs (bail1-holders), 3 ms cadence vs worker latency. An admission gate at ACQUIRE time either wedges ILOCK holders (arm 3) or starves peers (arm 4) — the race has to be closed at the UNLOCK.

## Next design (ruling-2 'latch pending BAST and close local re-adoption')
In mxfs_ag_dlm_unlock's ULBP branch (xfs_mxfs_dlm.c ~43667): when holders->0 && bast_pending (past a short window), set a handoff latch (new pag_dlm_handoff_latched or pre-set pag_dlm_demoting) under pag_dlm_lock BEFORE queueing the worker, so no 0->1 re-adoption can win; the worker clears it on every bail/commit path (study mxfs_dlm_ag_bast_work_fn ~44700-45030: enter / bail1-holders / bail1-uncached / bail2-holders / COMMIT demoting / mint). Blocking acquirers then park in the existing mxfs_ag_dlm_wait_demote — bracket THAT wait in pag_mxfs_agwait_inflight so the convoy-aware noino fence classifies it (it is the same wait as a peer-held CAW wait); nonblock -> -EAGAIN (P-AGTRY-DEMOTING exists). Measure BAST->holders==0, holders==0->release, BAST->release p50/p99, post-latch readopts (target 0), rsync wall spread, zero wedges, zero INODE-item freezes owned by the BAST worker.

## Harness
25-AG prep: MXFS_MKFS_OPTS="-d 50G" MXFS_FORCE_PREP=1 D385_STEP="arm_prep TREATMENT"; one lap per call; knobs via /sys/module/mxfs/parameters/{ag_readopt_window_ms,noino_lifecycle_requeue,ailstuck_probe}.
