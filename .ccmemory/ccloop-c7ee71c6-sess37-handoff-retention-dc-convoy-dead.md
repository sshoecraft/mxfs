---
name: ccloop-c7ee71c6-sess37-handoff-retention-dc-convoy-dead
description: sess37 part2: direct EX handoff+PR batch (314/315, anatomy 8.6x A/B), clean-PR evict retention (316), local eofblocks peek (317) — dc convoy 6-9s→0.1…
metadata:
  type: project
---

# sess37 part 2 — pace-family campaign (builds 314-317)

## Shipped, each RULE-4 stack/A-B proven
1. **0.11.314 DIRECT EX HANDOFF** (dlm/dlm_caw.c, knob mxfs.caw_direct_handoff=1): release CAS transfers ownership to the fair-handoff EX winner in the SAME CAS (holders_ex|=W, clear W waiters, yield_to=0, epoch/streak done FOR W: dir_epoch++ if last_ex_slot!=W, last_ex_slot=W). Winner ADOPTS on sight: adopt branch in caw_wait_for_grant needs reg_gen (generation the registration CAS wrote, new param threaded from both callers) + gen>reg_gen + own waiter bit CLEARED + holder bit in requested mode. ad_handoff derived by comparing slot dir_epoch vs cached grant_meta epoch (caw_grant_meta_get_epoch helper; no cache=true). Nudge targets ONLY the winner (p6h_handoff_bit). GPT-ruled ownership-incarnation conditions; abort-reconcile: caw_drop_own_waiter got giveup_mode param — clears own holder bit of the abandoned mode in the same CAS (P6H-ABORT-RECONCILE), covers handoff-landed-mid-abort AND ambiguous-CAW-landed (sess34 SIGKILL wedge class). Prints P6H-HANDOFF/P6H-ADOPT.
2. **0.11.315 PR BATCH GRANT**: streak-yield arm direct-grants the whole PR class in the release CAS (holders_pr|=pr_w, streak reset via grant_streak_note(PR)); P6H-PRBATCH. Measured need: 823 streak_yields vs 310 EX handoffs. **Same-build A/B 32/caw anatomy (tests/caw_grant_wait_anatomy.sh 8 32): knob on = 11.1s total wait/75 grants/max 255ms; knob off = 95.8s/171/max 2657ms — 8.6x, no overlap. Creates mean 109ms vs 235.**
3. **0.11.316 EVICT-RETAIN-PR** (knob mxfs.evict_retain_pr=1, xfs_mxfs_dlm.c mxfs_dlm_evict): clean PR grants retained across eviction (no wire unlock); demand-release via proven noino BAST path; free boundary safe (free needs EX which excluded PR bits first); unmount safe (release_all sweep); EX NEVER retained. Root: DCSTK stack sampler (added to dir_reuse dc poll loop) caught 32 nodes in caw_slot<-unlock_gen<-v5_dlm_inode_unlock<-mxfs_dlm_evict — barrier-aligned dc unlock CAS storm on hot slots walking 5s unlock deadline. P6R-RETAIN print.
4. **0.11.317 LOCAL EOFBLOCKS PEEK** (xfs_bmap_util.c xfs_can_free_eofblocks tail): the in-core peek took xfs_ilock(SHARED)→full DLM wire acquire per EVICTED inode (stack: mark_reclaimable→needs_inactive→can_free_eofblocks→ilock); replaced with raw down_read_nested(&ip->i_lock) — no dlm hooks, symmetric.
RESULT: dir_reuse dc-real (new marker) = **0.10-0.15s** (was 6.3-8.8s). CONVOY DEAD.

## dir_reuse still FAIL (7 rounds vs 8): new split (markers wrbar-done/presync-done added)
Round r6/r7 rank1: create ~3s own + **wrbar (slowest creator) 8-9s** + sync 2.2-3.0s + dc 0.15s + ls 0.1 + lookups 1.6-2.4s + rm 3.3-3.4s + mkdir/create-start ~3.4s ≈ 17s. Need ≤12.5s.
- Create rotation: **1496 dir(ino131) handoffs in 7-round lap ≈ 214/round** (128 creates + rm + mkdir) — dir_ex_batch_grace_ms=40 NOT bridging create loop gaps at 32-load (each create its own tenure). dir_ex_tenure_floor=1/inode_mht_ms=300 exists. P6H-ADOPT tails 356-1183ms elapsed (whole-wait incl queue).
- NEXT LEVERS: (a) make one node's 4 creates share one tenure (raise batch grace? measure actual inter-create gap under load first); (b) adopt-latency (winner notices grant: reads=3-31 before adopt); (c) sync 2-3s (32-node log force+flush herd); (d) rm cohorting (GPT: hold dir EX across unlink run, per-cluster tenure batching — see sess37 GPT consult #3 in transcript).
- GPT consult #3 full prescription: retained-grant ledger ranked #1 (DONE as retention), release combining #2, dir/inode lock-domain split #4 (format risk). rm target: 4-5 cluster tenures not 128.

## CAUTION / pending
- **Board on 317 NOT yet run** — handoff/PR-batch/retention are invasive; full 32-board required before any disposition updates. Boards 313=20/21 (dir_reuse only FAIL).
- teardown_leak_repro.sh now uses tests/mxfs_shutdown.sh (GOINGDOWN 0x8004587d via stub ioctl, 312) — xfs_io shutdown NEVER worked on mxfs (all xfs ioctls stubbed ENOTTY).
- dir_reuse_coherency.sh gained DRCph sub-markers (dc-real-done, wrbar-done, presync-done, ls-done, lookups-done) + DCSTK stack sampler (head -14, in dc poll loop) — keep; they're cheap and load-bearing.
- D-DWORK-TEARDOWN-LASTREF-LEAK = FIXED AND VERIFIED in ledger (313: arm gate all 25 sites + put_super s_inodes sweep; P6S-ARMSWEEP cancels=1 refs=1 ×7 engagements, 0 leaks). 8 OPEN remain.
