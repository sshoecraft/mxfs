---
name: sess8-part3-readdir-tear-xfsaild-dirblock-root
description: sess8 part3: readdir-undercount ROOT EVIDENCE (run112, 4/tcp r2): unused-chain swallows live dirent; t2 xfsaild wrote shared dir block mid-peer-tenur…
metadata:
  type: project
---

# sess8 part 3 — readdir undercount (dir_reuse 4-node) root evidence

## Reproducer (fast, ~4min)
Clean cycle 4 VMs → `MXFS_EXTRA_MODARGS='dir_relverify=1 leafprobe=1' ./run.sh 4 tcp dir_reuse_coherency` → FAILs round 2 with `readdir=399/400 lookup_fail=0`, missing name identical on ALL nodes (incl the creator!). run112 evidence in scratchpad dmesg112_t{1..4}.txt (session 6d09e32f).

## PROVEN shape (run112, missing=node4_f19.md5)
- Lookup finds the name (leaf hash → offset 3272 → dirent bytes INTACT); readdir misses it on every node ⇒ the DURABLE block image's UNUSED-ENTRY CHAIN swallows offset 3272 (an unused descriptor before it spans past it). Intra-block tear: entry bytes present, walk-metadata inconsistent. 123s verify retry loops blow the 300s budget at 4 nodes (8-node budget 480 hides it more often).
- t4 added node4_f19 @daddr=4186528 aoff=2000 and f19.md5 @aoff=3272 on a P58-flagged gen-stale base (dir_gen=7 loaded_gen=6). t3 concurrently streamed adds into the SAME daddr at aoff 3400+ (P13-LADD both sides).
- **test2 (not even in the add streams): `P3W-DIRWR owner=131 daddr=4186528 lseq=7 wseq=0 pin=0 in_ail=1 dirty=0 skip=0 comm=xfsaild`** — its xfsaild WROTE the shared dir block from its own (older-tenure) cache. Same uncoordinated-writeback class as the FIX-22 SF-dinode ratchet, but for DIR DATA blocks. skip=0 ⇒ a skip guard exists at pal/linux/xfs_buf.c:3290 region and did NOT engage.
- Also `P-DBLALLOC agno=2 agbno=10 daddr=4186528 holds=dir-block magic0=XDB3 tenure=1 node=2 wasfromfl=0` at 53.426 on t2 — the block was reallocated while carrying a live-looking dir image (rm-rf/recreate daddr+ino reuse ABA context).

## NEXT (exact thread to pull)
1. Read pal/linux/xfs_buf.c ~3250-3300 (P3W-DIRWR print + its skip condition). sess40 memory: "dir-block ABA writeback skip (build B9F9326E UNVERIFIED)"; sess16 lead: extend mxfs_buf_xfsaild_skip_bmbt_write (sess61 P61-CHOKEPOINT-SKIP-BMBT) to dir dirent blocks. Design: xfsaild must not write a multinode dir DATA/leaf block when we don't currently hold the dir EX (or when b_epoch lags valid_epoch) — rotate/requeue instead (FIX-19 pattern). Careful: lseq/wseq (logged vs written seq) machinery already on the buffer; wseq=0 lseq=7 = never-landed committed block (FIX-16 class dir blocks are mxfs-seq!).
2. After fix: rerun run112 repro; then FULL 4/tcp (also fixes tds mesh? unrelated), then re-check 8/tcp (run110 was 15/17: dlm_scaling setup visibility race + tds pace/ghosts remain there).

## Ladder state after run110/111 (build 38D787B1)
- 8/tcp: 15/17 (dlm_scaling 7/8 setup-visibility race on 1 node; tcp_dlm_scaling 2/8 pace+drained=2 ghosts+barrier churn).
- 4/tcp: 14/17 (dir_reuse 0/4 THIS readdir tear; fault_netpartition 3/4 "healed node sees partition writes got=0"; tcp_dlm_scaling 0/4 "tcp mesh >= N-1" on all nodes).
- 2/tcp, 1/tcp: NOT yet run this generation.
- tds residual ghosts (n1_r128, n8_r40 in run110) = post-FIX-22 second seeder, rate ~2/1200 rounds; needs P8 ledgers (dir_relverify=1) to trace.
