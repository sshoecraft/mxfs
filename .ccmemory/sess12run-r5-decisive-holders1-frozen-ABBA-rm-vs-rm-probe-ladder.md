---
name: sess12run-r5-decisive-holders1-frozen-ABBA-rm-vs-rm-probe-ladder
description: sess12 r5 DECISIVE: fence starve = holders=1 FROZEN 60s on t1 AG-0 (readopt=0, no re-adoption) + t1 rm waits hot-dir(164)-EX while t4 rm holds 164 wa…
metadata:
  type: project
---

# sess12 — r5 probe data kills shapes A/B/C; it's a hold-and-wait ABBA (rm vs rm)

## r5 (build AFEF43B92, artifact /tmp/run_fence_during_write_20260704T001728Z)
- t4 rm: `DLM AG lock failed ag=0 rc=-110` → defer_finish shutdown 00:25:58 (only t4 died this time).
- test1 = AG-0 stuck holder again (master t2 sent 60 P5B ag=0 BASTs → target test1).
- P12-AGBAST-RX on t1: **holders=1 CONSTANT, cached=0, sched=0, readopt=0, page_ms 0→60447** — NOT re-adoption ping-pong (shape A dead), NOT lost/queued work (shapes B/C dead: no unlock-last edge ever happened). ONE t1 thread held AG-0 inside one transaction for 60+s.
- t1's ONLY DLM waiter: `P36-RETRY ino=164 type=1 ag=0 mode=EX comm=rm` (60×1s, master of 164 = test4). ino 164 = fence HOT dir (mkdir'd by t1 at 00:24:56, P42-SFCONV).
- t4: 190/205 P7S-BAST-FIRE ino=164 target=t4 ITSELF = t4 holds 164-EX un-releasable (Approach-A defers BAST honor to trans_free) while its rm waits AG-0 → **cycle: t1(AG-0→164) vs t4(164→AG-0)**.
- Open question: IS t1's AG-0 holder the same rm (hold-and-wait, weird path — entry locks normally precede AG) or a third thread? P36-STACK + P12-HOLDERTASK answer next FAIL.
- Upstream order says rm takes dp EX BEFORE any AG in its trans → t1's AG→dir edge must come from an mxfs hook (ilock_begin unpublished-dir backstop / reload_prelock / mid-trans re-acquire after a swallowed release) or a non-rm holder.

## Probe builds (ladder)
- AFEF43B92: P12-AGBAST-RX/READOPT/WORK/ULBP (perag pending_since+readopt_n).
- 5126B737: + P36-STACK (dump_stack at FIRST acquire-timeout, cap 8/boot; mxfs_pal_dump_stack added to pal.h/kern.c).
- D9A38627: + pag_dlm_holder_pid/comm stamped at all 5 holders 0→1 sites + P12-HOLDERTASK (sched_show_task of holder when BAST sees page_ms>15s, cap 6/boot; needs linux/sched/debug.h).
- 864C59A0: + P10-DIRDUMP-BLK prints lba= (daddr+bt_sector_offset) + drc script dd's raw blocks (O_DIRECT) to /root/drc_blkdump_r<round>_rank<R>/ at RDMISS.

## Second blocker: dir_reuse 1-dirent durable loss (r7, node1_f17.md5 round2)
- Probe trail PERFECT: add@aoff=2448 (t1), all later adds sequential 2480,2512,... no collision/reuse; every cross-node EX FUA-read saw the prior sum (coherent chain); each add immediately durably written (P-DIRWR in_ail=1 per add).
- Verify: readdir misses f17 on ALL 4 nodes, but LOOKUP SUCCEEDS (lookup_fail=0) → final durable block is INTERNALLY inconsistent: entry at 2448 valid (exact-offset read OK) but walk-chain (prior entry/unused length) skips it. NOT stale-whole-block (later entries visible + count off by exactly 1).
- Disk evidence lost (next run re-mkfs). Raw-block capture now armed in drc script (build 864C59A0) — decode entry chain around the missing offset on next RDMISS.

## Suite ledger (full 4/tcp, ~17 min/iter via tests/suite_iter.sh — recycles VMs first)
r4 FAIL(fence starve, 2 shutdowns) / r5 FAIL(fence starve, 1 shutdown) / r6 PASS / r7 FAIL(drc 399/400) / r8 PASS. Flake ~40-60%.

## Next
1. Loop tests/suite_iter.sh on 864C59A0 until fence FAIL → read P36-STACK (both rm's) + P12-HOLDERTASK (t1 AG-0 holder identity/stack) → name the AG→dir edge → design fix (FIX3-style ordering or break t4's164-hold via bounded honor).
2. On drc RDMISS → decode /root/drc_blkdump_*/blk_*.bin entry chain around missing offset.
3. Gotcha: shutdowns wedge rmmod — suite_iter recycles VMs every iter anyway.
