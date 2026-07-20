---
name: AAA-ccloop8ba7-sess6-END-iter13-PIVOT-stale-fork-resurrection
description: sess6 FINAL: iter_13 P145 INVERTED the mechanism — block WAS freed (test25 rm); bug = uv dir fork SHRINK lost/resurrected on disk (stale superset re-…
metadata:
  type: project
tags: [ccloop-8ba7ae5c, sess6-end, double-alloc, stale-fork, handoff]
---

# iter_13 PIVOT (supersedes the iter_10/12 'never freed' premise — read AFTER the other two sess6 memories)

## The P145 probe INVERTED the mechanism
iter_13 (build A3BD5947 = all 5 fixes + P144/P145 probes) reproduced: uv=48234650 pm=23068828 OVERLAP fsb 6029607 (AG23 agbno295 — always agbno~295 because that's where each AG's first dir-data blocks land).
- **23:11:53.588 test25 (comm=rm): P145-FREE agno=23 bno=295 len=1 — THE BLOCK WAS LEGITIMATELY FREED** (uv dir block-0 emptied during unlink storm → xfs_dir2_shrink_inode → bunmapi → free). My iter_10/12 'never freed' inference was wrong (P38 series just ended before the frees).
- 23:13:34 test14 re-allocated it for pm — LEGAL from the btree's view (disk_owner=48234650 in P-DBLALLOC just means the old dir-block bytes were still on media — normal for a freed block).
- **The REAL bug: uv's ON-DISK fork still references the freed block** (static: uv extents=4 incl 6029607; live ls EFSCORRUPTED). The rm's fork shrink (nx 4→3, removing the offset-0→295 extent) either never landed on the dinode durably, or landed and was RESURRECTED by a peer's stale-superset re-adopt (P63-HANDOFF 'forcing disk-superset adopt' family) that re-persisted the pre-rm nx=4 map.
- So: AG free-space machinery is (probably) INNOCENT; the fence (P143) and the evict-time-travel theory targeted the wrong layer. GPT's hypothesis #5 (stale fork readoption) — which we both 'ruled out' on the bad premise — is BACK as the leading mechanism. cc's 31/32 2-check fails (iters 7c/12/13) are likely the same stale-map ghosts.

## Exactly where the next session should resume
1. Join the uv dinode-write timeline for iter_13: use **P136-DIRINO-WRDONE** prints (dir-dinode write COMPLETION trace: ino/fmt/gen/size/nx/daddr/realns — exists in pal/linux/xfs_buf.c ~line 2110, gated mxfs_dirwr/instr? CHECK gating — may need dblalloc_probe/instr enabled) — NOT P-DIRDW (no realns; my last query failed on that).
   Target: find who wrote dinode-cluster daddr=48144280 with an nx=4/blk0=6029607 image with realns AFTER the free realns 1784243513588443216, and which reload/adopt path fed it (P62-RELOAD-FORK-SHRINK / P61-ADOPT-CHK / P63-HANDOFF / P33-FROMDISK-DIRSHRINK prints around it). test25's own post-rm prints after 23:11:53.588 show whether its nx=3 iflush ever happened.
   Logs: tests/logs/dblalloc_repro/iter_13/full_test*.log (859K lines, [testN]-prefixed).
2. Note P62-DUALREAD on test25 at the pre-rm adopt printed verdict=PLATTER-IS-OLD(R-a-or-legit) — the platter-behind detection exists on the dir side; the shrink-direction adopt may bypass its guards (P33-FROMDISK-DIRSHRINK 'REVERTED smaller (leaf-vs-data tear source)' fires normally, so shrink-adopts are considered legit — the RESURRECTION direction (disk STALE-BIGGER re-adopted after a local shrink was committed) is the suspect gap; the epoch guard (b_mxfs_wr_flush_epoch/P34B) covers bmbt leaf reads, maybe not the DINODE-image adopt path (mxfs_dlm_reload_inode / P56-RELOAD-MERGE).)
3. If the timeline shows test25's nx=3 write landed and a peer later wrote nx=4: instrument/fix the adopt gate (di gen equal; need a fork-change seq or dir_gen comparison — dir_gen exists in prints and is piggybacked cluster-wide; adopt should REFUSE a disk image whose dir_gen < local acted gen... P63 prints grant_gen/acted_gen/dir_gen/loaded_gen — the data for the gate is already there).
4. Repro cost: ~6min/iter, reproduces ~1-in-2 now (iters 10,12,13 of 10,11,12,13). dblalloc_repro.sh auto-deploys current mxfs.ko.
5. Ladder + budgets + Family-A panics still pending (see the two earlier sess6 memories).

## Build state
Tree = 0.10.117 srcversion A3BD5947 (5 fixes + P143 fence [harmless, keep] + P144-WR/RD + P145-FREE/AGFL + enriched P117). All 32 nodes last ran it in iter_13. Local mxfs.ko matches tree.
