---
name: ccloop-c7ee71c6-sess6-B-torn-da3-crc-and-hole-dossier
description: sess6-B: crash_consistency@8/tcp exposed TWO live defects — ON-DISK torn da3-node CRC (5-node shutdown cascade, P-DIRCRC family) + P14-DABUF-HOLE for…
metadata:
  type: project
tags: [crash_consistency, dircrc, torn-write, da3, hole, corruption, shutdown, 8tcp, rung]
---

# sess6-B: the 8/tcp rung's two live defects (after FIX-26 + orphan NAK landed)

## Rung status on v0.11.93 (srcver 84A5D6346B21D4756912E93)
Re-ran the stale (v0.11.82-era, 13:15-13:32Z) board rows on the current build:
strong_consistency/posix_multi/mmap_coherency/dlm_fairness/zero_silent_loss/
dlm_membership/scaling_curve/rsync_paired ALL PASS (fast, in budget) — PLUS the
earlier dir_reuse ×3 + cache_coherency + dlm_scaling + precond greens.
STILL STALE on the board (need re-run on final build): fio_perf,
fio_perf_vs_xfs, soak, tcp_dlm_scaling, fence_during_write, fault_netpartition
(the last two pre-assert-failed after the CC shutdown cascade).
IMPORTANT: `./showstat.sh 8 tcp` board rows persist across builds — ALWAYS
check `jq .runs["8/tcp"].iso` timestamps in criteria.json vs current-build
deploy time before trusting a green row.

## DEFECT A (CRITICAL, on-disk): torn da3-node dir block → 5-node shutdown
- crash_consistency 8/tcp (run 20260725T181124Z, 18:11:24-18:12:54Z kill):
  FAIL NO_TERMINAL_RECORD=8 at the 90s box (was 29s green on v0.11.82).
- 18:13:39 test3 (leftover CC bash verifiers): `Metadata CRC error at
  xfs_da3_node_read_verify, xfs_da3_node block 0xa7e220` (daddr 11002400)
  of CC's shared dir ino=17307530 (800 entries → da3 node format) →
  EUCLEAN inside xfs_trans_read_buf_map → FORCE SHUTDOWN → P-WITHDRAW.
  5 of 8 nodes shut down this way (test3/4/5/7/8) — pre-assert correctly
  failed for fence_during_write/fault_netpartition after it.
  (`mount|grep -c mxfs` LIES here — stale mount-table entry persists;
  `mountpoint` returns EIO. Trust the pre-assert, not mount count.)
- Hexdump of the bad block: da3 header SELF-CONSISTENT (magic 0x3ebe @8,
  self-blkno 0xa7e220 @0x10, owner 0x108178a=17307530 @0x38) — CRC fails
  because LATER SECTORS are another write era = TORN/INTERLEAVED write.
  A local buffer write always lands CRC-valid ⇒ either (a) TWO NODES wrote
  the block concurrently (EX exclusivity broken — e.g. membership-purge
  REVERSE arm: master record purged, two believers) or (b) some partial-
  sector dir write path (dir blocks have ONE block CRC; partial writes are
  never CRC-safe — inode-cluster per-dinode CRC logic does NOT transfer).
- All 8 nodes P21F-RELFLUSH-LEAF'd daddr 11002400 within 18:11:35-36
  (leaf_count 127..142 as dir grew) — normal EX rotation shape; no
  write-side holder/CRC trace was armed (CC does NOT arm watch_ino).
- Context: v0.11.92 prep (17:41, 208s) had to HARD-RESET test6+test7
  (rejoined 17:47/17:49) — membership churn preceded both defects.
- kernlogs preserved: /tmp/run_crash_consistency_20260725T181124Z/
  (t1=1472 lines mentioning the daddr, t2=1212, others 200-1400).
- NEXT (RULE 4): (1) write-side instrumentation for dir-block submits:
  print holder-mode + grant gen + CRC-at-submit for watched-dir daddr
  writes (or arm watch_ino in CC harness like dir_reuse does); (2) rerun
  CC@8/tcp to re-trip; correlate which two writes interleaved; (3) check
  membership events between 18:11:24-18:13:39 on all nodes (purge storms);
  (4) the reverse-purge concurrent-EX arm is the PRIME suspect — consider
  instrumenting process_remote_request grant path to log grants issued
  while another GRANTED entry for the same resource was purged recently.

## DEFECT B (in-core, EUCLEAN-only so far): P14-DABUF-HOLE format tear
- 17:52:44 test3 (during GREEN .92 dir_reuse triple — checks still passed):
  `P14-DABUF-HOLE ino=131 bno=8388608 fmt=2 nextents=1 disize=4096
  dir_gen=203 loaded_gen=203 evicted_incarn==i_gen dlm_mode=5(EX)
  iget_age_ms=42889 iversion=26 comm=bash` + Internal error
  `!(flags & XFS_DABUF_MAP_HOLE_OK)` xfs_da_btree.c:2909 via
  xfs_da_read_buf. bno 8388608 = XFS_DIR2_LEAF_OFFSET ⇒ caller decided
  LEAF/NODE format, but the (freshly reloaded, gen-matched) fork is
  BLOCK-format 1-extent 4096B. Format-decision TOCTOU across a reload:
  isblock/isleaf decision on OLD state → reload (or mid-tenure fork swap)
  → walk on NEW fork → HOLE. Repeated bursts 17:52:44-17:53+ (EUCLEAN to
  the op, NO shutdown). This is state.md-sess3's ORIGINAL "P21H-LEAFHOLE"
  suspect list item (a)/(c) territory. NOT what shut nodes down.
- NEXT: find the exact caller seq — xfs_dir2_isleaf/isnode decision site
  vs mid-tenure reload (P6-MIDTENURE-RELOAD-SKIP has an exception path?);
  the walk holds ILOCK, so the fork swap must happen через a nested
  acquire inside the walk (da_read_buf → dlm read hooks → reload).

## Cluster/LUN state at save
- test3/4/5/7/8: fs SHUT DOWN (mounted-but-EIO). test1/2/6 alive.
- THE ON-DISK DIR (.crash_consistency, ino 17307530) LIKELY CARRIES the
  CRC-bad block. BEFORE any further runs: full FORCE_PREP; then either
  `tools/chk_mxfs -v <dev>` from an unmounted node to assess, or just
  re-mkfs (`tools/mkfs_mxfs`) — test data is disposable, and a dirty LUN
  will retrip CC forever. (Does prep mkfs? NO by default — must handle
  explicitly.)
- Leftover CC bash loops may still run on nodes (kill or reboot at prep).

## Session-6 fix inventory (all landed, docs updated in awareness/)
v0.11.87 FIX-26 writepages admit; v0.11.88-91 injection+probes
(fix26_delay_ms, P26DBG-INJ, P26PRE-DELALLOC-SUBEX+dem_cur);
v0.11.92 orphan-grant NAK (P5N, dlm.c+v5_mount.c+ag_bast_notify);
v0.11.93 dem_cur field. Harness: run.sh dir_reuse ct ordering
(hang<ct<tt); dir_reuse stale-capture cleanup. scripts/
fix26_wb_bast_exerciser.sh. state.md is HANDOFF-ONLY (user directive —
never use as mid-session history; restored to sess3 content).
