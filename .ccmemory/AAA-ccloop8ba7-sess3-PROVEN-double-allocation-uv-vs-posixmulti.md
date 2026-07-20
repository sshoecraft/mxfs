---
name: AAA-ccloop8ba7-sess3-PROVEN-double-allocation-uv-vs-posixmulti
description: PROVEN@32/caw: cache_coherency FAIL aftermath = DOUBLE-ALLOC. uv-dir(10485913) ext0/1 (fsb 1311015,1835313) ALSO in posix_multi(4194460) btree. AG fr…
metadata:
  type: project
tags: [ccloop-8ba7ae5c, cache_coherency, double-allocation, ag-freespace, 32node, proven]
---

# sess3 (ccloop 8ba7ae5c) — cache_coherency@32/caw FAIL root: AG free-space DOUBLE ALLOCATION (PROVEN static)

## Scoreboard context
Run 20260716T172745Z (build 5DA487D4, ladder r2): 32/caw = 18/19 PASS; ONLY cache_coherency FAIL
(test1: `uv gone node7_file30` + `remain exp=0 got=1`, nodes_pass=31/32, checks 3019/3021).
1/2/4/8/16 caw all 100% already (criteria.json). This is the LAST criteria blocker.

## Static forensics on /home/steve/disk.img (SCST backing store; xfs_off=100704256; geometry: bsize=4096 agblocks=261653 agcount=50 isize=512 inopblog=3 agblklog=18)
- unlink_visibility dir ino=10485913 (agno 5): disk dinode fmt=2 nx=6 size=20480 cc=1921;
  extents: off0=fsb 1311015 (daddr 10468480), off1=1835313 (14655008), off2=1573159 (12561704),
  off3=2883879 (23027824), off4=4718887 (37680392), leaf 8388608=6029608 (48146520).
- Reading the dir NOW → EFSCORRUPTED at xfs_dir3_data_read (owner check, NOT verifier): block content
  at ext0/ext1 is VALID XDD3 owned by ino 4194460 = **.posix_multi** (127/139 live nodeN_fileM entries).
  ext2/3/4 now contain FILE DATA ("20\n..."); leaf block zeroed.
- **.posix_multi (ino 4194460, fmt=3 btree, nx=36, root ptr fsb 786746) CONTAINS extents
  startoff=20→fsb 1311015 count=1 and startoff=7→fsb 1835313 count=1.**
  ⇒ TWO LIVE FORKS reference the SAME blocks = double allocation. Ironclad, no kernel needed to verify:
  parse dinodes+btree from disk.img (scripts in sess transcript; redo with python struct walk).

## Timeline (from 24 nodes' journals; test1-8 journals rotated away)
- 17:36:58-17:37:08 uv grow: P62-REL-DIREXT disk_nx 1→10 (creates, 960 files).
- 17:37:25-17:37:33 uv shrink: nx 10→8→7→6, then STABLE at fmt=2 nx=6 size=20480, incore==disk
  on ALL reporting nodes (P62-RELOAD-FORK-SHRINK 17:37:33 = final: identical). Dir NEVER contracted
  below 6 — blocks 0-4+leaf were NEVER freed by the dir. cc=1921 is the FINAL agreed state, NOT stale.
- 17:37:37 cache_coherency FAIL recorded (test1 ghost node7_file30) — separate read-side/resurrect
  symptom, NOT yet root-caused (test1 journal lost).
- 17:39:54 posix_multi runs: allocator hands fsb 1311015+1835313 (uv-owned!) to .posix_multi dir
  blocks; later tests (zero_silent_loss 17:40 etc.) got ext2/3/4 as file data + leaf reused.
  Pattern: agbno≈295 in agno 5,6,11,18 + 305 in agno 7 — "first free block" of near-virgin AGs ⇒
  those AGs' free-space btrees REVERTED/never-recorded uv's grow-phase allocations.
- 18:39:08+ separate dinode-verify/TYPEFLIP noise during fence_during_write (guarded, tests passed).
- 18:51 my ls triggered the dir3_data owner-mismatch detections (test1+test2).

## Root family
AG ALLOC METADATA (AGF/bnobt/cntbt) staleness across AG-DLM handoffs: either (A) grow-phase alloc's
AG btree updates not drained before AG unlock, (B) later allocator used stale cached AG btree image
(freshness not tied to lock generation), or (C) stale destage clobbered AG btrees after correct write.
Same family as GPT root-2 (_XBF_FUA_FRESH timeless boolean) but in the ALLOC domain — dir-block domain
has guards (P49-STALEBASE/P116-RELOAD-SELFCLOBBER/P73-heal); alloc domain apparently does not.
NEXT: read xfs_mxfs_dlm.c AG acquire (cached AG-DLM) + drain_alloc_buflist; find whether AGF/bnobt
bufs get invalidated/FUA-reread on AG-DLM re-acquire after peer EX tenure; instrument alloc of a
double-owned block (win: log AGF freshness state at xfs_alloc_fixup/near_bno alloc time).

## Env notes
- Cluster still UP (32 nodes, mpatha, build 5DA487D4) with the corrupted FS mounted — do NOT trust
  further tests on this prep; fresh prep (mkfs) required for next runs.
- test1-8 journald rotated (probe volume); use test9+ for windowed forensics.
- SSH: tools/mxfs_sshpass.sh <host> /tmp/.mxfs_pass '<cmd>'. journalctl times = UTC.
