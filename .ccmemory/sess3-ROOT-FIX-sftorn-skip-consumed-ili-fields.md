---
name: sess3-ROOT-FIX-sftorn-skip-consumed-ili-fields
description: sess3(a16ec5f2) ROOT PROVEN+FIXED: P22-SFTORN-SKIP via flush_out CONSUMED ili_fields w/o writing → committed dir contraction lost → map-of-freed-bloc…
metadata:
  type: project
---

# sess3 (ccloop a16ec5f2) — SFTORN discard root, PROVEN + FIXED

## The complete measured chain (run15, test1, uptime 5273.32-5273.63)
1. rm contracts shared dir ino131: `PW-LEAF2BLOCK nx=5` → `PW-BLOCK2SF nx=1 sfsize=22` → `P3-EFREE-Q agbno=15` (block0/blk15 free queued; became durable in bnobt).
2. xfsaild iflush attempt hits transiently-torn SF fork (mid-conversion, hdr count=1 i8count=1) → `P22-SFTORN-SKIP ili_fields=0x3` (xfs_inode.c:4712 sess22 branch) → **error=0 goto flush_out → flush_out moved ili_fields→ili_last_fields and CLEARED them with NOTHING copied to the buffer**; next cluster-write completion (nx=6 stale content) → xfs_iflush_done → AIL delete → committed contraction silently dropped from writeback FOREVER. (No PW-IFLUSH between — probe sits at xfs_inode_to_disk, after the skip.)
3. Release fence (`PW-RELFENCE`) sees pin=0/in_ail=0/fields=0 → passes w=0. Reload at next acquire: `PW-ADOPT incore_fmt=1/nx=0/size=22 → disk fmt=2 nx=6` + `P-RELOAD-HOLEY-ADOPT` → resurrects the stale EXTENTS map cluster-wide **whose blocks the bnobt already freed** (verified on-disk: ALL 6 mapped blocks incl blk15/off0 FREE in bnobts while mapped+leaf-referenced).
4. File delalloc writeback re-allocates agbno=15 (`P-DBLALLOC agno=0 agbno=15 holds=dir-block`, comm=kworker) → urandom over live-mapped block0 (daddr 0x78=120) → cold readers CRC `error 74` → cluster-wide shutdown. (= run12/run13 face, run9/10 variants.)

## FIX (build 49A0E80D, VERIFIED operating in run16)
- xfs_inode.c SFTORN branch: return **-EAGAIN without touching ILI** (keep dirty in AIL; retry when conversion settles). Comment block "sess3 (ccloop a16ec5f2) ROOT FIX".
- xfs_iflush_cluster: on -EAGAIN → clear IFLUSHING, raw un-take ilock, error=0, continue (must NOT shutdown/fail buffer).
- Verified: run16 shows 20× `PW-IFLUSH ino=131 fmt=1` (SF images now written); no err-74/blk15 face in window; runs now reach r=15 (480s budget) vs r=2-7 shutdowns.

## Instrumentation added this session (keep; all gated on params, default off)
- `mxfs.watch_daddr=131` (sector-granular): PW-DADDR/PW-SLOT (dinode decode+REGRESS tracking, stacks ratelimited), PW-IWR (partial-writer decision masks), PW-WDONE (completion, realns). pal/linux/xfs_buf.c.
- `mxfs.watch_ino=131`: PW-IFLUSH (xfs_inode.c@xfs_inode_to_disk), PW-IABORT (xfs_inode_item.c, w/ stack), PW-RELFENCE-IN/OUT (release fence), PW-ADOPT (reload from_disk site), PW-LEAF2BLOCK/PW-BLOCK2SF (contractions).
- Arm via `MXFS_EXTRA_MODARGS="watch_daddr=131 watch_ino=131" ./run.sh 8 tcp dir_reuse_coherency` (prep_node insmods with it).
- ANALYSIS PITFALLS: dmesg spans multiple runs (nodes not always rebooted; window by LAST `DRCph r=1 rank=. PHASE=create-start` per node); boot clocks skew ~10s (barrier-align by create-start or use realns=); `[ ts]` padded bracket breaks awk $1 (sed with \1 capture!); `nx=` greps match `maxnx=` (anchor with space).

## Facts bank (verified)
- geometry: isize=512 blocksize=4096 inopblock=8 rootino=128, drc dir=ino131, its own sector daddr=131 (cluster bm_bn=128 len=32), dir block0 ALWAYS blk15/daddr120=0x78 (agbno15, right below ino chunk at agbno16). Leaf daddr 6279744.
- rm-end shape is legitimately HOLEY (partial shrink; AG-lock timeouts leave empty blocks mapped); create-path negative lookups P26-DSCAN over holey map spam benign MAP_HOLE internal-error lines (P21H class).
- P74-DINEXT-REGRESS blind for fmt=EXTENTS (BTREE-only guard); P37-STALEBMAP gated instr/dir_relverify.
- LIO: tcm_loop LUN over /home/steve/disk.img (fileio, O_DSYNC write-through, WCE=1). chk_mxfs -v works on the backing file directly. envelope xfs_data_offset=100704256.

## Residual faces after fix (run16, 15 rounds, 4 fail rounds, no cluster shutdown)
1. test6 solo shutdown ~r=11: "Corruption of in-memory data (0x8) at xfs_trans_cancel" (dirty cancel) — cause TBD.
2. r=11: readdir=748 (node6's .md5 block-worth lost — likely test6 shutdown fallout).
3. r=12-14: persistent readdir=700/800 + lookup_fail=2 (node5_f3,node7_f15) — same 100 missing every round after test6's shutdown (test6 absent → its 100 files not created? 800 exp assumes 8 creators → test6 down = 100 missing per round + its stale leaf refs = the 2 lookup_fails. LIKELY pure fallout, verify).
4. r=6 (pre-fix runs): single-entry durable loss face (node6_f20.md5 / node2_f29+f31.md5) — separate stale-base data-block RMW family, still to fix.

Links: [[sess2-END-dinode-regression-root-run12-odsync-pace-fixed]]
