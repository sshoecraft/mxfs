---
name: sess29-write-merge-fix-implemented-build-BA856D08
description: sess29(ccloop): implemented write-side 3-way merge (dir_write_merge param, build BA856D08) for dir_reuse data-block loss. Helps count; shutdowns now…
metadata:
  type: project
---

## sess29 — WRITE-SIDE 3-WAY MERGE implemented + tested (criteria 8/tcp NOT yet met)

### What I built (KEEP, default-OFF lever)
`mxfs_dir3_data_writemerge()` in pal/linux/xfs_buf.c, called from `xfs_buf_submit` BEFORE `xfs_buf_verify_write` (so freescan+graft are covered by the CRC the verifier stamps). Param `dir_write_merge` (xfs/xfs_mxfs_dlm.c, default 0). Build **BA856D08** (= keeper C1B4BFC0 behaviorally when off).
- At the dir DATA-block bio chokepoint, FUA-reads the current on-disk image; when the two images diverge in BOTH directions (we hold a NAME the disk lacks AND disk holds a NAME we lack = MERGE-NEEDED), grafts the disk's name-unique dirents into our in-core block via `mxfs_dir3_data_graft_one` (non-logged byte surgery: carve a free slot, write the dirent, then `xfs_dir2_data_freescan` rebuilds bestfree). Logs **P-WMERGE2 grafted=N ourx=N**.
- **Dedup is by NAME, not inumber** — CRITICAL. v1 (build 51CF6BEE) deduped by inumber → grafted stale prior-incarnation entries (same name, old inode) as DUPLICATE NAMES → readdir=845 (45 over-count) + lookup_fail. Name-dedup fixed the gross over-count.
- MERGE-NEEDED gate (`ourx>0`) makes it loss-safe: a legit REMOVE looks pure-stale (incore_extra==0) and is NEVER touched → no resurrection. dir_reuse's create wave is pure concurrent ADD (rank1's rm-rf is after the verify barrier), so bidirectional divergence is always two concurrent adds.

### Measured (drc_one.sh 0 24, 8/tcp, DRC_STREAM=1)
- Merge FIRES correctly: `P-WMERGE2 owner=131 grafted=1 ourx=1`. Early rounds readdir=**800** (CORRECT count, was 791 baseline-loss). So the merge DOES reduce the data-block dirent loss.
- RESIDUALS with merge on: occasional **+1 over-count** (round3 readdir=801) and **lookup_fail=1** (leaf-hash hole, e.g. node4_f17.md5 — entry in data block but datascan-lookup still ENOENT; needs investigation: stale-inode graft? or datascan gap).

### THE DOMINANT BLOCKER IS NOW A SHUTDOWN (pre-existing, NOT my merge — PROVEN by A/B)
Baseline (dir_write_merge=0, SAME build) ALSO shuts down: test7 readdir=791 dirent-loss at round 5, then **xfs_defer 0x8 corruption** (`xfs_defer_finish_noroll+0x2b6`, xfs_defer.c:721) at round 15. Merge run: test4 **DABUF_MAP_HOLE_OK** (xfs_da_btree.c:2876, stale leaf → freed-block hole) at round 5. Different shutdown on different node each run = the "BROAD 8-node flakiness". One node's shutdown breaks the barrier → cascade → whole test FAILs. So ≥3 independent bugs gate 8/tcp 100%:
  1. data-block dirent loss (readdir<800) — my merge addresses.
  2. **DABUF_MAP_HOLE shutdown** = stale cached LEAF referencing peer-freed data blocks (sess20 root [[sess20-PROVEN-dabuf-hole-is-stale-leaf-fixed-by-postread-leaf-only]]). Lever `dir_postread_reread=1`(+leaf_only=1 default) drove it 60→0 in sess20 but surfaced deeper CRC/bnobt. Currently default OFF.
  3. **xfs_defer 0x8 corruption shutdown** (separate, ~round 15).
  4. leaf-hash lookup_fail (datascan heal gap).

### NEXT (RULE 4)
Testing merge + `dir_postread_reread=1` together (in flight at relay). If DABUF_HOLE clears and merge holds data, isolates the xfs_defer shutdown. Tooling: `DRC_STREAM=1 EXTRA="..." bash tests/tcp/drc_one.sh 0 24` (NFS stream beats ring rotation — P-WMERGE2 was invisible in plain dmesg by round 24). The data-block merge is the right idea but the leaf has the same TOCTOU and the per-node leaf ADDRESS differs (can't copy peer's leaf entry) → leaf coherency must be read-side (datascan) or a reacquire reload. See [[sess28-SMOKINGGUN-EXholder-destages-stale-inAIL-base-bgen0-mergeneeded]].
