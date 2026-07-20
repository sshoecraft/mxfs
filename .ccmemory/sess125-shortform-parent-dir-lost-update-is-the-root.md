---
name: sess125-shortform-parent-dir-lost-update-is-the-root
description: sess125 (ccloop): build 1371EA35. cache_coherency unlink_visibility ROOT = reused-inode STALE-CACHE on winner DIR inode (incore mode=0/gen+1); NOT sh…
metadata:
  type: project
---

## sess125 — root of unlink_visibility FAIL = stale-cached winner DIR inode (mode=0), NOT shortform parent

Build **1371EA35E6242D6D3EBA22B** on test1-4. cache_coherency still RED (only failing criterion; 11/12 pass).

### Two changes made this session (both in 1371EA35)
1. **modify-time tenure stamping — KEEP (correct, no regression).** Replaced READ-time `b_tenure_id`
   stamping with MODIFY-time in `mxfs_ag_meta_track` (xfs_mxfs_dlm.c, stamps before the AGMETA_TRACKED
   early-return). Removed read stamps at xfs_btree.c:1433, xfs_ialloc.c:3102, xfs_alloc.c:3737. Makes
   tenure mean "last modified" not "last read" → a cache-HIT read no longer re-stamps a prior-tenure
   stale buffer current. Result: no shutdown, timing fast, but **P124 still fires 4-16/node**
   (residual = in_ail prior-tenure ghost; invalidate_stale can't discard in_ail regardless of tenure).
   Preserves sess123 AGI fix (in-tenure RMW logs buf → stamped current). KEEP.
2. **dir-flush reorder — KEEP (architecturally sound, NO effect on this test).** Moved
   `mxfs_dir_flush_data_blocks(ip)` to AFTER the sess29 settle (msleep+2nd log_force) in the inode
   BAST release. Gemini Q1: the pre-settle flush ran in the async CIL→AIL window so a just-committed
   dir block was unpinned-but-not-IN_AIL → needs_flush saw it clean → skipped → landed in_ail during
   msleep → xfsaild destaged post-handoff. Correct for EXTENTS dirs. IRRELEVANT here (this failure is
   a SHORTFORM/inode issue; the fn early-returns on non-EXTENTS).

### RULE-4 diagnosis (sharp, corrected)
test_unlink_visibility: node4 PASSES; node1/2/3 FAIL (node1 `actual=0` incl own files; can't rm own).

**Shortform parent .mxfs_test (ino=131) is a RED HERRING — DISPROVEN.** Merged 4-node
`P-SFDIR-RELOAD ino=131` timeline: node1 reloads 131 `count=2 names=[test_unlin unlink_vis]` at t=79
and KEEPS it all run. node1 resolves unlink_visibility in the parent FINE.

**ROOT = reused-inode STALE-CACHE on the winner DIRECTORY inode 4194433** (sess40/48/90/114 family):
- on-disk winner = node4 ino=4194433, LIVE dir (disk_mode=040755 nlink=2 gen=2861374702).
- node1 CACHED 4194433 as a STALE FREED incarnation: `P-IRESURRECT ino=4194433 incore_mode=00
  incore_nlink=0 incore_gen=2861374703` (= disk_gen+1). node1 resolves name→4194433→serves its mode=0
  cached inode → readdir on a "free" inode → 0 entries; create/rm → ENOENT.
- d_revalidate (pal/linux/xfs_super.c mxfs_drevalidate) FAILS to catch it: positive dentry, name still
  resolves to SAME ino (actual_ino==ip->i_ino)→ret=1 valid. The GENMISS FUA recheck (super.c:1984) and
  TYPEMISS recheck are GATED on `S_ISDIR(incore mode)` / non-zero incore ftype — incore mode==0 so BOTH
  are SKIPPED. → stale mode=0 inode served, never evicted; first real P-VNLOOKUP ino=4194433 only at
  t=201 (cleanup). node4 passes because its own cached 4194433 is the live dir.
- producer of incore mode=0/gen+1: node1 (mkdir create-race loser — it found existing 4194433 lrc=0,
  orphaned its own 135) evidently holds/derived a stale "freed+reused" image of 4194433. The v0.4.9
  sess38 stale-cluster-invalidate-on-cache-miss fix does NOT cover this dir-inode path.

### NEXT (RULE 4; Gemini consult #2 NOT yet done — escalate to GPT if 2 Gemini fail)
Try cheap first, measure node1 actual=120:
1. **d_revalidate gate fix:** in mxfs_drevalidate, for a POSITIVE dentry resolving to the SAME ino but
   `VFS_I(ip)->i_mode == 0` (cached-free) — do the lockless FUA di_gen/di_mode recheck UNCONDITIONALLY
   (drop the S_ISDIR(incore) gate for the mode==0 case); if disk_mode!=0 set i_dlm_stale+XFS_ISTALE_CAW,
   return 0 → xfs_lookup evicts+re-igets node4's live dir. Watch for sess91 ISTALE-CAW thrash / rename
   regress.
2. **iget cache-hit reload (true root):** xfs_iget_cache_hit (xfs/xfs_icache.c) — a dir inode cached
   mode==0 (or incore_gen>disk... here incore>disk) while a peer/dirent shows it live must force a
   coherent FUA reload, not return the stale freed incarnation.
Instruments: `P-IRESURRECT ino=<dir>` (incore vs disk mode/gen), `P-VNLOOKUP ino=<dir>` timing.

### Iteration rules (unchanged)
Power-cycle ALL 4 (virsh destroy+start, boot ~50s) → `INSMOD_OPTS="fua_disable=1 instr=0" bash
tests/reset4.sh 4` → verify srcversion + `dmesg -C` → subtest `MXFS_NODE_OFFSET=0
MXFS_TESTS_DIR=/src/mxfs/tests timeout 600 bash tests/run_tests.sh --nodes 4 --phase cluster --test
test_unlink_visibility --pass-file /tmp/.mxfs_pass --device /dev/sda --mount-point /mnt/shared`.
Results in /home/steve/.mxfs/results/<ts>/. inode_mht_ms default 50.

Related: [[sess124-mht-fixes-starvation-real-root-is-inail-acquire-fence]]
[[sess123-tenure-id-FIXED-agi-corruption-now-starvation]] [[sess114_lessons]] [[sess90_lessons]]
[[sess48_lessons]] [[feedback_timing_is_first_class]]
