---
name: sess33-fixes-refuted-zombie-bli-reenters-after-evict
description: sess33: 5 fixes REFUTED for dir_reuse 799 (merge→803; write-skip×2→empty-dir catastrophe; release-stale→fires-no-fix; acquire-evict zombie-retire→fir…
metadata:
  type: project
---

## sess33 — dir_reuse 8/tcp readdir=799: mechanism proven, 5 fixes refuted

### PROVEN mechanism (P-WGHOST=0, P-WMERGE+DONE): the loss-write is the CANONICAL dir data buffer (not a ghost), state `DONE=0 in_ail=1 dirty=0 pin=0 delwri=0 lseq==wseq bgen=0 held_mode=EX(5) comm=dd/bash kind=data disk_extra=1 incore_extra=1`. A COHERENCY-INVALIDATED (XBF_DONE cleared by acquire-evict), CLEAN, already-DESTAGED dir buffer is written (xfsaild/sync-AIL-push) with its STALE pre-evict content over a peer's durable add → reverts it. `mxfs_dir3_disk_has_extra_inum(incore,disk)` = count of disk inums absent from incore; disk_extra=1 = disk has a dirent our in-core lacks → our write drops it.

### 5 FIXES REFUTED (RULE 4, all with evidence):
1. `dir_write_merge=1` (write-chokepoint union graft, mxfs_dir3_data_writemerge): WORSE — round1 readdir=803 over-count every node + round2 readdir=0 + lookup_fail=58. Over-grafts/dup under rm+recreate churn. [[sess33-REFUTED-dir-write-merge-overgrafts-803]]
2. write-chokepoint reflush-skip v1 (EX+clean+destaged, NO !DONE key): was INERT — gated by mxfs_dirskip_enabled (default 0, "enforce refuted sess17"). Never fired (P33=0). The iter-3 failure that run was flaky variance, NOT the fix.
3. write-chokepoint reflush-skip v2 (+!XBF_DONE key, enforced independently): CATASTROPHIC — readdir=0/1 all nodes (empty dir). Legit dir-block content writes are ALSO frequently DONE=0 at submit (FUA/_XBF_FUA_FRESH read cycle + acquire-evict clears DONE every tenure), so !DONE skip drops NEEDED writes. **Write-side suppression of dir buffers is the corruptor in ALL forms (sess23 confirmed).**
4. release-side GFS2 demote-stale (dir_release_stale: at EX release after data_durable, xfs_buf_stale clean dir buffers): FIRED (P33-RELSTALE 18-115x/node) but loss PERSISTS (799). Wrong boundary — the stale buffer re-enters cache+AIL during the NEXT tenure.
5. acquire-evict zombie-retire (dir_zombie_retire: in mxfs_dir_evict_data_blocks !undurable branch, xfs_buf_item_done the in_ail+destaged BLI before soft-clear): SAFE (no corruption/shutdown) but FIRED 0× (P33-ZOMBIE-RETIRE=0) → loss persists. **P68-EVDECIDE never shows in_ail=1 at evict time.** So the buffer is NOT in_ail when the acquire-evict runs; the zombie BLI enters the AIL AFTER the evict (an in-tenure re-log), with DONE still 0 (stale base, no re-read).

### KEY NARROWING: the zombie BLI's in_ail=1 arises BETWEEN acquire-evict (soft-clears DONE=0) and the write. So during the EX tenure, the DONE=0 soft-cleared buffer is RE-LOGGED (BLI→AIL) on its STALE content WITHOUT a fresh re-read, then written = clobber. Contradicts sess32 POST-RMW (superset right after addname) — needs reconciling. Candidates: (a) a dir code path re-logs an existing block via get_buf (no read) e.g. freescan/bestfree/leaf; (b) the modify re-reads but a DIFFERENT block (the soft-cleared one) is re-logged stale by freescan; (c) BLI lingers across release (data_durable bmap-walk misses the block — stale in-core extent list).

### Build state: 9EBCB933, all 3 new params (dir_reflush_skip, dir_release_stale default 0; dir_zombie_retire=1 but fires 0× = inert) → behaves keeper-equiv, cluster-safe. P-WMERGE now logs DONE/fua_fresh/delwri/comm. mxfs_dir_canonical_buf_ptr (P-WGHOST) + mxfs_dir_stale_clean_data_blocks_relsafe helpers added. CRITERIA NOT MET. [[sess33-PROVEN-clean-inAIL-stale-reflush-not-ghost]] [[sess33-HEAD-handoff]]
