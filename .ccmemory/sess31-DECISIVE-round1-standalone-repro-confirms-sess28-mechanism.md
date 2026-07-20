---
name: sess31-DECISIVE-round1-standalone-repro-confirms-sess28-mechanism
description: sess31 DECISIVE: clean round-1 standalone repro of dir_reuse loss + P-WMERGE reconfirms sess28 stale-in-AIL-base destage. Fix=txn 3-way reapply (writ…
metadata:
  type: project
---

## sess31 — DECISIVE fresh evidence for the dir_reuse single-dirent loss

### Reliable repro (much better than before)
`tests/tcp/drc_repro_loop.sh 8 "" 24` (reboot+loop 8/tcp dir_reuse). The clean loss reproduces at **ROUND 1** standalone (not reuse-churn dependent), ~1 in 2-3 iters. The lost entry is consistently **node1_f4.md5** (rank1's md5 sidecar #4), durably gone (all 8 nodes readdir=799/800, LOOKUP_ENOENT, REREAD_MISS — data dirent AND leaf hash both gone). To CAPTURE: reboot, then foreground `MXFS_EXTRA_MODARGS="dir_writeprobe=1 dir_relverify=1" MXFS_TEST_ENV="DRC_STREAM=1 DRC_ROUNDS=6" ./run.sh 8 tcp dir_reuse_coherency`. The clobber is in the CREATE-phase snapshot `/root/drc_create_r1_rank<N>.dmesg` (NOT the verify-phase drc_fail dmesg). Modargs are insmod-style (no `mxfs.` prefix); run.sh only applies them on a FRESH insmod (reboot first — it reuses an existing mount).

### THE smoking gun (test5/rank5 create-phase, dir inode=131)
`P-WMERGE owner=131 daddr=16745864 disk_extra=1 incore_extra=1 held_mode=5(EX) in_ail=1 dirty=0 bgen=0 kind=data — MERGE-NEEDED`
EXACTLY sess28 [[sess28-SMOKINGGUN-EXholder-destages-stale-inAIL-base-bgen0-mergeneeded]]. test5 (EX, re-acquired) is destaging an in-AIL dir-DATA block whose base is STALE (bgen=0, prior tenure): disk_extra=1 = disk holds node1_f4.md5 (a peer add) the in-core base LACKS; incore_extra=1 = test5's own add the disk lacks. Destaging the stale base reverts node1_f4.md5. Exactly ONE such event per loss (single-dirent). P25-RELVERIFY-MISMATCH=0 (data coherent at every EX *release*) — so the staleness develops AFTER release: test5 T1 lands its add coherently → peer adds node1_f4.md5 to disk → test5 T2 re-acquires, the read-side gen hook sees bgen=0≠dir_gen=3 but CANNOT invalidate (block in_ail = test5's own un-destaged work → clearing XBF_DONE corrupts) → test5's next addname RMWs the stale in-AIL base → destage clobbers node1_f4.md5.

### Heavy background context (release-side)
P34-LEAF-DRAIN fires ~19k×/run; **9593× are CACHED=0** (leaf block uncached at release → release-drain can't destage it — flagged in-code as the "Inv 1 leaf gap"). Not yet proven causal to THIS data-dirent loss but suspicious for the leaf-hash half.

### Fix direction (the ONLY non-refuted path)
**Transactional 3-way re-apply at re-acquire / addname** (sess28 option 1, NEVER tried): when an addname is about to RMW a dir-DATA block that is stale (bgen≠dir_gen) AND in_ail (can't read-invalidate), within the addname transaction read the coherent disk and RE-ADD the peer's unique dirents (node1_f4.md5) so leaf+freeindex+data all update coherently. Candidate site: `mxfs_dir_addname_coherent_refresh` (xfs/libxfs/xfs_dir2_data.c:1603, called from xfs_dir2_{node,leaf,block} addname; gated `mxfs_dir_addname_coherent`, default 0 — it currently does a FUA re-read but does NOT eliminate the loss → needs to become a real txn merge).

### REFUTED hard this session
- **`dir_write_merge=1`** (non-txn bio-submit graft) → **bnobt double-free SHUTDOWN** `ltbno+ltlen>bno` (xfs_alloc.c:2254). Strictly worse. Don't retry. The graft updates data+bestfree+CRC but NOT leaf/freeindex/free-space-btree → AG corruption.

### Standing: 1/2/4 tcp = 100%, 8/tcp = 2/3 (only this loss remains). [[sess31-STATUS-8tcp-residual-is-clean-single-dirent-loss-only]] [[sess31-BREAKTHROUGH-duplicate-iscsi-iqn-was-the-8node-flakiness]]
</body>
