---
name: sess10run2-PROVEN-transport-clean-lastrel1-cluster-clobber-suspect
description: sess10 PROVEN: transport sound (6000 cross-node FUA reads, 0 anomalies); lastrel_flag=1 at every SF revert = release flush RAN yet platter regressed…
metadata:
  type: project
---

# sess10 late findings — transport exonerated, cluster-clobber prime suspect

## RULE-4 chain
1. r10 (unarmed chain iter): dlm_scaling 1/4 rate-face; P-SFDIR-REVERT on parent ino=8389057 on ALL nodes: incore=N disk=fua=N-1 with **lastrel_flag=1, lastrel_age_ms=5..256, lastrel_size=full** → the releasing node's `__mxfs_dlm_dir_inode_durable` RAN and completed (delwri submit + blkdev_issue_flush + AIL-exit + P55D self-skip retry all inside mxfs_inode_cluster_durable, xfs_mxfs_dlm.c ~3870-4085) yet the PLATTER (SCSI FUA read) regressed to N-1 within ms.
2. SCST config (/etc/scst.conf): v5 LUN = vdisk_fileio disk1 with **async 1 + o_direct 1** (disk1b = same image write_through — unused by v5?). Suspected ack-before-media.
3. **Transport TESTED CLEAN** (RULE 4): plain-write+SYNC_CACHE+same-node FUA read ×100 idle = 0 miss; ×120 under cross-node 3GB write storm = 0 miss; cross-node monotonicity (t2 writes 1500 ascending patterns each +sync; t1 FUA-reads ×6000) = **0 backward**. The async SCST export honors flush-vs-FUA ordering. INFRA EXONERATED.
4. ⇒ The platter regression must be a LATER WRITE carrying older bytes: **co-resident inode-cluster clobber** — nodes iflush the shared 4KB cluster (parent dir + their own subdir/file dinodes co-resident); a node whose cluster BUFFER holds stale parent bytes (its copy predates the peer's parent update; xfs_iflush_cluster only re-copies inodes it owns/dirty — P119 discards non-EX co-residents) writes the mosaic → last-writer-wins regresses the parent slot. Fits: dlm_scaling (parent+4 subdirs same cluster), fence hot-dir leak, and P-SFDIR-REVERT on all 4 nodes seeing the same regressed platter.

## New detector (build 89321B9D)
P10-CLREGRESS (pal/linux/xfs_buf.c, after the P97 block): on every multinode inode-cluster WRITE submit, gated `mxfs_dir_relverify`, FUA-read the on-disk cluster and for each DIR dinode slot (magic IN + S_ISDIR(di_mode@0x2) + same di_gen@0x5C): if disk di_size@0x38 > buf di_size, or equal size + disk SF-count(byte@176, v3 LOCAL both, fmt@0x5) > buf count → pr_warn P10-CLREGRESS with owned (b_li_list boffset match) + ofields + comm + realns. owned=0 hits = clobbering an unowned peer slot = THE mechanism.

## RUNNING at write time: ds2 loop ×8
`MXFS_EXTRA_MODARGS='dir_relverify=1 watch_ino=999999999999' MXFS_WATCH_ARM=0 scripts/suite_cycle_run.sh 4 tcp scratchpad/ds2_loop.log dlm_scaling` (session scratchpad 2eca429b). READ ds2_loop.log + /tmp/run_dlm_scaling_* artifacts: on any FAIL (or even PASS runs) grep kernlog_test* for **P10-CLREGRESS** — owned=0 lines pin the clobber writer + moment. Correlate with P-SFDIR-REVERT lastrel.

## Fix directions once CLREGRESS confirms (pick per evidence)
- At iflush_cluster (or the mxfs overlay): for UNOWNED dir dinode slots, refresh slot bytes from a FUA read (or from a per-slot authoritative source) before writing — i.e., never write stale co-resident dir slots (surgical per-slot merge; the sess45 P97 comment already suggested "surgical per-inode write (skip non-owned)").
- Alternative: skip writing unowned+clean slots by masking?? cluster writes are whole-buffer — need content merge, not skip.
- Note sess55 REVERT lesson: blanket FUA-refresh of the whole cluster buffer pre-flush REGRESSED (adopts stale disk for fresh-created inodes, readdir=0) — the merge must be PER-SLOT and only for slots NOT owned/dirty locally, and only ADOPT disk bytes that are AHEAD (size/count/gen-equal comparison), never behind.

## Also this session (see companion memories)
- pal.md updated (P-DIRWR watch scope). watch_light modparam added (heavy P49/P13-COLLIDE per-placement platter walks skippable; cheap traces stay) — for the dir_reuse round-3 block0 fork armed-light repro, still TODO after ds2.
- dir_reuse r3 face: 2 repros (iter7, chain-r8), victims=peers' f1/f2, verify in-core==platter, conversion at mkdir (P42-SFCONV sf_count=0) — block0 birth-fork on reused daddr. The cluster-clobber mechanism may ALSO explain it if the parent DINODE regression at the wrong moment forks block0 lineage... but block0 content itself lost = needs the armed-light P-DIRWR timeline. NEXT after ds2: `MXFS_WATCH_ARM=1 MXFS_EXTRA_MODARGS='watch_ino=1 watch_light=1' suite_cycle_run.sh 4 tcp <log> dir_reuse_coherency` ×8.
- Chain results r8-r10: r8 16/17 (dir_reuse r3), r9 16/17 (tds 0/4 unarmed = REAL face), r10 16/17 (dlm_scaling rate 1/4). r11-13 killed (superseded by ds2 loop).
