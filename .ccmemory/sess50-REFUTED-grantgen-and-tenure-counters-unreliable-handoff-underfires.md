---
name: sess50-REFUTED-grantgen-and-tenure-counters-unreliable-handoff-underfires
description: sess50(ccloop): MEASURED-refuted grant_gen writeback gate + refresh_inplace. Root lead: DLM handoff/grant-gen UNRELIABLE for contended dir inode (gra…
metadata:
  type: project
---

## sess50 (ccloop 4cb2d0a2) — comprehensive RULE-4 refutations + new DLM-handoff-unreliability root lead

Build at relay: instrumentation only (P50-RD/P50-WR content trace, P50B-TENURE, grant_gen fields in P-DATACLOBBER). srcversion 4115969B. NO functional fix yet. Baked default still 3B0EB406 behavior (epoch_adopt=0).

### CLEAN failure signature (no modargs, 8/tcp, DRC_ROUNDS=16): ALL nodes agree round-1 loses exactly ONE dirent `node1_f9.md5` (readdir=799/800, LOOKUP_ENOENT, REREAD_MISS = durably gone). Cascades later (a node stuck 699/800 or 0/800; test1 dir even fails to stat → dirino empty). EXP=800 (8 nodes × 100 files into one shared dir, EX-serialized adds, then rank1 rm-rf+recreate reusing ino 131/daddr 120).

### REFUTED THIS SESSION (each with direct measurement — DO NOT RETRY):
1. **grant_gen writeback gate** (sess49 GPT design): added detector logging bp->b_mxfs_grant_gen vs ip->i_dlm_cached_grant_gen at the clobber. **gg_mismatch=0 on EVERY clobber** (buf==cur, frequently BOTH 0). The gate would never fire. grant_gen is INERT for the contended dir inode.
2. **dir_refresh_inplace=1** (P39 EX-gated disk strict-superset drop): modarg test → REGRESSES to whole-batch loss (round2 loses node1_f1,f10,f10.md5,f11... — drops legit writes; same class as sess26/28). 
3. **Case A — allocator overwrites live dirent** (GPT free-slot theory): RULED OUT by logic — xfs_dir2_data_use_free calls xfs_dir2_data_check_free (xfs_dir2_data.c:1872) which EFSCORRUPTs on a non-free slot; we see SILENT loss not corruption shutdown.
4. **Case B via i_mxfs_ex_grant_seq tenure counter**: P50B-TENURE shows clobber buf_tenure == cur_epoch (prior_tenure=0) on ALL xfsaild clobbers — BUT this counter is UNRELIABLE (only bumps on slow-path EX upgrade @ xfs_mxfs_dlm.c:15172, NOT on fast-path serves / under-fired handoffs), so prior_tenure=0 is a likely FALSE NEGATIVE.

### CONFIRMED (re-derived): reads coherent (sess37 P28-PLATTER MATCH), modify base NOT stale (sess69 P-TDS-RMW=0), loss is COUNT-PRESERVING (existing always-on P-COUNTREGRESS @ xfs_buf.c:2784 fires 0× — one dirent replaced, count held up by writer's own add). Clobber buffer = clean(bdirty=0)/in_ail=1/pin=0/EX/same-incarn, byte+grant+count IDENTICAL to legit rm (sess69 conclusive: NO local write-side discriminator).

### Storage: target is genuinely **LIO-ORG** (lsscsi), write-through cache, per-initiator read caches → FUA reads REQUIRED+ON (fua_disable=0 correct). NOT SCST. So FUA-platter-lag is NOT the mechanism.

### NEW ROOT LEAD (the actionable one): the DLM EX handoff/grant epoch is UNRELIABLE for the contended dir inode 131. mxfs_dlm_grant_gen (dlm/dlm.c:2406) scans LOCAL table for a granted lock owned by local_node; returns 0 when none — yet XFS i_dlm_mode=5 (EX). DISCREPANCY = XFS serves a CACHED/phantom EX not backed by a current local DLM grant. mxfs_dlm_grant_was_handoff (dlm.c:2442) returns lk->handoff but UNDER-FIRES ~80% on TCP (comment xfs_mxfs_dlm.c:14435). Mechanism: peer takes real EX, modifies disk to N, releases; this node's fast-path keeps serving stale N-1 buffer (handoff not detected, grant_gen/epoch unchanged), xfsaild flushes N-1 over N. **If handoff/grant-gen detection were reliable, the EXISTING evict-on-acquire (xfs_mxfs_dlm.c:15142, gated on grant_gen change) + read-gate (xfs_da_btree.c:3950) would fix it.**

### GPT-5.5 consult (this session, RULE-5 justified — prior grant-epoch design refuted by measurement): two structural fixes that DON'T need reliable handoff detection — **Fix 3**: on EX acquire for a shared dir, UNCONDITIONALLY invalidate ALL cached dir metadata buffers (data+leaf+node+free), force cold reload (not gated on the unreliable grant_gen). **Fix 4**: EX release must guarantee NO AIL item can later push a home-block write (force log to inode's LSNs, push AIL, wait BLIs leave AIL + writeback done, invalidate clean dir buffers, blkdev_flush, THEN unlock) — stronger than current flush-dirty+blkdev_flush. **Fix 5**: local lockseq write-authority LIFETIME token (not content suppression): xfsaild may push a dir buffer only while its stamping lockseq is the active EX tenure or in release-drain; after unlock, quarantine/invalidate. Birth-stamp at data_init to avoid the fresh-block(tenure_id=0) false-positive that made the existing tenure_mismatch arm detect-only.

### NEXT (RULE 4): (a) determine WHY grant_gen=0 / handoff under-fires — is it a lost-BAST DOUBLE-GRANT (master grants peer EX on BAST timeout while we still hold)? Check master grant-while-held / BAST-timeout path in dlm.c. (b) If double-grant: fix the DLM (don't grant until holder releases). (c) Else implement GPT Fix 3 (unconditional acquire-invalidate of all dir meta for shared dirs) — most robust, sidesteps unreliable detection. Test each (RULE 4); watch RULE-0 timing.

See [[sess49-GPT-design-dlm-epoch-authority-for-dir-buffer-coherency]] [[sess69-CONCLUSIVE-no-writeside-fix-buffer-content-reverted]] [[sess49-residual-two-modes-write-clobber-and-reader-stale-block]].</body>
