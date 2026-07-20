---
name: sess10run2-iter-results-dlm-scaling-sf-durability-lead
description: sess10(a9a03929) iters 1-6: 4×17/17; real flakes = fence leak (iter1, 5 durable names) + dlm_scaling node4 own-mkdir ENOENT (iter5). SF-parent disk_c…
metadata:
  type: project
---

# sess10 iteration results + dlm_scaling SF-durability lead

## Suite iterations (build lineage 48BCA7DF→939EC23E→F46BCC58→D4C22548, all + watch_ino instrumentation)
- iter1 (armed): 16/17 — fence_during_write leak: 5 durable leftover names (n2_0 n2_12 n4_12 n4_13 n4_15) in hot dir; REAL flake (fence was unarmed then).
- iter2 (armed): 17/17. iter3 (armed): 16/17 tds 42/150+35/150 rounds + leak n2_r43/n3_r36 — **tds break rounds = P5D-STALE-SERVED comm=mv trans=1 moments** BUT ALSO perturbed by watch leak (ino reuse; P-DIRWR 3370x during tds).
- iter4 (armed): 17/17. iter5 (armed): 15/17 — dlm_scaling 3/4 REAL (below) + tds window-miss (perturbed by P50-RD per-da_read platter reads, 6216x — REMOVED from P50-RD after).
- iter6 (UNARMED r8-parity, MXFS_WATCH_ARM=0): 17/17. iter7 unarmed launched.
- Hygiene added: lib.sh finish() resets watch_ino→1; MXFS_WATCH_ARM=0 mode uses watch_ino=999999999999 (silences ALL storm probes incl legacy ino<=256).

## dlm_scaling iter5 failure (artifact /tmp/run_dlm_scaling_20260703T191250Z + kernlog_test*)
- node4: own `mkdir -p .dlm_scaling/node4` ok, then FIRST create `node4/f1` = ENOENT → break → quota 0/2000. Parent `.dlm_scaling` ino=12583063 SHORTFORM.
- P-SFDIR-REVERT fired 21-30×/node on the parent: incore_cnt=N, disk_cnt=N-1, **fua_cnt==disk_cnt** (SCSI READ FUA = platter authority) → the LUN PLATTER genuinely lacked the last committed entry at reload, repeatedly, in_ail=0 pin=0.
- NO P13-SFPARENT-DURABLE-FAIL / P68-DIRINODE-DURABLE-FAIL lines → the release-side `__mxfs_dlm_dir_inode_durable` (xfs_mxfs_dlm.c ~10769, inside the dir release drain) either ran+succeeded (yet platter stale ⇒ **flush lands in SCST write-cache; blkdev_issue_flush→platter step unreliable or missing**) or was skipped via a path that bypasses this drain section.
- Skip-gate at 10767 (`mxfs_dir_pr_release_fast && p_clean_release && (>=2 || self_demote)`) can NOT skip EX releases (p_clean_release requires held!=EX).
- mxfs_inode_cluster_durable (~3870): release-side 1500×2ms wait, iflush_cluster + AGAIN→submit + (per comment) delwri_submit + blkdev_issue_flush.
- **DISCRIMINATOR READY: P-SFREL-VERIFY probe (~10777, gated dirwr/instr/mxfs_dir_relverify) FUA-reads the dinode AFTER the durable call at every SF-dir release → DURABLE vs STALE-DISK verdict.** Run standalone dlm_scaling loop with MXFS_EXTRA_MODARGS='dir_relverify=1': STALE-DISK despite durable-call ⇒ flush-to-platter gap (fix at cluster_durable: verify+retry FUA readback); all-DURABLE yet peer reads stale ⇒ different release path bypasses the drain (find it).

## Other confirmed mechanisms this session
- tds round-break ↔ P5D stale-serve correlation (iter3): P5D LOCKED branch = "buffer locked >50ms during dir read" (b_mxfs_stale_pending is NEVER SET anywhere — the honor mechanism is vestigial; P5D is a busy-buffer proxy).
- fence leak names persist durably; mechanisms candidates: lost-remove via peer stale-base RMW resurrect, or silent rm -f ENOENT via stale lookup view.

## r8 forensics (see sess10run2-r8-forensics-t3-stale-serve-conversion-fork)
Block0 daddr=7872: t1 never destaged post-conversion (0 t1 P64 data-writes), t3 converted at 343.066 after platter re-read at 342.928, t3 P5D stale-serves 343.16/343.26, last write t3@343.810 = durable lineage missing 59.
**Unifying theme: EX handoff outruns durable-to-PLATTER (write-cache vs FUA-read asymmetry) → next holder RMWs stale base → last-writer-wins.** The dlm_scaling SF case is the cleanest lab for it (single dinode, no block machinery).

## State
Build D4C22548 deployed via iter6/7. dir_reuse: no failure in 6 iters + 3 standalone (r9). Marker NOT written. Next after dlm_scaling loop: root-fix durability-at-handoff, then 3 consecutive clean 4/tcp, then 8/2/1.
