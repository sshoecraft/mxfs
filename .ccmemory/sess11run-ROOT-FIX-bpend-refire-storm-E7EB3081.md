---
name: sess11run-ROOT-FIX-bpend-refire-storm-E7EB3081
description: sess11 ROOT PROVEN+FIXED (E7EB3081, KEEP): dlm_scaling rate storm = ilock_end CACHED&&bast_pending refire NEVER consumed bpend → eternal release/reac…
metadata:
  type: project
---

# sess11 (ccloop a9a03929) — the ino-131 PR self-revoke storm: PROVEN + FIXED

## What the storm was (corrects sess10's read)
- sess10's P10-CLREGRESS 1630× "stale-dirty-ili livelock" on t1 was a MISREAD: ino 132 (off=2048 daddr=128) is node1's OWN dlm_scaling dir, held EX (mode=5) the whole test, oscillating create fN (size 18) → rm fN (size 6). buf_size=6 vs disk=18 = the write is the NEWER post-rm image; the detector's size-only compare can't tell newer-smaller from stale-smaller. **P10-CLREGRESS is a false-positive detector under rm-heavy workloads** — do not chase it without a version/seq discriminator.
- The REAL rate-face root: ino 131 (`.dlm_scaling` parent, block-dir daddr=72) PR lock revoke storm. t1 in FAIL run 20260703T210920Z: 22,587 P4L-ALLOC (all mode=3 PR, only 2 owners t1+t4), 11,445 P6U-UNLOCK (all PR, all comm=kworker), 2,554 P3D-RELINVAL, rel_gen reached ~10,000 — with **ZERO real BASTs (P7S-BAST-FIRE=0, P7B-BASTNOTIFY=0)**. ~5 path-walks/op × full TCP DLM round-trip + dir-block invalidate = 20ms/op = <50 ops/s floor FAIL (peers 212).

## Engine (RULE-4 proven via new qsrc/bpend forensics)
P70-BP ENTRY now prints qsrc (who queued the work) + bpend. Storm run 21:53:54Z: **t2 5,991 entries ALL qsrc=1 (ilock_end refire) bpend=1**; P11-ACQSTALE-SELFBAST stayed at 1-3 → completion-check self-BAST is only the SEED, not the engine.
- Lifecycle bug: `i_dlm_bast_pending` set by 4 sites (MHT batch_arm 17739, P15 gen-moved abort, stranded, MHT rearm); ONLY consumer was the dwork fn (sess36: "dwork is the SOLE releaser", deliberately doesn't consume when busy). The sess9-v3 ilock_end arm `CACHED && bast_pending` ALSO releases on it but NEVER cleared it → any bpend surviving a completed work-channel release refired a FULL DLM release+reacquire after EVERY subsequent use, forever. Two flavors seen: full-release storm (relinval=4000 capped) and spin-reentry storm (5,941 entries, relinval=2).
- Seed shapes (P11 marker): `stale=1 src=7 acq_bast=0` = slow-path pre-reload stale survived a reload keep-stale bail → false self-BAST (1-2 per healthy run); also legit src=6/7 with acq_bast=1 (sess35 deferred BAST — correct).

## Fix (build E7EB3081, KEEP)
`mxfs_dlm_ilock_end` gate: `ip->i_dlm_bast_pending = false;` when committing state=DEMOTING. Obligation is discharged by the release; abort paths re-SET bpend after aborting so a truly-owed BAST re-arms. Stray flag now costs ≤1 extra release.
Verified: 2× dlm_scaling PASS, relinval 0-3/node (was 4000+), qsrc1/bpend1=0 (was 5991), bp_entries 4-10 (was thousands), iteration wall 73s (was ~110s).

## Instrumentation added (always-on, cheap, KEEP)
- `i_dlm_stale_src` (xfs_inode.h:135, u8): last i_dlm_stale=true setter code. 1=readdir 2=consumer_refresh 3=modify_prelock 4=adopt_fmt 5=bast_process_rel 6=bast_notify_acq 7=ilock_slow_prereload 8=fastpath_rearm 9-13=dlm misc 14-17=iget 18-20=inode misc 21-23=super.
- `i_dlm_bastq_src` (u8): who queued bast work. 1=ilock_end_refire 2=demwait 3/4/5=bast_notify idle/orphan/immediate 6=ilock_begin_recov 7=acq_selfbast 9=mht_arm 10=stranded 11=batch_arm. Printed in P70-BP ENTRY (+bpend).
- P11-ACQSTALE-SELFBAST (capped 8000, ino<=256) at slow-path grant completion: the previously SILENT stale-only self-BAST now visible with src.
- Module param `mxfs.acq_stale_selfbast` (default 1=legacy): 0 = don't self-BAST on stale alone (keep grant CACHED; on-use reload paths cover coherency — ilock_try rejects on stale, readdir:959/lookup xfs_inode.c:991/modify-prelock re-check). NOT yet flipped — seeds are harmless post-fix. A/B lever if residual churn matters.

## Where things stand / next
Ladder: dlm_scaling ×8 clean (2/8 done) → full 4/tcp ×3 → 8/2/1 node. Storm byproducts were plausibly feeding the durable-loss faces (quota-0 SFDIR-REVERT, fence leak, dir_reuse r3, tds pace) — re-measure them on E7EB3081 before chasing further. dir_relverify=1 kept for comparability during ladder; consider off for perf once loss faces re-baselined.
