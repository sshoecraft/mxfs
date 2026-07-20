---
name: sess10run-HANDOFF-do-release-grant-timing-probe-next
description: sess10(ccloop) HANDOFF: leading root = release→grant ordering race (GPT Rank1); fast-path/non-owner/param fixes all refuted. Next: add release-flush-…
metadata:
  type: project
---

## sess10 (ccloop 4cb2d0a2) — HANDOFF: the ONE experiment to run next

### State: criterion NOT met. Tree at clean baseline DE3A7E21 (ALL sess10 experiments reverted). Cluster clean (test1-4 rmmod'd), test1-8 VMs up.

### Settled this session (do NOT re-try these — refuted)
- 4/tcp dir_reuse: durable single-dirent loss ~80%, all nodes lose SAME entry (durable on shared target = write clobber). 2/tcp clean. Coherency family otherwise passes; only dir_reuse fails at 4-node.
- REFUTED: dir_epoch_adopt=1 (~1/5); fast-path grant_gen-change trigger (INERT, P-FXGGEN=0 — cached_gg tracks hgg); fast-path handoff bool (under-fires, consumed via acted_gen); level epoch (constant within tenure, epoch_adv=0); dirskip=1 enforce (refuted sess17); non-owner xfsaild flush (sess69: clobber holds real EX). Writer durability WORKS (P-DSIG flush=1). Slow-path acquire ALREADY cold-reads+evicts unconditionally. Clobber is stale_base=0 (invisible to all in-core gen).
- GPT-5.5 consult: leading root = RELEASE→GRANT ordering race (Rank 1) or release-drain coverage hole (Rank 2). i.e. the EX owner that clobbers got a STALE base from its slow-path COLD-READ because the peer's just-committed entry was not yet visible on the shared target when it read (DLM granted before the prior owner's drain/flush was truly complete+visible), OR the prior owner's release drain skipped the block.

### THE decisive experiment (RULE 4 — run FIRST next session)
Prove/refute Rank 1 by timing. Add a probe at the END of the dir-inode release in bast_process (xfs_mxfs_dlm.c, right BEFORE mxfs_v5_dlm_inode_unlock, after mxfs_dlm_dir_inode_durable/mxfs_dir_flush_data_blocks + blkdev_flush) logging: `P-RELDONE ino=%llu realns=%llu` (the moment our dir mods are durable+we're about to release). The acquire side already logs P105-ACQ-DIRINODE (realns) and P-DIRRD (cold-read crc+realns). Then run `MXFS_EXTRA_MODARGS='dirwr=2' MXFS_TEST_ENV='DRC_ROUNDS=20 DRC_STREAM=1' ./run.sh 4 tcp dir_reuse_coherency`, find the lost entry's round (mxfs-drc-RDMISS) + its block daddr, and across nodes by realns check: does the clobbering owner's first COLD-READ (P-DIRRD) of that daddr occur BEFORE the peer's P-RELDONE for the same dir? 
- If YES (read before peer release-done) → Rank 1 CONFIRMED → fix: make the DLM master not grant the next EX until the releaser's P-RELDONE (two-phase unlock), OR make the acquirer's cold-read wait for/verify the grant's durability seq.
- If the cold-read is AFTER peer release-done but still returns content WITHOUT the entry → Rank 2 (drain coverage hole) → fix mxfs_dir_flush_data_blocks (per-grant touched-set; the "uncached⇒skip" at line ~1290).

### Separately blocking criterion: in-suite contamination (tests pass standalone, fail in full ./run.sh — fault tests degrade later tests; run.sh has no inter-test recovery). Address after dir_reuse.

### Repro/env: dir inode = 131 (REUSED every round via rm-rf+recreate — incarnation aliasing complicates static lineage; key on round# from DRCph/RDMISS). Bash tool default timeout 120000ms — use run_in_background or raise timeout for run.sh (~5min/run). Reset between full runs: virsh -c qemu:///system destroy+start.

See [[sess10run-FIX2-grant_gen-change-fastpath-refresh]] [[sess10run-GPT-consult-durable-clobber-stale-inAIL-block-survives-release]] [[sess10run-DECISIVE-fastpath-dominant-P63-handoff-never-fires]] [[sess10run-NEXT-real-fix-direction-concurrent-rmw-stale-base]].</body>
