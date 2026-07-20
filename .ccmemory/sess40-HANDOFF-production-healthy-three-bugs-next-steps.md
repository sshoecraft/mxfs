---
name: sess40-HANDOFF-production-healthy-three-bugs-next-steps
description: sess40 HANDOFF: dir_reuse 2/tcp — BOTH the sess39 fence AND sess40 ABA skip are REFUTED. Build B9F9326E = mht_ms=300 default + inert ABA skip + incar…
metadata:
  type: project
---

## sess40 (ccloop 8ddb16a2) HANDOFF — dir_reuse_coherency 2/tcp. Marker NOT written. Build **B9F9326E0E9490E9F83866B** deployed.

### What this build is:
B9F9326E = (prior C22056240) + **mxfs_inode_mht_ms default 50→300** (xfs_mxfs_dlm.c:3718) + a REFUTED-but-INERT dir-block ABA writeback skip + dir-block incarn stamping (mxfs_dir_data_track, xfs_dir3_data_init). The ABA skip (b_mxfs_dir_incarn != i_generation) fires 0× — harmless; can be removed. The sess39 inode-cluster fence (xfs_inode.c P-CLMERGE-DEADINCARN) is ALSO inert/refuted. **mht=300 default is the load-bearing keep** (canonical ./run.sh 2 tcp now uses the working timing config).

### TWO fixes REFUTED this session (RULE 4, don't repeat):
1. **sess39 inode-cluster incarnation fence** (P-CLMERGE-DEADINCARN): fired 0× even on FAILs. Wrong object.
2. **sess40 dir-block ABA incarnation skip**: P16 proved on daddr=120 writes **bincarn==cincarn in ALL 272 cases (aba=0)** → the clobber is NOT a dead prior incarnation. Confirms [[sess16-stale-tenure-keepguard-fix]]: i_generation is the WRONG token; **b_mxfs_dir_gen vs i_dlm_dir_gen (TENURE)** is right. 16 daddr=120 writes had bgen<dgen.

### THREE independent failure modes (all must pass for 100%):
- **Bug A — stale-tenure block-0 clobber** (readdir short, lookup_fail=0): xfsaild flushes a CURRENT-incarnation but PRIOR-EX-TENURE block-0 (b_mxfs_dir_gen < owner i_dlm_dir_gen) over the peer's newer durable image. There is NO always-on DATA-block writeback guard (the sess20 leaf-clobber guard described in pal.md is from an OLD lineage, NOT in this tree).
- **Bug B — AG free-space DOUBLE-ALLOC → EFSCORRUPTED** (C22056240 iter3 corrupt=39): random file data over inode cluster @daddr 0xb40, P117-AGMETA-STALE-CLEAN bnobt firing. Allocator-side; file data bypasses the xfs_buf chokepoint. HARDEST.
- **Bug C — borderline TIMEOUT**: ~284s at mht=300 (sess36) vs run_coord TEST_TIMEOUT=300. sess36 already fixed the 6s deferred-BAST handoff (mxfs_dlm_bast_dwork_fn re-arms every ~4ms); residual is aggregate TCP-DLM op latency. dirwr=1 logging tips it over 300s → false timeout FAILs.

### ⚠️ CRITICAL METHODOLOGY: validate ONLY at production (dirwr=0, mht=300 default = NO MXFS_EXTRA_MODARGS). dirwr=1/instr=1 PERTURB timing → timeouts + heisenbug races. At dirwr=0 the test is healthy: production batch iter1 PASSED clean (~5min, fit timeout). Reserve dirwr=1 for SHORT targeted diagnosis only; trust dirwr=0 results.

### NEXT STEPS (priority):
1. **Read the production batch result** (tests/_cap/loop_summary.txt, task was running `bash tests/drc_loop.sh 5` at dirwr=0). iter1 PASS. If 5/5 or 4/5 → production is close.
2. **Run the FULL suite at production**: `unset MXFS_EXTRA_MODARGS; bash tests/suite_loop.sh 2 tcp 2` (harness written this session) — must reach 17/17 reproducibly (16 of 17 last passed on STALE older builds). Reboot test VMs (virsh destroy+start) for a clean slate if results look flaky.
3. **If Bug A recurs at dirwr=0**: implement an always-on DATA-block writeback clobber guard in mxfs_buf_xfsaild_skip_dir_write / the pal chokepoint — FAST PATH `b_mxfs_dir_gen >= owner i_dlm_dir_gen` returns (no disk read); SLOW PATH (bgen<dgen) plain-bdev-read the daddr (mxfs_pal_bdev_read_plain_bdev, pattern at pal/linux/xfs_buf.c:2052) + count live dirents (mxfs_dir3_data_fingerprint) + skip iff disk is a VALID same-owner dir block with MORE dirents (disk_cnt>buf_cnt). Mirrors the sess20 leaf guard; avoids the fresh-block false-positive. Add always-on P-DATACLOBBER-SKIP log.
4. **Bug C** if timeouts recur at dirwr=0: the ~284s is aggregate latency; profile per-op (sess34 6s handoff already fixed). Lower mht? (tradeoff: more coherency churn).
5. **Bug B** (hardest): AG bnobt/cntbt/agf coherence — P117 release-discard is insufficient; the double-alloc still occurs. Enable instr for P32B-DOUBLEMAP / P31E evidence.

Harnesses (RULE 3, in tree): tests/drc_loop.sh N (per-iter PASS/FAIL+detector aggregation), tests/suite_loop.sh N dlm K (full-suite reproducibility). Related: [[sess40-ABA-fix-REFUTED-clobber-is-current-incarn-stale-tenure]] [[sess40-fence-REFUTED-real-root-dirdata-clobber-plus-AG-doublealloc]] [[sess34-6s-dir-handoff-is-LOCK_ACQUIRE_WAIT_MS-deferred-bast]]
