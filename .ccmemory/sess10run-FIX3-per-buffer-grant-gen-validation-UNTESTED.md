---
name: sess10run-FIX3-per-buffer-grant-gen-validation-UNTESTED
description: sess10(ccloop) FIX3 build 9527F28F (UNTESTED): per-buffer b_mxfs_grant_gen — dir block re-read under EX if last read under an older grant gen (GPT fr…
metadata:
  type: project
---

## sess10 (ccloop 4cb2d0a2) FIX3 — per-buffer grant-gen validation (build 9527F28F, UNTESTED — validate next)

### Rationale (GPT-5.5 + proven evidence)
The clobber is stale_base=0 (invisible to lossy i_dlm_dir_gen, which gets stamped FRESH over STALE content). GPT: freshness must mean "read under the CURRENT grant," using the reliable acked-TCP grant gen. Also discovered: the pre-read dir-gen invalidation in xfs_da_read_buf is gated `!owned_ex` (SKIPPED when we hold EX = the modify/clobber path), so an EX RMW serves whatever is cached.

### The change (3 files)
1. `xfs/xfs_buf.h`: added `uint32_t b_mxfs_grant_gen;` (grant gen at last COHERENT read of a dir block).
2. `xfs/libxfs/xfs_da_btree.c` xfs_da_read_buf:
   - postread_reread gate (~3673): ALSO re-read when `dp->i_dlm_mode == 5 (MXFS_LOCK_EX) && bp->b_mxfs_grant_gen != dp->i_dlm_cached_grant_gen` (block last read under an older grant → we lost+reacquired EX since = peer modified → stale). The existing `clean`(destaged, !dirty/!in_ail/!pinned/!delwri/!undestaged) guard still wraps the actual re-read → no resurrection.
   - stamp `bp->b_mxfs_grant_gen = dp->i_dlm_cached_grant_gen` on a genuine fresh disk read (gated dir_stamp_fresh, which is true ONLY on inc_rc==-ENOENT = real cache miss) AND on the postread re-read success path.
   Net effect: each dir DATA block is coherently re-read ONCE per EX grant tenure (when grant gen changes = handoff), reliably, independent of the unsound i_dlm_dir_gen. Within a tenure: no re-read (perf OK).
   - NOTE: had to hardcode `5` for MXFS_LOCK_EX (enum include/mxfs/mxfs_dlm.h not in scope in xfs_da_btree.c; NL=0..EX=5, confirmed by traces mode=5=EX).

### VALIDATE NEXT (build is 9527F28F, deployable; cluster clean, test1-8 up)
1. dir_reuse 4/tcp with a virsh destroy+start of test1-4 BEFORE EACH run (MANDATORY — a FAIL wedges a node → next mkfs fails; see [[sess10run-REFUTED-fua_disable0-and-test-harness-wedge]]). Run >=4 separate reset+run cycles; baseline is ~80% FAIL so need several clean PASSes.
2. If it fixes 4/tcp: full ./run.sh 2 tcp (RESURRECTION canaries unlink_visibility/rename_visibility/dlm_fairness MUST stay PASS — primary risk), then 1/4/8, watch RULE-0 timing (~13s/round).
3. If it does NOT fix: the staleness is NOT a cached-block-under-EX issue → pivot to release-side (the EX owner's slow-path cold-read itself returns pre-peer-durable content = GPT Rank 1 ordering); do the P106-EXREL vs P-DIRRD timing experiment (see [[sess10run-HANDOFF-do-release-grant-timing-probe-next]]). If it REGRESSES (resurrection): the clean-guard is insufficient → revert (remove the b_mxfs_grant_gen trigger in xfs_da_btree.c; the field is harmless).

### Refuted earlier this session (do NOT re-try): dir_epoch_adopt, fast-path grant_gen trigger (inert), handoff bool, level epoch, dirskip, non-owner flush, fua_disable=0.
See [[sess10run-DECISIVE-fastpath-dominant-P63-handoff-never-fires]] [[sess10run-GPT-consult-durable-clobber-stale-inAIL-block-survives-release]].</body>
