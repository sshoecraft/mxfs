---
name: sess5-ccloop-dirreuse-lostupdate-acquire-reload-locked-skip-gap
description: sess5(run6614) dir_reuse lost-update GAP pinpointed: acquire-reload (xfs_mxfs_dlm.c:13384) UNCONDITIONALLY stales cached dir blocks but TRYLOCK-SKIPS…
metadata:
  type: project
---

## sess5 (run 6614) — dir_reuse readdir-undercount lost-update: gap pinpointed

Build 59784327 (2/tcp=17/17 solid). dir_reuse 4/tcp ~70% pass (readdir=300/exp=400, lookup_fail=0 = 100 dirents DURABLY LOST = sess52 node-addname stale-base RMW clobber). This is PRE-EXISTING (sess4: flaky 25-50%), independent of my salvage fix.

### THE PINPOINTED GAP (xfs_mxfs_dlm.c ~13310-13408, mxfs_dlm_reload_inode acquire-side)
On fresh inode-EX acquire the reload walks ALL dir extents and UNCONDITIONALLY stales cached dir blocks (`xfs_buf_stale` + clear XBF_DONE — gen/epoch INDEPENDENT, correct). BUT it uses `xfs_buf_trylock`; a LOCKED block (in-flight xfsaild writeback of this node's own prior-tenure stale copy) is SKIPPED (`n_locked_h18++`, P-H18-INSTR locked_skip=1 observed). The surviving stale block is then RMW'd by the next addname → the peer's 100 dirents in that block are durably clobbered. sess37: blocking xfs_buf_lock here DEADLOCKS (lock inversion); bounded-retry+msleep REGRESSED.

### REFUTED config levers THIS session (all measured on 59784327-equiv):
- dir_tenure_evict=1 dir_tenure_stale_bypass=1 → 4/5 (no better).
- force_coherent=1 dir_tenure_evict=1 → 3/6 (no better / slower).
- Broad owned_ex-independent read-salvage → 2/6 (REGRESSED — over-fires on shared readers keeping stale blocks; REVERTED).
- dir_grant_evict=1 already default-ON (sess36: safe but insufficient). dir_newtenure_evict=1 default-ON. Epoch check defeated by MODIFY/READ-time b_mxfs_dir_epoch LAUNDERING (sess52) and/or stale master-epoch (cur_mep) propagation, so prior_tenure evict misses.

### WHY read-path (xfs_da_read_buf) fixes CAN'T reach it: addname RMW holds dir EX (owned_ex=1) → the read-time revalidation gate is skipped unless tenure_evict on; and even on, the epoch signal is laundered. The staleness must be killed at ACQUIRE (reload) or WRITE-completion, not read.

### CANDIDATE FIXES (not yet tried):
1. DEFERRED-STALE: when acquire-reload can't trylock a dir block, mark it (per-buffer flag under b_lock) so xfs_buf write-completion (__xfs_buf_ioend) or the next read force-stales it once the lock frees. Closes the locked-skip window.
2. Ensure release-side drain WAITS for dir-block writeback COMPLETION (sess40 b_mxfs_dir_wr_counted barrier) so no dir block is mid-write (locked) when the PEER acquires — but the locked block here is the ACQUIRING node's OWN xfsaild flush, so this needs the acquiring node to quiesce its dir-block xfsaild writeback before/at reload.
3. Stop laundering b_mxfs_dir_epoch on non-coherent reads so tenure_stale reliably fires.

### Existing write-side guards (already in tree): b_mxfs_relepoch (sess50, skip flushing stale block at writeback), b_mxfs_dir_wr_counted (sess40, release completion barrier), b_mxfs_dir_incarn ABA skip (sess40). None fully close it.
See [[sess52-ROOT-node-addname-stale-epoch-datablock-readgate-miss]] [[sess5-ccloop-MILESTONE-2tcp-17of17-forceblock1-salvage]] [[sess40-FIX-dirblock-ABA-writeback-skip-build-B9F9326E]]
