---
name: sess5-ccloop-HANDOFF-state-fixes-and-next
description: sess5(run6614) FINAL HANDOFF build 9762C6C6: 2/tcp=17/17 SOLID (cache_coherency FIXED after ~50 sessions, verified 3x). 4/8 blocked by dir_reuse lost…
metadata:
  type: project
---

## sess5 (run 6614) FINAL HANDOFF — criterion NOT met, marker NOT written. Build **9762C6C6**.

### VERIFIED DELIVERABLE (tree default force_block=1):
- **2/tcp = 17/17 ✓ SOLID (verified 3×).** The ~50-session cache_coherency deterministic-shutdown blocker is FIXED. Also fixes the sess67 force_block=1 regression (cache_coherency now passes at BOTH fb settings).
- 4/tcp: cache_coherency 4/4 ✓. Blocker = dir_reuse_coherency ~70% flaky (readdir-undercount lost-update) + its shutdown face cascades to fault_netpartition/fence/tcp_dlm_scaling.
- 8/tcp + 1/tcp: unrun.

### KEPT FIXES (build 9762C6C6, all verified not to regress 2/tcp):
1. **Undestaged cold-read SALVAGE** (xfs_da_btree.c) — THE breakthrough, fixes cache_coherency. [[sess5-ccloop-FIX-undestaged-coldread-salvage-BREAKTHROUGH]]
2. **soak dump_stack gate** (pal/linux/xfs_buf.c) — P-DIRSTALE/P-DIRFREE behind mxfs_instr_enabled.
3. **deferred-stale** (b_mxfs_stale_pending) — acquire-reload locked-skip; fires 500×, marginal, no regression.
4. **query-max dir_epoch** (dlm.c:2509 returns MAX across local mirrors) — marginal, harmless.
(Fix A keep-guard tweak + P-DBLALLOC-AGF probe also in tree, harmless.)

### dir_reuse ROOT — PROVEN (see [[sess5-ccloop-ROOT-dirreuse-master-epoch-zero-disables-gates]]):
Node-addname RMW's a stale cached dir-DATA block (100/400 dirents durably clobbered). ALL epoch-gated coherence guards are INERT because `mxfs_v5_dlm_inode_dir_epoch(131)` intermittently returns 0 — the master SENDS correct monotonic epochs (P51→190, never 0) but the LOCAL granted-lock mirror's stored dir_epoch lags/zeros (P44=0/8/22). P29-DATAWRITE CLOBBER=0 (NOT a stale-write; it's a stale-READ base). P2-EPOCHPLACE 314× unestablished(master_ep=0).

### GPT-5.5 ROADMAP for next session (RULE-5 consult done this session; see [[sess5-ccloop-FIX-relepoch-evict-gpt-design]] for full text):
**Core: gate dir stale-base correctness on the RELIABLE LOCAL `ip->i_dlm_epoch`/`b_mxfs_relepoch`, NOT the broken master dir_epoch.** But 2 prerequisites (learned by REGRESSION this session):
- **relepoch-evict at the EVICT site REGRESSED to 3/8** — the modify-evict already force-evicts all clean/destaged blocks; the ONLY blocks it keeps are undestaged-in-AIL (this-node CURRENT work), and relepoch (stamp lags after modify) false-flagged those → evicting LOST our dirents. REVERTED. So do NOT relepoch-evict.
- **FIRST fix the b_mxfs_relepoch STAMP reliability** (GPT Step 3): stamp `b_mxfs_relepoch = i_dlm_epoch` on every local MODIFY under EX (xfs_dir2_data_log_entry), not just on read (currently only stamped at xfs_da_btree.c:4009/4075 read + dlm.c:22456). Then relepoch<i_dlm_epoch reliably means "not touched this tenure".
- **THEN enforce at the READ/addname site** (GPT Step 4/5), preserving the undestaged keep-guard: force a coherent re-read of a stale (relepoch<i_dlm_epoch) DESTAGED block before the addname free-slot search. Must cover the txn-held-buffer path (xfs_trans_read_buf) and run even under owned_ex. Add a last-chance guard in xfs_dir2_node_addname before bestfree scan; if any placement buffer (data/leaf/free) is stale → restart addname.
- Also fix DLM propagation (canonical res->dir_epoch, refresh ALL mirrors + fast-path re-adopt, not first-match-break) — secondary.

### REFUTED this session (don't repeat): broad owned_ex read-salvage (2/6), relepoch-EVICT (3/8), dir_tenure_evict+stale_bypass (4/5), force_coherent+tenure_evict (3/6), deferred-stale alone (6/8), query-max alone (~4/6).

### FAST repro: `scripts/drc_reliability.sh 4 8`. cache_coherency@fb1 now deterministic PASS.
See [[sess5-ccloop-ROOT-dirreuse-master-epoch-zero-disables-gates]] [[sess5-ccloop-FIX-relepoch-evict-gpt-design]] [[sess5-ccloop-MILESTONE-2tcp-17of17-forceblock1-salvage]]
