---
name: sess44-KEPT-fix-1842-dir-epoch-propagation-partial-next-is-fastpath-serve
description: sess44 KEPT FIX (build EBBC5A82): dlm.c:1842 downgrade→promote dispatch now calls dg_grant_ex + send_grant (was the only 1-of-4 promote_waiters site…
metadata:
  type: project
---

## sess44 — KEPT a real DLM fix; identified the remaining dominant gap

### KEPT FIX (build EBBC5A82, KEEPER-SAFE — 2/tcp dir_reuse PASS, no regression):
`dlm/dlm.c` ~1842 (the lock DOWNGRADE → promote_waiters dispatch) was the ONLY one of the 4 promote_waiters dispatch sites (1684, 1842, 2065, 3364) that dispatched promoted grants with ONLY `pending_signal_resource` — NO `dg_grant_ex` (so EX grants promoted there got dir_epoch=0) and NO `send_grant` to a remote grantee (stranding it). Fixed to match the other 3: call dg_grant_ex for EX (stamp dir_epoch+handoff) and send_grant to remote owners. This is a genuine correctness fix (epoch-propagation consistency); keep it.

### RESULT: 8/tcp dir_reuse run1 PASS, run2 FAIL → only MARGINAL improvement. P68-EVDECIDE after the fix: cur_mep=0 ×9853 vs cur_mep=15 ×2147. So the downgrade-promote path was NOT the dominant grant path — most storm-dir EX grants STILL get dir_epoch=0 through another path.

### THE DOMINANT cur_mep=0 SOURCE = the FAST-PATH MHT serve (sess61's exact target): under inode_mht_ms=300 batching, a node holding CACHED EX serves modify after modify LOCALLY without any DLM grant round-trip, so its lock's `dir_epoch` is never refreshed from the master's advancing epoch (master computes epoch→515 via P64 but the fast-path server reads its own stale lk->dir_epoch=0). The slow-path that would refresh cached_grant_gen/dir_epoch (xfs_mxfs_dlm.c:15006, gated `mode > i_dlm_mode`) never runs on a cache hit. So ALL the acquire-side epoch/grant_gen eviction stays inert during the rapid fast-path create wave.

### NEXT (RULE 4) — implement sess61 step 4b (the fast-path grant_gen/epoch check), NOW with the propagation bug fixed so the signal is finally reliable: in the dir-EX FAST-PATH serve in mxfs_dlm_ilock_begin (find the cached-mode-EX serve / `dir_ex_verify_held` region), query live `g = mxfs_v5_dlm_inode_grant_gen(dlm, ino)` (and/or mxfs_v5_dlm_inode_dir_epoch); if it differs from `i_dlm_cached_grant_gen` (or the cached epoch), a peer took the lock since we cached → force the slow path / set i_dlm_stale + reload + bump i_dlm_dir_gen + run the acquire-evict BEFORE serving the RMW; then refresh the cached value. MHT preserved: within one continuous tenure grant_gen/epoch don't change → fast path keeps serving (no dlm_fairness starvation). CAVEATS: (1) sess35 trap — refresh at tenure START not mid-tenure (don't force-evict this tenure's own un-landed creates → readdir=0); (2) the residual wall (sess43/44: the stale base is often the node's own dirty/in-AIL buffer + possible insert-time leaf-conversion loss) may still need work after the signal is live; (3) a rare P-DOUBLEGRANT (1×) still fired — investigate the DG_SHADOW_N=512 shadow-slot eviction under 800-inode/round load.

### STATE: keeper EBBC5A82 (2/tcp dir_reuse PASS; 1842 fix kept; sess44 levers default-off; P44 probe gated). 8/tcp dir_reuse still ~33% fail. Criterion NOT met. [[sess44-NEXT-fix-dir-epoch-on-local-promotion-grant-dlm-704]] [[sess61-THE-FIX-implement-sess10-grant-gen-faststale-check]] [[sess44-ROOT-epoch-and-grantgen-both-zero-for-reused-dir-inode-coherency-signal-dead]]
