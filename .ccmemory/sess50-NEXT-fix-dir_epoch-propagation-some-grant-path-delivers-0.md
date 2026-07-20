---
name: sess50-NEXT-fix-dir_epoch-propagation-some-grant-path-delivers-0
description: sess50(ccloop) PINPOINT: the monotonic handoff epoch under-fires because some grant path delivers dir_epoch=0 to the grantee's lk->dir_epoch. Fix the…
metadata:
  type: project
---

## sess50 (ccloop) — the FIX is dir_epoch PROPAGATION (the level-triggered handoff epoch reaches the grantee as 0)

### Chain of reasoning (this session, all evidence-backed):
1. dir_reuse loss = a fast-path dir-EX serve modifies a STALE base (P51-HANDOFF-UNDERFIRE PROVEN: hgg jumps 862→1071 with ho=FALSE).
2. The one-shot handoff bit `ho` under-fires because dg_grant_ex sets `handoff = (last_owner != owner)` and overwrites last_owner every grant (dlm.c:2753) → only catches the IMMEDIATELY-prior grant.
3. The RELIABLE replacement is the MONOTONIC `dg_shadow.epoch` (dlm.c:2744, P64-MASTER-HANDOFF), surfaced as the grantee's `i_dlm_dir_valid_epoch` (queried via mxfs_dlm_grant_dir_epoch = local `lk->dir_epoch`, dlm.c:2482).
4. **BUT sess44 already PROVED it's broken**: P44-GRANTDIREPOCH (dlm.c:2514, ino 131) showed the modifying node's local lock carries `epoch=0` (cur_mep=0 dominant) EVEN THOUGH the master computes epoch→515 (P64). So the monotonic epoch is NOT reaching the grantee's local lock → the level-triggered refresh can never fire → under-fire persists → stale-base modify → clobber.

### THE BUG: some grant-dispatch path delivers dir_epoch=0 to the grantee's lk->dir_epoch.
- REMOTE grant via promote-waiters (dlm.c:1714-1727): CORRECT — dg_grant_ex(..., &wk->dir_epoch) at 1719, send_grant(... wk->dir_epoch) at 1727; receive path stores it (dlm.c:3269/3283).
- **SELF-grant (master grants itself), dlm.c:1720-1722**: `pending_signal_resource(...)` is called instead of send_grant — it does NOT store wk->dir_epoch into the master's OWN local lk->dir_epoch. So a master-self EX holder's lk->dir_epoch stays 0. (master_self=1 modifying node → epoch 0.)
- OTHER send_grant paths to AUDIT: dlm.c:1334 (local insert: `newlk->handoff = dg_grant_ex(...)` — does it capture/store epoch_out into newlk->dir_epoch? line 1334 only assigns handoff), 1866, 2099, and the inline grant in process_remote_request. Any that pass a literal 0 / don't wire dg_grant_ex's epoch_out → grantee gets 0.
- ALSO: the FAST-PATH serve itself (xfs_mxfs_dlm.c:14373) never updates i_dlm_dir_valid_epoch from the master epoch even when it IS available — and the consuming read gate (xfs_da_btree.c:3959) only fires if valid_epoch advanced.

### NEXT (RULE 4, exact steps):
1. Build with P44-GRANTDIREPOCH always-on (already gated to ino 131, cap 4000) + add the grant-PATH id to it. Run 8/tcp dir_reuse. Identify WHICH grant path delivers epoch=0 to the modifying node's local lock (self-grant vs a specific send_grant vs missing fast-path update).
2. FIX every grant path to store dg_grant_ex's computed epoch_out into the grantee/holder's lk->dir_epoch (monotonic max). Especially the self-grant path (1720): store wk->dir_epoch into the local mirror lock.
3. Then ensure the fast-path dir-EX serve (xfs_mxfs_dlm.c:14373) compares mxfs_v5_dlm_inode_dir_epoch vs i_dlm_dir_valid_epoch and arms dir_ex_stale_refresh + bumps i_dlm_dir_gen if it advanced (level-triggered; cannot under-fire like ho, cannot over-fire like raw grant_gen — only cross-node handoffs advance dg_shadow.epoch).
4. Verify: P44 shows cur_mep == master epoch at the modifying node; P51-HANDOFF-UNDERFIRE still fires but now the epoch-refresh catches it; dir_reuse 8/tcp PASS. Then reliability loop (tests/drc_reliability_relepoch.sh — repurpose) 8+ consecutive clean PASS. Then confirm 1/2/4 tcp still pass. Then the FULL ./run.sh {1,2,4,8} tcp suite 100%.

### Build at relay: 5362F91E (baseline-equiv + P51 detector + P50/relepoch dormant instrumentation). Cluster healthy. Marker NOT written.
See [[sess50-ROOT-handoff-underfire-last_owner-immediate-prior-only-use-dg_shadow-epoch]] [[sess50-FINAL-all-coherency-refuted-prime-suspect-dlm-serialization-hole]]. NOTE this connects to [[sess16run-INPROGRESS-master-epoch-check-done-stamps-remain]] (the master-epoch swap was left partially done — the stamps/propagation were never finished).</body>
