---
name: sess50-ROOT-handoff-underfire-last_owner-immediate-prior-only-use-dg_shadow-epoch
description: sess50(ccloop) ROOT PROVEN: dir-EX fast-path serves STALE base because handoff bit under-fires (last_owner tracks only immediate-prior grant). Fix: c…
metadata:
  type: project
---

## sess50 (ccloop 4cb2d0a2) — ROOT of the dir_reuse loss PROVEN: handoff-bit under-fire on the fast-path EX serve

### PROVEN MECHANISM (P51-HANDOFF-UNDERFIRE detector, build 5362F91E, always-on):
On a dir-EX FAST-PATH serve of the storm dir (ino 131), the live per-grant token jumps massively (e.g. `hgg=1071 cached_gg=862` = 209 intervening cross-cluster grants) while the master handoff bit `ho=FALSE` → the fast-path serve does NOT arm the stale-base refresh → the node RMWs/modifies on a base missing peers' adds → count-preserving single-dirent clobber (readdir=799). Fires 45×/run on test1. THIS is the serialization-visibility hole behind the 130-session loss.

### WHY `ho` UNDER-FIRES (the root, dlm.c dg_grant_ex ~2732-2756):
`handoff = (dg_shadow[mine].last_owner != 0 && last_owner != owner)` and `last_owner` is overwritten to `owner` on EVERY grant (line 2753). So `ho` is TRUE only when the IMMEDIATELY-PRECEDING grant was a different node. In a hot burst where this node releases and re-grabs EX repeatedly (interleaved with peers), the grant right before ours is often OURSELF → `ho=FALSE` even though peers modified the dir earlier in the burst. sess63 gated refresh on `ho` (not raw grant_gen) precisely because raw grant_gen over-fires on benign same-node re-grants (resurrected deletes 2/24→16/24) — but `ho` then under-fires the real cross-node case.

### THE RELIABLE SIGNAL ALREADY EXISTS (just not consumed on the fast path):
`dg_shadow[mine].epoch` — a MONOTONIC per-resource counter incremented on EVERY cross-node handoff (dlm.c:2744, logged P64-MASTER-HANDOFF), returned via epoch_out and surfaced as `i_dlm_dir_valid_epoch` (queryable via mxfs_v5_dlm_inode_dir_epoch / dg_shadow_dir_epoch). sess64 designed it as the LEVEL-TRIGGERED fix: a grantee compares the master's current dir_epoch to its cached valid_epoch and refreshes if it advanced — catching handoffs it missed (served fast-path / one-shot `ho` consumed elsewhere). The read gate (xfs_da_btree.c:3959 `b_mxfs_dir_epoch < i_dlm_dir_valid_epoch`) consumes it on READ — but the FAST-PATH dir-EX SERVE (xfs_mxfs_dlm.c:14373-14404) only checks the one-shot `ho`/grant_handoff and does NOT compare the master's monotonic dir_epoch → so a fast-path RMW proceeds on a base whose epoch lags the master.

### THE FIX (RULE 4, implement + test next session):
On the fast-path dir-EX serve (xfs_mxfs_dlm.c ~14373, where `ho`/`hgg` are queried), ALSO query the master's monotonic dir_epoch (mxfs_v5_dlm_inode_dir_epoch). If it EXCEEDS the inode's cached `i_dlm_dir_valid_epoch`, a cross-node handoff occurred since our base was coherent → set `dir_ex_stale_refresh = true` (+ bump i_dlm_dir_gen so the dir-DATA read hook re-reads) and advance i_dlm_dir_valid_epoch. This is LEVEL-triggered (monotonic compare), so it cannot under-fire like `ho` and cannot over-fire like raw grant_gen (benign same-node re-grants do NOT advance dg_shadow.epoch — only cross-node handoffs do, line 2743-2744). MHT/perf preserved (within a same-node tenure the epoch is unchanged → fast path keeps serving). WATCH: do not resurrect deletes — the epoch only advances on a genuine cross-node handoff whose prior tenure was release-drained durable, so a refresh adopts the peer's durable superset, not a stale-disk revert (the sess63 over-fire was raw grant_gen incl. same-node; this is handoff-only).

### Build at relay: 5362F91E = baseline-equivalent (relepoch gates default-OFF) + the P51-HANDOFF-UNDERFIRE detector (pure instrument, always-on ratelimited) + sess50 P50 diagnostics. Safe to bake. dir_reuse 8/tcp still flaky-FAIL.

### Verify FIRST that mxfs_v5_dlm_inode_dir_epoch returns the dg_shadow.epoch reliably for ino 131 on a non-master node (it must be propagated in the grant response — check resp.dir_epoch plumbing). If the epoch is only known on the master, a non-master fast-path serve can't see it without the value being carried in the grant/cached — confirm the grant response carries dir_epoch and the inode caches it.

See [[sess50-FINAL-all-coherency-refuted-prime-suspect-dlm-serialization-hole]] [[sess50-relepoch-writeback-gate-REFUTED-loss-is-at-modify-not-writeback]]. This SUPERSEDES the serialization-hole framing: it is NOT a double-grant (master serializes correctly, MX-DOUBLEGRANT 0×); it is the GRANTEE serving a fast-path cached EX on a base it failed to refresh because the one-shot handoff bit under-fired. The monotonic master epoch is the fix.</body>
