---
name: sess64-GPT-design-per-dir-monotonic-epoch-replaces-handoff
description: sess64 GPT-5.5 design: replace edge-triggered handoff bit with level-triggered per-dir monotonic EPOCH on every grant. Fixes 80% under-fire + both mo…
metadata:
  type: project
---

## sess64 — dir_reuse 4/tcp: ROOT proven + GPT-5.5 architectural fix (per-dir monotonic epoch)

### This session's PROVEN evidence (RULE 4)
- attempt-3 (publish-side SYNC flush gated on handoff) REFUTED: 2/24, no improvement. Reverted.
- DIRID probe: loss is INTRA-INODE (all peers resolve same dirino on a failing round). Confirmed.
- dg_shadow 512-slot table-overflow hypothesis REFUTED (P64-SHADOW-EVICT fired 0× — table never fills).
- **DECISIVE: master computes ~270 handoffs but grantees act on only ~58 (P64-MASTER-HANDOFF total ~270 vs reload-side P63-HANDOFF total ~58) = ~80% of handoffs LOST.** The edge-triggered handoff bit + one-shot acted_gen consumption + EX-only + fast-path-bypass loses most cross-node dir-base-change signals.
- ALL point-fix detectors CLEAN on failing runs: P106-STALE-EX=0 (no in-core-EX-while-slot-lost), P-SF-DURABLE-FAIL=0 (release fence sess97 ALWAYS achieves durable+unpinned before handoff), P58-SELFSKIP-STALE-DIR=0, P-DOUBLEGRANT=0, no shutdown. So the release side is durable; the gap is reliable ACQUIRER refresh + READER invalidation.
- TWO failure modes: Mode A = single-dirent loss (EX RMW of stale cached dir DATA block; usually nodeX_f1). Mode B = whole-node frozen view (e.g. 300/400 stuck rounds 18-21 — a PR reader latched stale cached dir xfs_bufs; drop_caches does NOT free xfs_buf metadata cache, only pagecache/dentries, so stale dir blocks survive across drop_caches+rm-rf).
- Root cause: DIR coherence rides the ASYNC/LOSSY disklock heartbeat evict-ring (28-deep, once-per-HB, cacheable-read-prone) for the PR/read path + gap-fill; the reliable handoff bit is EX-only and edge-triggered.

### GPT-5.5 FIX (RULE 5 consult, design saved) — replace handoff bit with LEVEL-TRIGGERED per-dir EPOCH
1. **Master**: per dir INODE resource keep monotonic `dir_epoch` + `last_writer`. Increment `dir_epoch` ONLY after a DIRTY EX holder completes the existing release fence (durable). Batch all mutations in one EX tenure = one epoch bump. (Build on dg_shadow: add epoch field next to last_owner.)
2. **Grant carries epoch**: every LOCK_GRANTED (PR or EX, remote or local/self-mastered) carries `dir_epoch`+`last_writer`. (Reuse the handoff wire field; widen to u64 epoch.)
3. **Client per inode**: `i_dlm_dir_valid_epoch`. On EVERY grant-authorization point (slow PR grant, slow EX grant, local grant, conversion, fast-path revalidate): `if (grant_epoch > valid_epoch) { invalidate CLEAN dir xfs_bufs; if EX reload_inode disk-superset; valid_epoch = grant_epoch; }`. MONOTONIC compare — missed intermediate epochs are fine (10→20 in one refresh). This is the cure for the 80% under-fire: no one-shot consumption, no edge to miss. NO xfs_log_force on acquire (release fence already made disk durable).
4. **Buffer-level epoch stamp**: stamp dir DATA/LEAF/NODE bufs `b_mxfs_dir_epoch=valid_epoch` when read under grant; in xfs_da_read_buf, if `buf_epoch < valid_epoch` invalidate-if-clean + reread. Coherency domain = whole dir block set, not just DATA.
5. **PR readers must be REAL DLM holders + reliably BAST'd to NL before a peer EX grant**; on PR recall: block new readdir, drain active readdir, invalidate clean dir bufs, drop PR, ACK. Pure cache inval, no log force. (Fixes Mode B.)
6. Fast path legal ONLY if `held_mode>=req && !recall_pending && valid_epoch==granted_epoch`.
7. Disk heartbeat DIR_MODIFY ring → downgrade to best-effort HINT, not correctness (keep for CAW).
8. Detectors: assert no dir buf used with buf_epoch<valid_epoch; no stale dirty/pinned dir buf without local EX.

### Why perf-safe (RULE 0): the SYNC log_force stays on the RELEASE side (async kworker, already there); the acquirer does only epoch-compare + cache-invalidate + on-demand FUA reread. Prior acquire-side SYNC log_force REFUTED (barrier desync). 

### Build state: repo at 5E78DEE0 + 2 always-on probes added to dlm.c (P64-SHADOW-EVICT, P64-MASTER-HANDOFF) = build A5554054. REVERT those probes (or keep, harmless ratelimited) before final. 1/tcp 16/16, 2/tcp 17/17 still valid (don't regress). NEXT: implement epoch (start with EX-acquire epoch compare to kill Mode A, then PR-reader recall for Mode B). See [[sess63-residual-root-crossnode-gen-divergence-reused-dir]] [[sess63-handoff-signal-works-1of24-residual-writeside-block0]].</body>
