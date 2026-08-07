---
name: ccloop-c7ee71c6-sess169-edge-mint-HALF-LANDED-tree-does-not-build
description: sess169: edge-mint helper REWRITTEN but TREE DOES NOT BUILD — 5 call sites + knob decl + _orig removal pending. Exact edit list inside. Compaction: 3…
metadata:
  type: project
tags: [mxfs, sess169, epoch-tenure, ex-grant-epoch, half-landed, do-not-deploy]
---

# sess169 — edge-triggered mint HALF-LANDED. ⚠️ TREE DOES NOT BUILD. Do not deploy, do not run boards from this tree until fixed.

Ruling: see `ccloop-c7ee71c6-sess169-GPT-ruling-edge-mint-tenure-token` (option (a) approved + hardening list + gate blockers). Implement queue there. THIS note = exact resume state.

## LANDED in dlm/dlm_caw.c (this session)
`caw_grant_epoch_update` REWRITTEN (~line 1102-1215 now): new signature
`(struct mxfs_caw_lock_slot *s, const struct mxfs_caw_lock_slot *cur, uint8_t grantee_slot, uint8_t mode)`.
- prior = node_held_mode(cur, 1ULL<<grantee_slot) guarded by grantee_slot < MXFS_MAX_NODES.
- Mint arm (!can_write(prior)): prev = s->ex_grant_epoch (NOT cur — claim path's caw_claim_inherit_epoch resets namespace on different-resource recycle and must be respected); caw_inject_take(&mxfs_caw_inject_gep_wrap) forces prev=~0ULL + logs P274-GEPWRAP-INJECT.
- CONT-ZERO arm (prior write-capable && cur->ex_grant_epoch==0): keep 0 fail-closed, log P274-GEP-CONT-ZERO at ERR (minting would conceal continuity loss).
- Preserve arm: s->ex_grant_epoch = cur->ex_grant_epoch (explicit copy, defensive), log P274-GEP-PRESERVE at WARN. Rare by construction (XFS never uses PW).
- last_ex_slot/dir_epoch rules UNCHANGED (per ruling Q3).

## PENDING — the tree DOES NOT COMPILE until these land (next session's FIRST job)
1. **Knob declaration** missing: add after mxfs_caw_inject_wait_expire block (~line 424, inside the kernel-only #ifdef with the other inject knobs):
   `static int mxfs_caw_inject_gep_wrap; module_param_named(caw_inject_gep_wrap, mxfs_caw_inject_gep_wrap, int, 0644); MODULE_PARM_DESC(... "TEST ONLY: next N tenure-token mints treat prior ex_grant_epoch as ~0 (wrap); asserts zero-skip (consumable; 0=off)")`.
   User-mode: caw_inject_take(k) macro drops arg so symbol unreferenced — matches sess154 convention, no user-mode decl needed.
2. **5 call sites** still pass OLD 3-arg form — insert `cur_slot,` as 2nd arg at ALL of: 6176-ish wait_for_grant self-promote; 6928-ish claim; 7789-ish compat-add; 8571-ish direct handoff (inside release CAS; cur_slot in scope, see caw_handoff_nominee_ok(cur_slot,...) guard); 9840-ish convert-upgrade. (Line numbers shifted ~+75 by the helper rewrite — grep `caw_grant_epoch_update(` for current positions.)
3. **Remove dead `mxfs_dlm_caw_flush_held_to_disk_orig`** (~12877+75 onward, static __maybe_unused, zero callers verified sess169; contains 2 old-signature calls at old-12977/13005 which will not compile). Ruling says convert-or-remove; DECISION: remove entirely, keep a short comment noting sess25 v0.3.86 disabled single→multi disk promotion (OR-bug) and the original lived pre-0.11.461 (git history has it). Live caw_flush_held_body (drops locks, no promotion) is UNAFFECTED.
4. Then: rev VERSION (0.11.460 → 0.11.461 per patch-rev rule), `make modules > /tmp/build.log 2>&1; echo $?` (NEVER pipe-to-grep directly — masks rc), deploy, wrap test, caw_verify PW subtest (both arms: lock(PW)+lock(EX) compat-add vs lock(PW)+convert(EX); NEEDS SACRIFICIAL DEVICE — never the live cluster LUN), board, ledger #15+#1 updates per ruling queue.

## Compaction status (2nd failed attempt imminent)
Agent a7c2bbc69fae5e78c (background, this session) was synthesizing `compiled-samenode-waiter-cancel-campaign` from 21 slugs (sess111-125: the 20 sess168 listed + sess111-GPT-ruling-blocker6-REJECTS-held-table-guard) — it had READ all 21 but NOT yet written the article at relay boundary; it dies with the session. LESSON (2 failures now): run compaction SYNCHRONOUSLY (run_in_background:false) EARLY in a session, agent returns article body as final text, then memory_write it under name `compiled-samenode-waiter-cancel-campaign` citing all 21 slugs as [[wikilinks]]. Do NOT TaskOutput-poll a local_agent (dumps raw JSONL transcript into context — cost this session ~15K tokens).

## Rig state (unchanged this session)
All 32 mounted/formed on 0.11.460 (460F52B), board-ready, do NOT re-prep. No rig commands were run this session.
