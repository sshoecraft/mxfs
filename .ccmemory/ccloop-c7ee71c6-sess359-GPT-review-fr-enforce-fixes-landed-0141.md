---
name: ccloop-c7ee71c6-sess359-GPT-review-fr-enforce-fixes-landed-0141
description: sess359: RULE-5 review of sess358 #1 landing (knob=0 GO / knob=1 NO-GO) + ALL code fixes landed 0.14.1 sv BDEB75D40B5BE7C21C82EF6 — needs make clean…
metadata:
  type: project
---

# sess359 — RULE-5 review of the #1 token-enforcement landing + fixes

## GPT ruling (full text in sess359 transcript, task kvz9vl8u2)
- **knob=0 32-node board baseline: GO** (subject to normal regression validation).
- **knob=1 campaign: NO-GO as sess358-landed**; stop-ships + obligations below.

## Code fixes LANDED this session → 0.14.1 sv BDEB75D40B5BE7C21C82EF6 (compile check only, NOT deployed; incremental build — MUST `make clean && make modules` before deploy per multi-file .c+.h feedback)
1. **Q3 STOP-SHIP — attempt-local enforcement mode**: new `xlog->l_mxfs_fr_enforce_mode`, set ONLY by `mxfs_fr_enforce_preflight` (the single OFF→ARMED point, before xlog_recover); evaluator's `se->enforce_cfg` now inherits it instead of resampling globals; `mxfs_fr_enforce_configured()` deleted; `mxfs_fr_enforcement_active()` dropped the per-txn proto_admitted re-read (pinned at preflight).
2. **Q5 STOP-SHIP — config serialization**: `DEFINE_MUTEX(mxfs_fr_cfg_lock)` (exported, extern in xfs_mxfs_dlm.h); enforce setter validates+writes under it; NEW guarded setters for `fua_disable` (rejects →1 while knob armed && !target_cache_protected, -EBUSY) and `target_cache_protected` (rejects →0 while knob armed && fua_disable). release_proof_enforce is 0444 = immutable, no guard needed. Armed-knob-with-invalid-prereqs now ABORTS retryably at preflight (P227-FR-ENFORCE-CFG-ABORT) — never silent enforcement-off.
3. **Proto demote explicit**: preflight logs P227-FR-ENFORCE-PROTO-DEMOTE and keeps blanket refusal for the attempt when !m_mxfs_proto_admitted (defined, attributable; abort would never terminate on a genuinely mixed fleet).
4. **Q6 allowlist STOP-SHIP**: admissibility nonbuf_taint is now a STRICT ALLOWLIST — only XFS_LI_INODE and the intent/done set (EFI/EFD, RUI..CUD_RT 0x1240-0x124f which covers ATTRI/ATTRD/XMI/XMD/RT) don't taint; dquot/quotaoff/icreate/iunlink/unknown all taint. Pass2 `mxfs_tainted` blanket scan deliberately UNCHANGED (changing it would alter knob=0 behavior).
5. **Q1 SHOULD-FIX**: one-shot inject consume + shape-4 torn-countdown arming moved AFTER successful preflight in mxfs_xlog_recover_foreign_slice.
6. **Setter 0/1 only**: kstrtobool in enforce setter.

## Verified (no code needed)
- **Errno retry contract**: both call sites (xfs_mxfs_dlm.c 46816 reap loop, 48035 mount barrier) key retry-vs-terminal on `fv.reason`, not errno — reason NONE re-arms reap / leaves slot in the cut. Preflight aborts are genuinely retryable end-to-end.
- **Inode-gate STOP-SHIP resolved as non-issue**: the di_changecount gate (xfs_inode_item_recover.c ~413-432) is a STALENESS skip (disk_cc >= log_cc → disk same-or-newer → correct redo no-op, upstream-LSN-skip analog), NOT an authority refusal; no refusal path exists in inode pass2 that needs terminal accounting. grep confirmed zero refusal/untagged_skips arms in that file.
- **snlocal immutability (Q2 condition)**: l_mxfs_untagged_authorized set once at shadow alloc before replay, never set on adopted logs.
- Evaluator created by preflight is freed on all paths (mxfs_shadow_eval_finish at xfs_log.c:1111 + dealloc backstop).

## OUTSTANDING knob=1 campaign proof obligations (GPT Q4 — record before any knob=1 rig work; these are TEST/PROOF items, not code)
1. Epoch anti-ABA: every release AND same-owner reacquisition bumps epoch (no reuse).
2. Token records the epoch at image-generation time, not reconstructed later.
3. Physical-buffer authority domain: an enforceable class's grant must serialize EVERY byte of the logged buffer image — inode-CLUSTER buffers (multiple inodes per buf) are the flagged aliasing risk; must be demonstrated per enforceable buffer class.
4. In-slice replay order preserved; WAL tail rules can't drop a later same-epoch update while an older one replays.
5. Recovery must not release/regrant the resource before admitted replay for that epoch completes.
6. LSN-gate replacement test matrix: old+newer same-epoch image on disk; release/regrant with old image in log; same-owner reacquire; shared-buffer aliasing; multi-resource txn.

## Next
1. `make clean && make modules` (deploy build), deploy 32/caw, knob=0 board baseline = zero behavior change (compare return codes/verdicts/skip counters/adopted/snlocal/inject shapes per GPT).
2. Then sess357 ruling step 2 onward (F2 coherence-only admission exists), defects #3/#4 (grant-freeze closure, umount escalation) before knob=1.
