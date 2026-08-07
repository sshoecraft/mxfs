---
name: ccloop-c7ee71c6-sess165-shadow-eval-plumbing-LANDED-evaluator-core-NEXT
description: sess165: step-5 shadow-eval plumbing LANDED (caw read, v5 wrappers, xlog victim slot, finish hooks). NOT BUILT YET. Next: evaluator core in xfs_log_r…
metadata:
  type: project
tags: [mxfs, sess165, foreign-replay, step5-shadow, victim-manifest, P273]
---

# sess165 — shadow-evaluator plumbing landed; evaluator core is the next edit

## LANDED THIS SESSION (uncompiled — `make modules` NOT yet run, version NOT bumped)

1. **dlm/dlm_caw.h + dlm_caw.c**: `mxfs_dlm_caw_victim_manifest_read(ctx, resource, victim_slot, &holds_ex, &ex_grant_epoch)` — consumer-only, placed directly after the sess110 do-not-reintroduce comment with the contra-sess110 contract (reads FENCED victim's frozen manifest; holds_ex = victim bit in holders_ex|holders_pw; epoch meaningful only when bit set; -ENOENT = no slot; never feeds a producer). Uses find_slot like read_generation.
2. **dlm/v5_mount.h + v5_mount.c**: `mxfs_v5_dlm_victim_ag_manifest_read(ctx, agno, vslot, ...)`, `mxfs_v5_dlm_victim_inode_manifest_read(ctx, ino, vslot, ...)` (make_ag_resource / make_inode_resource; -ENODEV if !dlm_caw), and `mxfs_v5_dlm_victim_recovery_read(ctx, slot, &stage, &victim_epoch, &victim_node)` wrapping mxfs_disklock_recovery_read (-ENOENT no descriptor, -EPROTO uninterpretable). Declared after the sess110 deleted-accessor comment block (~v5_mount.h:384).
3. **xfs/xfs_log_priv.h**: struct xlog += `uint32_t l_mxfs_victim_slot` + `struct mxfs_shadow_eval *l_mxfs_shadow_eval`; `#define MXFS_XLOG_VICTIM_NONE ((uint32_t)-1)`; forward decl `struct mxfs_shadow_eval`; prototype `void mxfs_shadow_eval_finish(struct xlog *log)` next to xlog_recover_cancel.
4. **xfs/xfs_log.c**: sentinel init in xlog_alloc_log (after l_curr_cycle=1); adopted site sets `l_mxfs_victim_slot = mp->m_mxfs_node_slot` (with why-comment: pass-2 claim ⇒ predecessor purged ⇒ expected all not-held; would_apply there = unpurged-manifest finding); foreign site sets `= dead_slot` + calls `mxfs_shadow_eval_finish(shadow)` before xlog_dealloc_log; adopted finish in xfs_log_mount_finish after xfs_buftarg_drain before clear_bit(RECOVERY_NEEDED); idempotent backstop call in xlog_dealloc_log before the m_log-NULL check. finish must be IDEMPOTENT (frees + NULLs; second call no-op) — foreign path calls it then dealloc calls it again.

## NOT YET WRITTEN — the evaluator core in xfs/xfs_log_recover.c

Everything goes near mxfs_report_replay_authority (~2170). xfs_log_recover.c already includes ../dlm/v5_mount.h and reaches ctx via `log->l_mp->m_mxfs_dlm` (pattern at :3247).

**struct mxfs_shadow_eval** (kzalloc GFP_KERNEL at first tokened txn; single-threaded pass2, no locking):
- capability: `int desc_rc; uint16_t desc_stage; uint64_t desc_victim_epoch; uint32_t desc_victim_node;` — filled ONCE at init via mxfs_v5_dlm_victim_recovery_read(mp->m_mxfs_dlm, log->l_mxfs_victim_slot,...). capability OK ⇔ desc_rc==0 && stage==MXFS_RECOV_STAGE_FENCED (=2, dlm/disklock.h:321; stage>=3 means purge may have begun; include disklock.h? — v5_mount.h may already pull it, else pass raw stage and compare against a v5-exported constant... simplest: `#include "../dlm/disklock.h"` works, v5_mount.c does it). Emit one `P273-SHADOW-CAP` xfs_notice at init: victim_slot, desc_rc, stage, victim_epoch, victim_node, capability yes/no.
- manifest cache: 64 entries `{uint8_t kind /*1=AG,3=INODE reuse MXFS_AUTH_CLASS_**/; int rc; bool holds; uint64_t resource; uint64_t epoch;}` linear scan; on miss+full: direct read each time + `cache_spill` counter.
- counters (uint64_t): buf_items, untagged, malformed, v1_not_evidence, classless, class_sb, class_unsupported (ICLUS), status_not_valid, foreign_owner, wrong_incarnation, manifest_err, not_held, stale_epoch, would_apply; txn_total, txn_all_apply, txn_mixed, txn_none, txn_nonbuf_taint; cache_spill.

**Per-token classify** (inside mxfs_report_replay_authority's existing loop, after parse; also bump untagged/malformed aggregates at their existing continue sites):
- v1 → v1_not_evidence (sess82 ruling: v1 NEVER evidence).
- v2 class NONE → classless; SB → class_sb (producer stamps SB with NO resource/epoch by design — pal/linux/xfs_buf_item.c:938 UNPROVEN, cannot match); ICLUS → class_unsupported.
- class AG/INODE: status != MXFS_AUTH_ST_VALID (=1) → status_not_valid; else av_owner_slot != l_mxfs_victim_slot → foreign_owner; else (capability&&av_owner_epoch != desc_victim_epoch) → wrong_incarnation; else manifest lookup (AG: victim_ag_manifest_read(av_resource as agno); INODE: victim_inode_manifest_read): rc<0&&!=-ENOENT → manifest_err; -ENOENT or !holds → not_held; epoch != av_grant_epoch → stale_epoch; == → **would_apply**.
- Per-txn rollup (report fn is per-txn): txn_all_apply = n_buf>0 && every LI_BUF landed would_apply && no LI_DQUOT/QUOTAOFF/ICREATE in txn (count those in the same loop — currently non-BUF items `continue` before n_buf++; count them as nonbuf_taint). all-skip → txn_none; else txn_mixed. Add per-txn would counts to the existing P227-TOKENSUM line (new fields wapply/wskip) so per-txn evidence is greppable.
- `mxfs_shadow_eval_finish(log)`: if !l_mxfs_shadow_eval return; emit `P273-SHADOW-EVAL` xfs_notice with ALL counters + victim_slot + capability; kfree; NULL the pointer.

**Key invariants argued this session**: verdict stability — would_apply/stale_epoch only arise on victim-held resources, which are quarantine-frozen (fenced node can't CAS; purge ordered post-IMAGES_REPLAYED; peers refused EX on dead-bit resources). not_held on live-peer resources is stable regardless of concurrent epoch churn. ex_grant_epoch left stale on release ⇒ only valid under the holder bit — the check does exactly that. Replay pass2 is single-threaded. GFP_NOFS inside caw read.

**After core lands**: bump VERSION 0.11.459→0.11.460, `make modules`, RULE-5 consult on the diff BEFORE deploy (sess163-style review; the design was ratified sess163 (D) + sess164 refinement, so consult is on the implementation), then rig: force a node kill at 32/caw and read P273-SHADOW-CAP/-EVAL on the electee; assert would_apply>0 with capability=yes on a real foreign replay and backstop conservation unchanged (authority_stats_sweep.sh). Also owed: ledger #7 next-field refresh (item-1 text stale — descriptor/freeze LANDED per sess164 audit), compaction backlog 196.

P273 chosen because P272 is the highest in use. NO module knob — report-only, always on for untrusted replay (same as P227).
