---
name: ccloop-c7ee71c6-sess166-evaluator-core-LANDED-gpt-review-fixlist-PENDING
description: sess166: shadow-eval core LANDED (0.11.460, builds clean, NOT deployed). RULE-5 review returned 8 findings; fix list PENDING — apply before any rig r…
metadata:
  type: project
tags: [mxfs, sess166, foreign-replay, step5-shadow, P273, rule5-review]
---

# sess166 — evaluator core landed; GPT implementation review returned a fix list that MUST land before the rig

## LANDED this session (0.11.460, srcversion 1EDC4F4ADC532E6998CF91B, builds clean, NOT deployed)

In `xfs/xfs_log_recover.c` (after `mxfs_blf_parse_authority`, before the sess48 report comment):
- `struct mxfs_shadow_eval` (capability desc fields + capable flag; 64-entry linear manifest cache; 14 per-token + 5 per-txn + spill counters).
- `mxfs_shadow_eval_get(log)` — lazy kzalloc GFP_NOFS at first report call; reads recovery descriptor via `mxfs_v5_dlm_victim_recovery_read`; `capable = (rc==0 && stage==MXFS_RECOV_STAGE_FENCED)`; emits one `P273-SHADOW-CAP` notice.
- `mxfs_shadow_manifest_lookup` — cache incl. errors; AG/INODE wrapper dispatch; out-params preset false/0 before call (covers untouched-on-error wrapper paths).
- `mxfs_shadow_eval_token` — verdict ladder v1→class(SB/NONE/ICLUS out)→status!=VALID→owner_slot→(capable&&epoch)→manifest(err/-ENOENT/!holds/epoch≠)→would_apply.
- Wired into `mxfs_report_replay_authority`: se get at entry, nonbuf_taint (DQUOT/QUOTAOFF/ICREATE) at the non-BUF continue, untagged/malformed/buf_items increments, `n_wapply`, per-txn rollup (total/all_apply/mixed/none/nonbuf_taint), TOKENSUM gained `wapply=/wskip=` (-1 when !se).
- `mxfs_shadow_eval_finish` now emits `P273-SHADOW-EVAL` with all counters before kfree.
- `#include "../dlm/disklock.h"` added (stage constants). xfs_log.c: explicit `l_mxfs_shadow_eval=NULL` + `l_mxfs_shadow_missed=0` init beside the sentinel. xfs_log_priv.h: `l_mxfs_shadow_missed` field added (declared, NOT yet used anywhere — wiring is fix-list item 6).

Verified along the way: find_slot returns **-ENOENT** on no-match; `read_slot` inherits the standard CAS-protected corrupt-slot **repair** (can write; same path every CAW reader uses — acceptable, note in comment); P273 free; VERSION bumped 459→460.

## RULE-5 review (gpt-5.6-sol, this session) — verdict: fix before deploy. THE FIX LIST (agreed disposition)

1. **BLOCKER — capable must gate the positive verdict.** Today !capable skips the incarnation check and a manifest match still lands would_apply (contaminated headline; adopted replay pools into it via epoch collision, cf. open defect D-EX-GRANT-EPOCH-NOT-UNIQUE-TENURE-ID). Fix: keep full ladder, but the FINAL match under !capable lands a NEW terminal `uncapable_match` instead of would_apply (preserves adopted not_held/stale distribution AND the unpurged-manifest signal; adopted⇒capable=false always since a FENCED-stage descriptor would have blocked the pass-2 claim ⇒ would_apply becomes foreign-only automatically).
2. GPT's NULL-deref finding is **already handled** in the real code (every se access guarded — it reviewed prose). Its real sub-point stands: alloc-fail-then-success = silent partial count. Fix via item 6.
3. **Cache → open-addressing hash table**: kvzalloc'd, 8192 slots (order fields u64 resource, u64 epoch, int rc, u8 kind, bool holds ≈24B ⇒ ~192KB), hash_64(resource ^ kind<<56), linear probe, insert-only, kind==0=empty, fill-cap ~3/4 then direct-read; rename cache_spill→`uncached_reads`; tbl==NULL (alloc fail) ⇒ all direct+counted. kvfree in finish.
4. **rc ladder reorder** (positive-rc hole): `rc==-ENOENT→not_held; rc!=0→manifest_err; !holds→not_held`.
5. **AG-class binding check**: pass blfp into eval_token; `xfs_daddr_to_agno(mp, blf_blkno) != av_resource → resource_mismatch` (new terminal) right after class selection. INODE class: no cheap reverse map — trusts producer labeling, same trust the live apply path places in its own locking (comment). RT-dev caveat noted (rig has no rtdev).
6. **Exactly one summary per untrusted log**: report fn does `if (!se && victim_slot!=NONE) l_mxfs_shadow_missed++`. finish(): victim_slot==NONE→return; se==NULL→emit state line (`state=unevaluated missed_txns=N` or `state=no_txns`); ALWAYS clear `l_mxfs_victim_slot=NONE` at the end (this is what makes finish idempotent for BOTH paths — the se-NULL check alone would re-emit the state line on the dealloc backstop call). Full summary gains `missed_txns=`.
7. **Rollup split**: `txn_buf_ok_taint_blocked` (all bufs authorized but nonbuf taint) separated from txn_mixed.
8. **Conservation sum** in summary: csum = untagged+malformed+v1+classless+sb+unsup+badst+fowner+winc+resource_mismatch+uncapable_match+manerr+notheld+staleep+would_apply; print beside buf= (analysis asserts equal; catches counting bugs).
9. **Comment/semantics notes to add**: counters are FIRST-FAILURE terminals (ordering masks later layers — not prevalence); would_apply = would-AUTHORIZE (downstream LSN gates still apply — GPT naming point, keep field name, document); txn_total denominator = txns with buf or taint items only; measurement is exploratory upper bound until #15 (epoch tenure id) lands — must NOT alone justify the enforcement gate.

GPT's forced-test menu for later verification is in the sess166 transcript (descriptor -ENOENT/-EPROTO/stage2/stage3, uncapable-match-must-not-authorize, >64-resource spill, alloc failure, adopted-after-reacquisition, error exits ⇒ exactly one summary).

## Next session order
1) Apply fix list to xfs_log_recover.c (items 1,3,4,5,6,7,8,9 — one coherent edit set), rebuild, keep 0.11.460 (not yet deployed anywhere).
2) Then rig measure per sess165 plan: deploy 32/caw, force node kill, read P273-SHADOW-CAP/-EVAL on electee, assert conservation + backstop sweep unchanged (authority_stats_sweep.sh).
3) Ledger #7 next-field refresh STILL OWED (structure inspected this session: tests/criteria/OPEN_DEFECTS.json = dict{_comment, defects}; refresh text drafted: item1 DONE per sess164 audit [recovery_complete v5_mount.c ~2897-3180, freeze-gate disklock.c ~1919/2017, cohort ~3185], item3 images-half LANDED sess165-166 = the shadow evaluator, items 2/4/5/6 unchanged).
4) Compaction backlog 197 STILL OWED (deferred two sessions running).
