---
name: ccloop-c7ee71c6-sess167-shadow-eval-fixlist-LANDED-and-RIG-MEASURED
description: sess167: sess166 fix list fully landed; shadow evaluator RIG-MEASURED live at 32/caw (capable=1, csum exact, 7/7 would_apply). Ledger #1+#7 refreshed.
metadata:
  type: project
tags: [mxfs, sess167, foreign-replay, P273, shadow-evaluator, rig-measured]
---

# sess167 — shadow-evaluator fix list landed and the first live measurement banked

## Landed (0.11.460, srcversion 460F52B862C3192D09EBAA9, DEPLOYED to all 32)

All sess166 RULE-5 fix-list items applied to `xfs/xfs_log_recover.c` as one edit set:
1. **uncapable_match terminal (the blocker)**: a full manifest match under `!capable` no longer lands `would_apply` — new counter; makes would_apply incarnation-proven AND foreign-replay-only by construction.
3. Cache → open-addressed hash table: kvzalloc GFP_NOFS (vmalloc fallback OK on 6.x), 8192 slots / 13-bit `hash_64(resource ^ kind<<56)`, linear probe, insert-only, kind==0=empty (CLASS_NONE never cached), fill cap 6144 then direct+`uncached_reads`; tbl==NULL alloc-fail = all direct+counted; kvfree in finish.
4. rc ladder reorder: `-ENOENT→not_held; rc!=0→manifest_err; !holds→not_held` (positive-rc hole closed).
5. AG binding check: eval_token now takes blfp; `(u64)xfs_daddr_to_agno(mp, blf_blkno) != av_resource → resource_mismatch` (u64 compare, no truncation). INODE trusts producer labeling (comment); no rtdev.
6. Single-summary lifecycle: report fn does `if (!se && victim_slot!=NONE) l_mxfs_shadow_missed++`; finish() returns early on victim_slot==NONE, emits `state=unevaluated missed_txns=N`/`state=no_txns` when se==NULL, ALWAYS clears victim_slot at end (idempotence for both paths); full summary carries `missed_txns=`. Verified: no other victim_slot consumers exist; all 3 finish sites are lifecycle-terminal.
7. Rollup split: `txn_buf_ok_taint_blocked` separated from mixed; nonbuf_taint stays as overlapping count; total = all_apply+taint_blocked+mixed+none.
8. Conservation `csum=` printed beside `buf=` (15 terminals summed).
9. Header comment: first-failure terminals, would-AUTHORIZE (LSN gate still downstream), txn denominator, exploratory-upper-bound-until-#15 warning.

Also: `#include <linux/hash.h>`; `blfp` hoisted before parse in report fn (deref only after PARSE_OK); `tests/foreign_replay_ab.sh` step-6 harvest now greps + prints `P273-SHADOW` lines.

## THE MEASUREMENT (first live sample, sess167)

`MXFS_FORCE_PREP=1 ./run.sh 32 caw prep_cluster` (73s clean) then `tests/foreign_replay_ab.sh 32 7 0`:
- Kill test7 (slot 22); electee test1 replayed at t+113s, "complete".
- **P273-SHADOW-CAP: desc_rc=0 stage=2(FENCED) capable=1** — descriptor/freeze machinery (sess164 audit: recovery_complete v5_mount.c ~2897-3180, freeze disklock.c ~1919/2017) proven end-to-end on a REAL kill.
- **P273-SHADOW-EVAL: buf=7 csum=7** (conservation EXACT), untagged=0 malformed=0 v1=0, **WOULD_APPLY=7** (all v2, slot+incarnation+manifest-hold+epoch matched), **txn=2 all_apply=2** — both blanket-ATOMIC-SKIPped txns (P227_ATOMIC_SKIP=2) fully authorized: the containment residual quantified for the first time. missed_txns=0 uncached=0 resmis=0 uncap_match=0. Exactly one CAP + one EVAL line.
- Visibility 40/40 dirs, 40/40 files, 40/40 sizes (no user-visible loss this run).
- `tests/authority_stats_sweep.sh 32`: all 31 survivors on 460F52..., P246/P247/P248 = 0/0/0 everywhere, phantom/backstop/publive = 0, revoke=release_begin=release_clean=30 conserved. test7 NOMOD (restarted un-prepped by design).

## Ledger updates
- #1 D-FOREIGN-REPLAY-UNGATED-IMAGES next: step-4/5 progress + measurement recorded; gate swap blocked on (a) more samples, (b) D-EX-GRANT-EPOCH-NOT-UNIQUE-TENURE-ID (epoch per-tenure uniqueness) FIRST, (c) sess163 hazards design.
- #7 D-FOREIGN-SLICE-INTENTS-ABANDONED next: item 1 DONE (sess164 audit + sess167 live proof); item 3 images-half LANDED (P273), intent/done inventory half still owed; 2/4/5/6 unchanged.

## Still unexercised (GPT sess166 forced-test menu, for the enforcement phase)
descriptor -ENOENT/-EPROTO/stage!=FENCED arms, uncapable-match path (needs adopted replay or degraded descriptor), spill >fill-cap, alloc failure, adopted-after-reacquisition, error-exit ⇒ exactly-one-summary. The adopted-mount arm (rejoin of a dead node's slot) is the natural next sample: expect capable=0 + uncap_match either 0 (purge worked) or >0 (unpurged-manifest finding).

## Rig state
Cluster formed 32/caw on 460F52B862C3192D09EBAA9; test7 booted but NOT prepped — run `MXFS_FORCE_PREP=1 ./run.sh 32 caw prep_cluster` before the next board.
