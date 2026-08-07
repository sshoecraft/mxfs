---
name: ccloop-c7ee71c6-sess161-foreign-replay-frontier-MAPPED-release-sites
description: sess161: D-FOREIGN-REPLAY frontier fully mapped. Item1 (stuck-notify) DONE sess151. Item2 wiring plan + release-site inventory; evict is THE gap. No…
metadata:
  type: project
tags: [mxfs, sess161, foreign-replay, authority, begin-release, release-sites, frontier]
---

# sess161 — D-FOREIGN-REPLAY-UNGATED-IMAGES frontier map (no code changes yet)

Build unchanged: 0.11.457 sv E44F37271ED23D708AFD84C. Ledger 28 open / 17 critical. Tasks: #1 done, #2 in_progress (mapping complete, implementation not started), #3 pending.

## Ledger `next` item 1 — DONE
`mxfs_v5_dlm_set_dlm_stuck_notify` wired sess151 (xfs_mxfs_dlm.c:43131, queue-work → xfs_force_shutdown(SHUTDOWN_META_IO_ERROR); cancel_work_sync at both teardown sites per sess135 UAF ruling). Teardown exercised clean in sess160 census ×4. Mark item 1 done when editing the ledger entry.

## Item 2 — begin_release_locked wiring (sess104 ruling) — THE MAP

**Current state:** `mxfs_inode_authority_begin_release_locked` xfs_mxfs_dlm.c:955, `__maybe_unused`, ZERO callers (relbegin counter only incremented there). Backstop = `mxfs_dlmtr_rec` ~1139: revokes on ANY mode-lowering with auth != NONE. Comment at ~1136 "primary revoke still happens at release-begin" is STALE/FALSE (sess104 measured backstop=2486 / release_begin=0).

**Release-site inventory (all in xfs/xfs_mxfs_dlm.c):**
- `mxfs_dlm_bast_process` NL store **line 15527** — inside i_dlm_lock section (opens ~14923) AFTER all abort checks (holders/pin re-check P15/FIX-A, orphan_live/strand FIX-H/H2/H3, cleanup-flavor guards). Order on this path: drain → RELFLUSH set → p_rel_gen capture → i_dlm_lock{aborts; **NL store = backstop revoke fires**; epoch++} → publish_unpublished → `mxfs_v5_dlm_inode_unlock_open` (~17535 routed→iclus_unlock / ~17772 plain, gen-aware). Mode-lowering PRECEDES peer-visible publication ⇒ revoke-before-publication already HOLDS here; hook goes immediately before the 15527 store (after aborts = release committed).
- bast_process unmounting short-circuit **13969**: NL store then unlock — same order, hook before store.
- **`mxfs_dlm_evict` (fn at 31226) = THE GAP**: releases at 31537 (`mxfs_iclus_unlock`), 31542 (`unlock_free` when MXFS_IF_FREE_COMMITTED), 31596 (plain unlock) with i_dlm_mode STILL EX/PR — no mode store, backstop never fires, cert dies only at destroy_inode. Directly violates sess96 D3/RCU "clear at reclaim/eviction BEGIN". Also a retain-PR arm (P6R-RETAIN, mxfs_evict_retain_pr) keeps the grant — that arm must NOT revoke... actually PR is non-write: cert should already be non-DURABLE unless downgrade raced. Hook at evict's release decision point under i_dlm_lock before ANY of the three calls.
- noino paths (19171 `mxfs_dlm_noino_bast_work_fn`, 19335 `mxfs_dlm_bast_notify` inline): no in-core ip ⇒ no cert; P-NOINO-LIVE-SKIP guards re-instantiation. No hook needed.
- 18215 `mxfs_iclus_pi_reconcile`: requires mode==NL (cert already revoked). 26502 P-ICLUS-CONV + 26534 mirror: explicit revoke already wired (routing = tenure transition, sess96 gap iii).
- ICLUSTER: `mxfs_iclus_unlock` (44350) / `mxfs_iclus_bast_notify` (44495) publish `mxfs_iclus_disk_release` ONLY when `!mxfs_iclus_covered_active` (no live routed inode) — per-inode demotes precede via `mxfs_iclus_fan_out`, so per-inode hooks cover routed certs. `ic->auth_epoch=0` on successful release.
- **UNRESOLVED**: the EX→PR demote-in-place arm not yet located (only NL store found in bast_process; 16308 is a comment). Next: `grep -n "i_dlm_mode = MXFS_LOCK_PR"` and check whether bast_process demotes in place or always full-releases; a PR store from EX also fires the backstop.

**Wiring plan (per sess104 ruling):**
1. begin_release_locked before the 15527 + 13969 NL stores and at evict's decision point.
2. Backstop rework in mxfs_dlmtr_rec: state==RELEASING at lowering ⇒ expected cleanup, transition to NONE silently (new counter, e.g. relclean); state==DURABLE_EX/UNPUBLISHED_EX at lowering ⇒ LATE-REVOKE invariant violation: counter + ratelimited warn (pick unused probe id — check P244/P246/P247 free) + defensive revoke.
3. Assertions at publication points (before unlock_open/unlock_free/iclus_disk_release): WARN-count if DURABLE cert remains.
4. Measure on rig: relbegin_n>0, late-revoke≈0, RELEASING bucket appears in P239/P240; board lap for RULE-0.

## Item 3 — consumer half status (for the consult)
- Producer+capture+serialize COMPLETE: v2 trailer `mxfs_blf_authority_v2` (XFS_BLF_MXFS_AUTHORITY) in every buf log record; capture at first protected dirty (capseq machinery, buf_item.c ~1060-1130; serialize ~1380-1430 with INCOMPLETE/BLFTCHG/MIXED demotion). Mints rig-verified sess110 (P241 clean 32/32).
- Replay gate xfs_log_recover.c:~2390 still BLANKET-SKIPS BUF/DQUOT/QUOTAOFF/ICREATE under `xlog_is_mxfs_untrusted_replay` — its "until records carry authority tokens" comment is now FALSE (they do). Torn-recovery (sess41) mitigated by ATOMIC-SKIP whole-transaction taint (0.11.349).
- Remaining: step 4 (recovery descriptor + IMAGE_REPLAY_DONE + victim-slot freeze — OVERLAPS ledger #7 D-FOREIGN-SLICE-INTENTS-ABANDONED next) and step 5 (gate swap: exact-match {resource,epoch} vs fenced slot ex_grant_epoch, per-transaction atomicity). sess107 blockers 8/9/10 open: 8=mixed-version (=ledger #14), 9=first-install-EX audit, 10=replayer binds (resource,epoch) tuple.
- NOTE `compiled-foreign-replay-authority-tokens` is stale past sess48 (predates sess81-110 v2 redesign) — its "RESUME at 3b" is superseded.

## Housekeeping still due
- Memory compaction (200 unfolded, threshold 20) deferred AGAIN — run compile-memories next session.
- dlm docs/.md refresh deferred (sess159 touched dlm_caw.c/v5_mount.c); pal awareness doc flagged stale by SessionStart hook.
