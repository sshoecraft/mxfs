---
name: ccloop-c7ee71c6-sess162-begin-release-WIRED-0.11.458-built
description: sess162: D-FOREIGN-REPLAY item 2 WIRED+BUILT (0.11.458 sv 5C83BE4B). 7 begin_release hooks, P246 backstop classify, 7 pub-checks. NOT deployed/consul…
metadata:
  type: project
tags: [mxfs, sess162, foreign-replay, authority, begin-release, P246]
---

# sess162 — begin_release wiring LANDED (built, NOT deployed, NOT consulted)

Build: **0.11.458 sv 5C83BE4B598C252C546DF3B** — builds clean (`make modules`; the two -Wcomment warns at 33637/34057 are pre-existing prose, not mine). Ledger unchanged: 28 open / 17 critical.

## What landed (all in xfs/xfs_mxfs_dlm.c; VERSION bumped 457→458)

**Corrected sess161's map first:** evict DOES lower the mode — at fn-end (pre-edit 31618), AFTER the wire releases (31537/31542/31596): publish-then-revoke ORDERING violation, not a missing revoke. Also found: P72-ORPHAN-FORCEREL (pre-edit 19632) published via `force_release_self` before its NL store — same class. Exhaustive store audit: NO EX→PR demote-in-place exists anywhere; every lowering is a full drop to NL; `= g`/`= g2`/`= mode` stores (28040/28343/28810/29074/29858) are all raise-only (`if (i_dlm_mode < g)`). 1453/1467 are the by-number visibility nudge (no in-core ip, no cert).

**7 begin_release hooks** (call `mxfs_inode_authority_begin_release_locked`, `__maybe_unused` dropped):
1+2. unmount short-circuit both arms (DLM-alive + no-DLM), before their NL stores.
3. main bast_process store — after ALL abort arms ("release committed" point), before store + publication.
4. P72 claim section — under i_dlm_lock at `claimed = true`, BEFORE the lock drop → before force_release_self publication (gen bump blocks stale installs in the window; state=DEMOTING + demoter claimed blocks new acquires).
5. evict unpub-slotless arm (brief spin_lock; deliberate UNPUBLISHED_EX give-up).
6. **evict pre-release (THE ordering fix)**: top of the `if (i_dlm_mode != NL)` release block, brief spin_lock, AFTER P237 last-chance publish + sess83/sess85 durability arms (those may dirty/destage under the live cert — placement nuance for the consult vs sess96 "clear at eviction BEGIN" wording). P6R-RETAIN arm: no-op by construction (clean wire-PR carries no proving cert; no EX→PR path exists).
7. single→multi transition sweep (pre-edit 41875), idle cached-grant invalidation.

**Deliberately NOT hooked (design decision — consult should ratify):** the 3 phantom/anomaly arms P108-REACQUIRE, P-TCPEX-REACQ, phantom-undo (pre-edit 26757/26827/27843). There a proving cert dropped = wire lost a grant the cache believed in → the new late-revoke warn IS the authority-side signal.

**Backstop rework in mxfs_dlmtr_rec:** lowering with state==RELEASING → `mxfs_auth_relclean_n++`, silent (protocol finishing). Lowering with PROVING state → `mxfs_auth_backstop_n++` + ratelimited **P246-AUTH-LATE-REVOKE** + revoke. Chokepoint comment rewritten (the old "primary revoke still happens at release-begin" stale claim is now TRUE).

**7 publication-point tripwires** (`mxfs_inode_authority_check_published`, lockless READ_ONCE, **P246-AUTH-PUB-LIVE**, `mxfs_auth_publive_n`): unmount unlock arm, P72 pre-force_release, evict×3 (iclus/unlock_free/plain — retain arm excluded), bast noanchor region, bast anchored region.

**Stats:** /proc authority file "relinquish" block now prints release_clean + pub_live.

## Next steps (tasks #2, #3 created)
1. **Task #2 — bundled RULE-5 consult** (NOT yet done): (a) review this wiring incl. no-hook-on-anomaly-sites + evict placement-after-P237 nuance; (b) consumer-half sequencing: step 4 (recovery descriptor + IMAGE_REPLAY_DONE + victim freeze; overlaps ledger #7) vs step 5 (gate swap to exact {resource,epoch}).
2. **Task #3 — deploy+measure**: 32/caw board lap; assert release_begin>0, release_clean>0, backstop≈0 (P246-LATE-REVOKE only from phantom arms if any), pub_live==0; RULE-0 timings; then tick ledger items 1+2 in D-FOREIGN-REPLAY next-field.
3. Housekeeping still due: memory compaction (201 unfolded), dlm+pal awareness doc refresh.
