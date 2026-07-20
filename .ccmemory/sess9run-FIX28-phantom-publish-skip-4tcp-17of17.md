---
name: sess9run-FIX28-phantom-publish-skip-4tcp-17of17
description: sess9 MILESTONE build 4353CDBB: 4/tcp FULL SUITE 17/17 (first ever). FIX-28 = deferred-publish skips master-EX claim when FS-layer EX gone (1000+/nod…
metadata:
  type: project
---

# FIX-28 + 4/tcp 17/17 milestone (build 4353CDBB)

## FIX-28 — deferred-publish phantom master-EX claims (P78 probe → guard)
`mxfs_dlm_publish_drain_loop` (xfs_mxfs_dlm.c ~18280) popped unpublished inodes and claimed master EX unconditionally. Suite r4 measured **~1000 claims/node/run with pre_mode != EX** (P78-PUB-PHANTOM): the FS-layer EX was already gone (released/demoted/evicted/reused), so each claim created a master-side ghost EX the FS layer never drives — broken by peers only via the orphan-release path (P135). Ghost holders = grant delays; prime suspect for tds "residual ghosts", dlm_scaling/fault setup-visibility flakes. Guard: skip the claim when pre_mode != EX (the 16057 both-nodes-EX hazard only exists while FS-layer EX is live; a later re-acquire goes slow-path and claims properly). P78-PUB-SKIP logs skips (capped).

## Ladder state (all on clean cycles)
- 4/tcp suite runs this session: r1(1F9B) 14/17 → r2(A5DB) 16/17 → r3(CE3B) 15/17 → r4(ECEB) 16/17 → **r5(4353CDBB) 17/17 FIRST EVER**. r6 repeat launched.
- Fix stack in 4353CDBB (all this session): FIX-26v2 (bast release-abort on mid-drain upgrade grant; CACHED-on-gen-moved), FIX-27 (ilock_begin EDEADLK goto-loop, panic fix), FIX-25-widened (ioend admit under PR), FIX-28 (publish phantom skip), + P9-LFREE / P13-realns / P9-NLEDGE ledgers.
- Residual watch items: dlm_scaling SF-dir setup race (failed r4 3/4: node1's own mkdir dirent lost in concurrent SF mkdir — FIX-28 may cover; recheck), s_remove_count skew (soak WARN flood, hit only r2, ledger armed), the EX→PR-with-pending-conversion origin (P78 family, may be gone with FIX-28).
- NEXT: r6 repeat → 8/tcp (boot test5-8) → 2/tcp → 1/tcp. Criteria = 17/17 at 1/2/4/8.
