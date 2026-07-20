---
name: sess42-CONFIRMED-stale-WRITE-not-base-grantevict-plus-wseq-both-insufficient
description: sess42(ccloop) A/B DECISIVE: dir_grant_evict=1 (fresh read base) + dir_wseq_at_completion=1 BOTH ON still fails 8/tcp → the readdir=799 loss is a sta…
metadata:
  type: project
---

## sess42 (ccloop) — DECISIVE A/B that narrows the fix to the WRITE side. Pairs with [[sess42-PROVEN-799-is-stalebase-clobber-not-insert-loss-gpt-tenure-fence-plan]] and [[sess42-SMOKINGGUN-cached-EX-stalegrant-demote-discards-uncheckpointed-dir-work]].

### Result: with BOTH correctness levers ON — `dir_grant_evict=1` (acquire-side: force-evict + FUA-re-read any dir block whose b_mxfs_grant_gen != i_dlm_cached_grant_gen, i.e. read under an older grant = fresh RMW base) AND `dir_wseq_at_completion=1` (written_seq stamped at I/O completion not submit) — the 8/tcp dir_reuse loss STILL reproduces (iter 2/6: 7 entries lost node4_f37.md5/f48/f49, node5_f31/f32/f42, node8_f25.md5; earlier single-entry variant also). Build 7E1EFD90.

### Interpretation (re-confirms sess36 independently): the loss is a **stale WRITE, not a stale base**.
- grant_evict guarantees the RMW node reads the CURRENT (fresh) base → so the node that does the RMW is NOT reading stale. Yet an entry is still durably dropped.
- ⇒ a node durably WRITES a dir-block image that is MISSING a just-added entry, AFTER the entry was added (within ONE incarnation, cross-node). The write itself carries a stale/regressed image.
- This is consistent with the dland write-completion ring (creator wrote block to count N-with-entry, a peer wrote it to count N+k WITHOUT the entry) AND with merge-inert (dko=0: at the clobbering write the LUN lacks the entry).

### So the grant_gen machinery (sess10/61, IS implemented: i_dlm_cached_grant_gen set on slow-path acquire @14574/13924; b_mxfs_grant_gen stamped at coherent read in xfs_da_btree.c:3871/4008; mxfs_v5_dlm_inode_grant_gen in v5_mount.c) covers the READ/base side but NOT the stale WRITE. The dir-EX FAST-PATH serve (xfs_mxfs_dlm.c ~13535-13760) increments holders + serves the cached EX, and only LOCAL/shortform dirs get a coherent disk-compare (sf_disk_check); leaf/btree (fmt=2/3 — the 800-entry storm dir) get only the grant-evict/refresh which is acquire-side. The sess10 plan 4b "fast-path serve → if grant_gen changed force SLOW path (full re-acquire+drain+reload) BEFORE serving" is NOT wired for leaf/btree dirs — BUT it's a base/serialization fix, and the loss is a stale WRITE, so it likely won't fix it alone either (and risks RULE-0 timeout: ~800 handoffs × slow-path re-acquire under the storm; sess43 proved per-handoff FUA-refresh blows the 300s budget).

### NEXT (write-side, RULE 4): instrument the dir-DATA-block WRITE chokepoint (pal/linux/xfs_buf.c xfs_buf_submit / __xfs_buf_ioend, or xfs_da_btree write) to catch the stale write IN THE ACT:
- At write submit of a dir3 data block for the storm dir, compare the in-core image's dirent set to the LAST-COMPLETED write's set for the SAME daddr+incarn (a per-daddr high-water name-set, NOT count — counts rise during the clobber). If this write DROPS a name a prior write of this daddr+incarn HAD → log P-STALEWRITE name/daddr/comm/grant_gen. (sess22 recommended exactly this "content-superset, not count" probe; never fully built.)
- Likely mechanisms to then test: (a) xfsaild destaging an OLD buffer instance for a reused daddr (buffer-cache ABA WITHIN one incarnation — sess40's incarn-keyed skip only covers CROSS-incarnation; extend it to a grant_gen-keyed write SUPPRESSION: if bp->b_mxfs_grant_gen < i_dlm_cached_grant_gen at write submit, the image predates the current tenure's fresh read → SUPPRESS/emulate-clean-ioend so the stale image never lands); (b) the addname RMW on the fresh base dropping an entry during freescan/compaction/leaf-rebalance.
- Then the architectural backstop = GPT's per-tenure checkpoint fence (flush all tenure-dirty dir metadata home before any peer can acquire EX), which makes the stale-write window unreachable.

### Build state: 7E1EFD90 = keeper FUNCTIONALLY (all fix params — dir_wseq_at_completion, dir_grant_evict, dir_write_merge, dir_release_flush_all_done — default OFF; only added storm-dir-scoped ratelimited probes P13-LADD/P42-RELDUR/P42-VACUOUS-DURABLE). Cluster clean (0 procs). Criterion NOT met.</body>
