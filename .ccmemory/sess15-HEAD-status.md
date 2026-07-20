---
name: sess15-HEAD-status
description: sess15 HEAD: 2/tcp = 15/16 PASS, crash_consistency SOLE blocker. ROOT PROVEN = DIR-STALE-SKIP: a reused-incarnation in-AIL undestaged dir buffer used…
metadata:
  type: project
---

## HEAD sess15. Criterion `./run.sh 2 tcp` 100% = NOT met. Marker NOT written. Build B623A0F0C480A4CE558A34F deployed both nodes (test1/test2), tcp.

## STATUS: FULL `./run.sh 2 tcp` = 15/16 PASS. SOLE FAIL = **crash_consistency (nodes_pass=1/2)**. All others PASS (cache_coherency, strong_consistency, posix_multi, mmap, zero_silent_loss, dlm_fairness, dlm_membership, scaling_curve, dlm_scaling, rsync_paired, fence_during_write, fault_netpartition, soak, tcp_dlm_scaling, precond). crash_consistency PASSES standalone, FAILS in-suite (flaky, ~50%).

## ROOT — PROVEN this session (RULE 4, fully instrumented):
crash_consistency = both nodes write 50 O_SYNC files+50 .md5 into ONE shared dir → block-format dir → a test2 dirent (whole-block-contiguous range) durably LOST (gone from LUN). test1 is the clobberer.
**The lost-update fires via DIR-STALE-SKIP** (xfs/libxfs/xfs_da_btree.c ~3258, sess39 detector). Exact buffer state at the loss (dirwr=1 repro, build B623A0F0):
`DIR-STALE-SKIP ino=2517 blk=0 buf_gen=0 inode_gen=4 dirty=0 in_ail=1 pin=0 delwri=0 li_empty=1 has_bli=1 bli_flags=0x2`
= a cached dir DATA block that is STALE (buf_gen=0 != inode_gen=4) but is IN-AIL with `mxfs_dir_buf_is_undestaged()`=true (b_mxfs_logged_seq != b_mxfs_written_seq), so the read-path invalidation hook's guard `(!in_ail || !undestaged)` PRESERVES it → the create/RMW reads this stale base → writes back → drops the peer's whole block of dirents.

## WHY it is a REUSE bug (PIVOTAL, proven by 2×2 probe matrix):
loss reproduces ONLY with inode/daddr REUSE **AND** tight back-to-back timing (no settle gap):
- cc_blockdir_probe (rm+recreate=REUSE, no gap) → LOSES <15 iter.
- cc_nogap_noreuse (unique dirs, NO rm, no gap) → 40/40 CLEAN.
- cc_minrepro (no reuse, per-iter dmesg-clear GAP) → 40/40 CLEAN.
- cc_reuse_scoped (REUSE + gap) → 30/30 CLEAN (the ~1s gap lets the stale in-AIL buffer destage/settle, masking it).
ino 2517 is REUSED across iters. The DIR-STALE-SKIP buffer holds a PREVIOUS incarnation's committed-unwritten (in-AIL, logged≠written) content at the reused daddr; the new incarnation RMWs from it. crash_consistency fails IN-SUITE because earlier tests (rsync_paired/dlm_scaling/etc.) free+realloc the inodes/daddrs .crash_consistency reuses, leaving stale in-AIL buffers on the peer.

## REFUTED this session (do NOT re-chase): master DLM double-grant (P-DOUBLEGRANT=0, single-clock detector); mastership flap (P-STALEMASTER=0); MHT window (inode_mht_ms=0 still loses); sf_merge (sf_merge=0 still loses; the "format oscillation" in P105 was inode-reuse, not real); clean-cached-stale-block (new dir_force_evict=1 forcing unconditional clean-block evict — STILL loses, the stale buffer is in-AIL undestaged not clean); CROSS-INODE daddr reuse / ABA owner-mismatch (new P15-ABA-DIRINVAL owner check fired 0× — owner always MATCHES = SAME-inode-number reuse, not cross-inode). The "format oscillation"/sf→block double-alloc framings were inode-reuse artifacts.

## FIX DIRECTION (next session): a PREVIOUS-incarnation in-AIL "undestaged" dir buffer at a reused inode#/daddr is wrongly preserved as "our committed work" by the sess43/sess133 in-AIL guard. Need to invalidate it. Candidates: (1) on inode FREE / dir-block free (xfs_ifree / xfs_bunmapi / xfs_trans_binval path), reliably xfs_buf_stale the dir's data-block buffers so they cannot survive into the next incarnation (the freeing node locally; peers via a RELIABLE signal — eviction-ring is lossy on TCP, mxfs_v5_dlm_note_inode_freed). (2) at the read hook, treat buf_gen=0 (evicted/never-current-stamped) in-AIL buffers as NOT-current → safe to refresh (a current-incarnation committed buffer would carry the current gen, not 0). (3) reset b_mxfs_logged_seq/written_seq on buffer reuse so a stale incarnation's seqs don't make undestaged=true. GPT-5.5 consult (RULE 5, done): recommended per-epoch authoritative reload + full inode-metadata-closure drain on release + assert no dirty/in-AIL dir buffer at NL; and ABA-detect at read (owner — refuted here since same-inode). VERIFY each fix with FULL `./run.sh 2 tcp` (crash_consistency must pass in-suite, ideally 3×).

## ASSETS (build B623A0F0, KEEP — full suite still 15/16, no regression): mxfs_dir_block_names() dir2-block dirent walker; P-RELFLUSH dumps names (de-ratelimited, dirwr-gated — consider re-ratelimiting); P-H14 dumps incore SF names; module_param dir_force_evict (default 1); P15-ABA-DIRINVAL owner check (harmless, 0×). Probes (tests/): cc_blockdir_probe.sh (FAST reuse repro <15 iter), cc_minrepro.sh/cc_nogap_noreuse.sh/cc_reuse_scoped.sh (2×2 matrix), cc_dirgrow_probe.sh (P34C), cc_doublegrant_probe.sh, cc_inode_timeline.sh. Always `tests/reboot_cluster.sh 2` if a node wedges; test2 rmmod-busy is recurrent (use `umount -l` + rmmod retry loop or virsh reboot). [[sess15-PIVOTAL-loss-requires-inode-daddr-reuse]] [[sess15-crash-consistency-is-sole-blocker-divergent-block]] [[sess15-decisive-negatives-blockdir-loss]]
