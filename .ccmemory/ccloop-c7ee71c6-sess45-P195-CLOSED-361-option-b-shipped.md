---
name: ccloop-c7ee71c6-sess45-P195-CLOSED-361-option-b-shipped
description: sess45: P195 CLOSED (0.11.361, Option B adopt-at-EX-acquire per GPT contract); 11 OPEN of 37; boards green both scales; rig 8/caw on 361
metadata:
  type: project
tags: [ccloop, p195, option-b, fixed-verified, 0.11.361]
---

# sess45 — P195 Option B shipped and verified; 11 OPEN of 37

## D-DIRENT-PUBLISH-STALE-BASE-P195-360 → FIXED AND VERIFIED (0.11.361, 9E90F6E01828836A53CEAD4)

Implemented the full gpt_ruling_sess44 contract. Mechanics (all in
xfs/xfs_mxfs_dlm.c unless noted):

- `i_dlm_base_valid` (xfs_inode.h, next to creator_base_state): explicit
  validity bit for the (valid_epoch, cached_grant_gen) pair. smp_store_release
  publish / smp_load_acquire gate reads.
- Knob `mxfs.dir_adopt_at_acquire` = 1 (module_param, near
  creator_baseline_stamp block ~12500). Helpers `mxfs_dir_base_stamp` /
  `mxfs_dir_base_invalidate` + 6 atomic64 counters printed as P216-B-STATS at
  the P6-DIRPATH dump.
- FAST-PATH GATE (ilock_begin S_ISDIR/EX block, after the epoch_adopt arm):
  sentinel (!valid) and epoch-!= (queried ONLY when hgg==0) arm
  dir_ex_stale_refresh + dir_ex_handoff (post_release=true reload). GEN
  movement is COUNT-ONLY (sess63: gen-only refresh resurrected deletes
  2/24→16/24; release-clear makes the gen leg redundant per the contract's
  UNLESS clause). dirty_here ⇒ P216-B-DIRTY-SKIP fail-closed (never adopt over
  this tenure's own work).
- STAMP only at reload INSTALL-COMPLETE (end of the from_disk-success else,
  after sf-merge/type-rewire), using PRE-read (epoch,gen) captured at the
  dir_grant_epoch site — mid-reload movement leaves stamp behind → re-adopt.
  TCP keeps monotonic-epoch guard. Knob-off arm reproduces pre-fix stamps
  minus the brace bug.
- INVALIDATE at: bast_process release drain (S_ISDIR block with H26 flush,
  BEFORE wire unlock — same-epoch re-grant can never skip a needed adopt),
  reload commit-to-adopt point (aborted install stays invalid), P106 phantom
  bail, inode init (31066 block), reset_inode_for_create AND
  rearm_unpublished (reuse funnels NEVER reset the sess28 quadruple before —
  knob-gated resets added; leaked valid_epoch also used to block the creator
  stamp for reused dirs).
- CREATOR SUBORDINATION: _apply now stamps through the helper whenever the
  knob is on (P210 prints state=2; deterministically proven live at site 4
  slow-path publish AND site 3 drain via hand probe mkdir + cross-node ls).
- dir_slow_skip requires established baseline. P34J bail counts
  mxfs_b_p34j_defer (level-held retry).
- SIX missing-braces bugs fixed (valid_incarn stamped unconditionally):
  xfs_mxfs_dlm.c 7409/7433 evict-syncs + old 23097 reload stamp,
  xfs_da_btree.c:3801, xfs_dir2_data.c:2238, xfs_dir2_node.c:2090,
  xfs_dir2_leaf.c:1200. Compiler confirmed via -Wmisleading-indentation.
- P195 probe now prints bvalid.

## Verification (all on 361)
- 32/caw: 4 fresh dirent_publish PASS; board green (26/27; only open_defects
  policy row red); 24 BOARD-AGED dirent_publish loops PASS (historical rate
  ~1/8 predicted ~3 hits, observed 0); sf_mkdir_storm 60r/32n PASS all rounds.
- 8/caw: full board green (same policy exception).
- Fleet: P195=0, stale_base_mutations=0 everywhere, P32E=0 post-storm ring,
  0 oops. Gate: ONE arm in the whole storm — reason=2 BACKWARD epoch reset
  (valid_epoch=9 fe=0): the exact wrap/reset case the ruled != exists for.
  12 dirty-skips, all one inode fe=0/hgg=0 (no cross-node history, nothing to
  adopt — fail-closed behaving).
- Pace: fio 34s, cache_coherency 29s, dlm_scaling 23s, sustained_load
  per_op=174ms — at/below the 317 healthy record. No regression.

## Also this session
- crash_consistency FAIL in-board once (NO_TERMINAL_RECORD=32, 90s wall) then
  standalone PASS 19s — appended as recurrence evidence to open
  D-CRASH-CONSISTENCY-32-NOTERMINAL-354 (pre-existing, intermittent in-board).

## Rig state
8/caw on 0.11.361, all mounted, marker current. 32-node prep needed before
32-scale work.

## Next queue (11 OPEN)
criticals: CACHE-COHERENCY-UV-COUNT-MISS-2332; INODE-CLUSTER-PUBLISH-WITHOUT-
AUTHORITY; FOREIGN-REPLAY-UNGATED-IMAGES (architectural certified replay);
CROSSNODE-OPEN-UNLINK-DATA-LOSS (C9-tcp impl; blueprint in
...-C9-tcp-open-tracking-gpt-design; tcp rig UNWIRED — needs host LUN + VM
XML). high: DIRVIEW-NONCONVERGE-SESS25. major: 2x pace;
CRASH-CONSISTENCY-32-NOTERMINAL-354. minor: MATRIX-UNMEASURED (tcp column
blocked on rig); RELOAD-FREED-ADOPT-BOGUS-IMODE (keep sweeping post-death
tests). unknown: AGI-UNLINKED-CROSSNODE (aged repro).
