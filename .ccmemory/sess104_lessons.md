---
name: sess104_lessons
description: sess104 — ABA inode-reuse root FIXED (build 736ECD00): criterion 2/4→3/4, 604s wedge gone. Residual: intermittent whole-node rename loss, COHOLD=0 +…
metadata:
  type: project
---

# sess104 (2026-06-06, ccloop run 29df431e) — build `736ECD00` (KEEP, deployed all 4)

Continues sess103. MAJOR root-cause advance: the dominant dir lost-update was an ABA bug. Criterion
**2/4 → 3/4**, the 604s EX-timeout wedge/shutdown cascade is GONE.

## KEPT FIXES THIS SESSION
1. **84AC92ED**: wired `mxfs_dlm_dir_modify_refresh` into `xfs_rename` (both src_dp+target_dp,
   before xfs_dir_rename_children/exchange) and `xfs_create` (after dp ILOCK_EXCL acquire).
2. **736ECD00 — ABA inode-reuse fix (Gemini RULE-5 consult, PROVEN 40→1/2 then 3/4)**:
   XFS dir DATA blocks are cached by PHYSICAL daddr, NOT by inode. When a prior test frees inodes
   and a new test REUSES the numbers+blocks, peers retain the PREVIOUS incarnation's dir blocks at
   the same daddrs with XBF_DONE set (owner==ino verifier passes). The `gen==0` short-circuits in
   modify_refresh + the eviction-ring DIR_MODIFY consumer treated a fresh dir as "nothing to go
   stale" — FALSE under reuse; and i_dlm_dir_gen collides across incarnations (old 1 == new 1).
   FIX: added inode field `i_dlm_dir_evicted_incarn` (init 0 at xfs_mxfs_dlm.c ~4153). In BOTH
   modify_refresh AND consumer_refresh: dropped the gen==0 early-return; force a one-shot whole-dir
   clean-block evict when `i_dlm_dir_evicted_incarn != VFS_I(dp)->i_generation` (XFS bumps di_gen on
   every realloc → monotonic incarnation key) OR gen advanced; set evicted_incarn after. Probes
   renamed P103→P104-MODIFY/CONSUMER-REFRESH (log incarn+new_incarn).

## STANDING: criterion 3/4 (build 736ECD00)
cross_visibility PASS, rename_visibility PASS, unlink_visibility PASS, **cross_write_read FAIL**.
cwr now fails FAST (4-5s, no wedge): node3's tiny `data_node3.md5` sidecar reads EMPTY on ALL nodes
incl. node3 itself, while its 1MB data file is fine = a reg-file small-file content lost-update
(DIFFERENT bug from dir lost-update; see sess45/79 reg-file writer-durability). cwr PASSES alone.

## RESIDUAL #1 — intermittent whole-node rename loss (the gen-arming hole)
rename_visibility is FLAKY: alone = 6/6 PASS. After cross_visibility (criterion order) = ~25% fail,
and when it fails ONE node loses ALL 20 renames (invisible to ALL incl. writer = DURABLE loss; the
losing node varies: node1/node3/node4). RULE-4 evidence on a failing run:
- **COHOLD=0** on all nodes → NO concurrent-EX; cluster exclusion/serialization is CORRECT.
- **SESS50-STARVE=29-35** on all nodes → heavy dir-EX contention (holder slow to release to waiters).
- **DIR-STALE-SKIP=0** → not the dirty/pinned read-hook skip window.
- **P-DIRFASTEX stale_base never fires** → gen-based evict (fast AND slow path) is DISABLED because
  i_dlm_dir_gen stays 0. gen is armed 0→1 ONLY on the READ path (xfs_da_read_buf line ~2921, gated
  !owned_ex) and on slow-path EX/PR re-acquire (xfs_mxfs_dlm.c:3611). The eviction-ring DIR_MODIFY
  bump is gated gen!=0 (line ~5143) AND the ring is unreliable cross-node in CAW (sess82). So for a
  modify-only / weakly-read dir, gen can stay 0 → the whole gen coherency machinery
  (loaded_gen stale-detect, evicted_gen re-evict) is OFF. My incarnation-evict fires ONCE per
  incarnation (first modify) but does NOT re-evict on subsequent peer modifies within the burst.
- NEXT HYPOTHESIS to test: ARM i_dlm_dir_gen on the MODIFY path too (when multi-node node takes dir
  EX and gen==0, set gen=1) so slow-path re-acquire's `gen>loaded_gen` detects the peer-modified gap
  and re-evicts. sess43 warned write-acquire gen-bump TIMED OUT rename (FUA storm) — but sess94
  fua_disable=1 made plain reads cheap (sess100 confirms the timing wall is gone), so re-try it.
  Consider also: 2nd Gemini consult (RULE5 allows ×2 before GPT) on the cleanest convergence — the
  gen machinery has 4 holes (read-only arming, eviction-ring gen!=0 gate, unreliable ring, evict
  skips undurable). Gemini Q2 (sess104 consult): the real invariant is EX-acquire must guarantee
  fresh dir blocks; gen is a band-aid. Slow-path acquire (3611+3621 reload + 3624 sess64 eager
  inval) IS the refresh point — verify it actually evicts dir DATA blocks for a gen-armed dir.

## RESIDUAL #2 — cross_write_read .md5 small-file content loss (reg-file, separate)
node3's ~33-byte `.md5` empty on all nodes incl. writer; 1MB data file fine. Reg-file content
coherency / writer-durability of a small file under concurrent same-dir creates. Investigate after #1.

## METHODOLOGY (carry forward)
- reset4.sh only reboots nodes it must (saw only test3/test4) → test1/test2 keep STALE dmesg. For
  trustworthy shutdown attribution: `virsh -c qemu:///system destroy+start ALL 4` + reset4 + dmesg -C.
- rename loss signature: ALL nodes incl writer miss one node's after-files = DURABLE lost-update.
  Reader-only staleness = only some nodes miss it.
- rename alone = clean; cross_visibility→rename = the inode-reuse trigger. Loop the PAIR to repro.
- Criterion runs test_rename_visibility (== test_rename_vis_dbg minus DBG-EMPTY logging).
- Foreground waits get auto-backgrounded by the harness when long; use `until grep RESULT; do sleep`.
Marker NOT written (criterion 3/4, need 0 failures).
