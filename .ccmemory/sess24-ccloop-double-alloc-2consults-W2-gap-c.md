---
name: sess24-ccloop-double-alloc-2consults-W2-gap-c
description: sess24(ccloop 4eef1f39): full cache_coherency=0/4 (not handoff's 3/4 — high variance). 2 Gemini consults converged: inode same-chunk same-gen double-…
metadata:
  type: project
---

# sess24 (ccloop 4eef1f39, 2026-06-07) — build 2C16B9C9 deployed

## REALITY CHECK: full criterion is 0/4, NOT the handoff's 3/4
A fresh `cache_coherency.sh --nodes 4` on clean reset4 cluster (all 4 = 2C16B9C9)
gave **passed=0 failed=4**. cross_visibility (FIRST test) failed → node1 inobt
corruption shutdown → cascade ("Node 1 not mounted") for the other 3. So the
criterion is HIGH-VARIANCE / cumulative-fragile; the sess23 handoff's "3/4" was a
lucky run. cross_write_read PASSES in ISOLATION (clean mount) — it only fails in the
cumulative sequence. Repro cmd reminders: standalone test needs
`MXFS_TESTS_DIR=/src/mxfs/tests MXFS_NODE_OFFSET=16 tests/run_tests.sh --nodes 4
--phase cluster --test test_cross_write_read --pass-file /tmp/.mxfs_pass --device
/dev/sda --mount-point /mnt/shared`.

## THE FAILURE (full run dmesg, all 4 nodes)
1. **SESS50-STARVE** on shared-dir inodes 128/132/136 (per-INODE DLM, EX vs PR
   convoy) → 120s barrier timeouts ("got 3/4") → timing FAIL by itself.
2. **Inode same-chunk same-gen DOUBLE-ALLOCATION**: `RELOAD-TYPEFLIP-STALE-SKIP
   ino=4194435 incore_mode=040755(dir) disk_mode=0100644(regfile) incore_gen ==
   disk_gen == 2964760501`. EQUAL gen rules out legit reuse (which bumps gen) ⇒ two
   independent allocations carved the SAME inode/chunk. Workload: 4 nodes race
   `mkdir -p .mxfs_test/<sub>` (same name) then create regfiles inside.
3. → `inobt record corruption in AG 2` (xfs_inobt_check_irec) → `xfs_difree_inobt
   -117 EFSBADCRC` → FS SHUTDOWN.

## VERIFIED FACTS (RULE 4, code-read)
- The AG-DLM deferred-unlock-at-commit does NOT yield the CAW. `mxfs_ag_dlm_unlock`
  (xfs_mxfs_dlm.c:7918): holders--→0 sets `pag_dlm_cached=true`, KEEPS the on-disk
  grant; CAW is yielded ONLY by bast_work_fn on a peer BAST (Invariant #1 drain
  first). So MXFS is ALREADY pure BAST-driven cached-lock release. (Refutes Gemini
  consult-1's premise.)
- The concurrent-mkdir stale-EX guards ARE present & firing but INSUFFICIENT:
  P108-REACQUIRE (verify on-disk caw_held before trusting cached dir-EX,
  xfs_mxfs_dlm.c:3774-3805) fired 1×/node; MODIFY-REFRESH (dir-block cold-read on
  create/remove/rename RMW) 5-6×/node; yet TYPEFLIP fired 1-3×/node. P108 gate skips
  unpublished inodes & only acts when fully idle (pin==0, no holders).
- Drain set (`mxfs_dlm_ag_drain_meta_buffers` ~7336) and acquire-discard
  (`mxfs_ag_meta_coldread_discard` ~5583) BOTH cover only
  AGF/AGFL/AGI/bnobt/cntbt/inobt/finobt — they OMIT `xfs_inode_buf_ops` (inode
  CLUSTER/dinode blocks). = sess102's known "Gap (c)".

## 2 GEMINI CONSULTS CONVERGED (RULE 5) on TWO mechanisms
- **Mechanism 1 (inobt stale on release, CIL→AIL async window):** bast drain does
  `xfs_log_force(SYNC)` then scans for in-AIL/pinned bufs, but CIL→AIL insertion runs
  on a background kworker AFTER log_force returns. A just-committed inobt buffer can
  be unpinned-but-not-yet-in-AIL and look "clean" (XBF_DONE,!dirty,!in_ail,!pinned) →
  drain SKIPS it as "durable" → on-disk inobt stays stale (4194435 free) → peer
  cold-reads it free → double-alloc. **CAUTION: this is REGRESSION-PRONE, already-
  trodden ground.** xfs_mxfs_dlm.c:1487-1532 documents prior msleep+double-log_force
  +ail_push_all_sync attempts that made it WORSE (2/5 vs 3/5); whole-AG
  xfs_ail_push deadlocks (sess39 sync_iflush OFF; sess111 drain-wedge). Gemini's
  `xfs_ail_push_sync(mp,lsn)` fix ≈ what already regressed. DO NOT naively retry.
- **Mechanism 2 / W2 (FRESH — inode-cluster buffer coherence = Gap c):** the dinode
  that flips type lives in an `xfs_inode_buf_ops` cluster buffer, which is in NEITHER
  the release drain NOR the acquire coldread_discard set. So a node re-reads a STALE
  cached cluster buffer when carving a sibling inode and flushes it back, overwriting
  a peer's dinode → type-flip + EFSBADCRC. Gemini fix: add `xfs_inode_buf_ops` to
  coldread_discard (CLEAN-only, scoped to the AG block range) on acquire, and to the
  release drain. CLEAN-only = safe (no pending mods lost; in-core xfs_inode is
  unaffected, only forces fresh re-read on next iget-miss/iflush).

## NEXT (recommended order)
1. Implement W2 (the fresh angle) — extend coldread_discard + drain to inode-cluster
   bufs, CLEAN-only, AG-scoped, with a P-CLUSTER-DISCARD detector. Build, reset4,
   run cross_visibility ISOLATED, grep TYPEFLIP/inobt-corruption count before/after.
2. If double-alloc persists, Mechanism-1 inobt durability is the deeper root but
   regression-prone — consider GPT escalation (ask_gemini already used 2× this issue)
   for a CIL→AIL settle that does NOT deadlock (targeted single-buffer wait, not
   whole-AG ail_push).
3. SESS50-STARVE (barrier timeout) is a SEPARATE blocker; Gemini gave a turn-ticket
   "targeted handoff" protocol (releaser picks ONE EX successor or all-PR via
   yield_to; waiters back off unless in yield_to; clears yield_to on entry) — matches
   sess16 design, still unimplemented. Risky (naive bidirectional yield all-stalled).
Marker NOT written (0/4).
</body>
