---
name: ccloop-c7ee71c6-sess260-488-mechanism-proven-GPT-ruling-restart-protocol
description: sess260: -488 livelock MECHANISM PROVEN (dd's own ILOCKed txn-joined inode poisons its AG's drain; Coffman cycle) + RULE-5 ruling: clean-txn restart…
metadata:
  type: project
tags: [ccloop, defect-488, aglock, livelock, rule5-ruling, restart-protocol]
---

# sess260 — -488 mechanism proven + RULE-5 fix ruling

## Mechanism (RULE 4 step 2b: PROVEN, direct instrumentation, test27 dmesg archived tests/forensics/sess260_scaling_livelock/)
scaling_curve 32/caw livelock = distributed hold-and-wait (Coffman) deadlock + livelock overlay:
- dd holds ILOCK(EX) + OPEN txn, inode joined (ino 4209345 ag=1 on test27; wr_last=xfs_trans_alloc_inode, dio alloc path).
- That inode's COMMITTED log item is the only ag=1 AIL item — flushable (pin=0, buf ok) EXCEPT iflush needs ILOCK_SHARED, write-held by dd itself.
- bast_work_fn ran ALL 90s: every pass P67-AG-BAST-STALL (-EAGAIN bounded per-AG AIL push). P67-STALL-OWNER named owner=dd/6936; OWNER-STACK showed dd inside the INLINE pre-CAW demote scan (__mxfs_ag_dlm_lock ~36469) whose design assumption ("caller's ILOCKed inode statistically not in scanned AG") fails on EVERY node in this workload → ~0.7s burn per alloc retry.
- readopt=254: fast path re-adopts cached AG despite bast_pending (waiter starvation), while allocator iterates foreign AGs (contiguity chase) all EX-held by symmetric peers.
- Causality proof: instant the harness killed dds → next drain COMMITted (P12-WORK ag=1 COMMIT 5746.87). No strand, no tracking loss.

## Refuted
- sess243 sticky-REVOKE premise for this shape (holder knew and was cooperating; revoke can't make an un-drainable AG drainable).
- sess259 "pin outlives process death": page_ms = bast_pending age; holder=pid/comm is last-holder stamp; dd was alive spinning (csw climbing) until kill landed.

## RULE-5 RULING (GPT, sess260) — fix shape
Core invariant: **an operation may NEVER block for a cluster AG grant while holding ILOCK / dirty txn / any resource an AG drain can require.** Fix = (a) immediate transaction-aware RESTART protocol (not timeout-based) + part of (d) per-AG CLOSING admission:
1. Lock-bearing allocator context: AG acquire is NOQUEUE/trylock ONLY. If would-block: assert txn still clean/restartable → unwind → cancel clean txn (+ release reservations) → drop ILOCK → block for AG grant in lock-neutral context (pregrant/admission ticket) → relock → REVALIDATE (redo map lookup, EOF, quota, AG suitability) → restart whole iomap allocation. Restart boundary = xfs_direct_write_iomap_begin (or helper beneath it); NOT just iterate_ags. Precedent: v0.3.148 xfs_dialloc ILOCK drop.
2. Do NOT propagate raw -EAGAIN through iomap (IOCB_NOWAIT means it leaks to userspace) — use MXFS-private internal restart result caught in the XFS/MXFS alloc layer. IOCB_NOWAIT: unwind + return -EAGAIN without sleeping.
3. Enforced contract: debug assertions that blocking CAW wait never happens with dirty txn/ILOCK/AG-meta buf locks held. Any path discovering it needs another AG only AFTER dirtying must be refactored (preclaim/split/constrain) — it must not block and cannot cancel.
4. BAST admission tightening: per-AG grant state OPEN→CLOSING→DRAINING→RELEASED. On BAST: CLOSING = no NEW txn admissions; already-admitted finish (mandatory — else BAST prevents the drain-enabling commit). Kills the readopt=254 starvation. Tie admission to txn epoch/active-user ref, not "still cached".
5. Remove the pre-CAW inline full-drain scan from lock-bearing allocator contexts (or reduce to nonblocking bookkeeping) — futile + 0.7s/retry.
6. REJECTED: (c) escrowed release (inode-DLM does not cover cluster-buf readers: xfs_iget of sibling inode, inobt/finobt ops, bulkstat, recovery — would recreate Mode A). (b) prefer-own-AG = optimization only, no progress guarantee. Deadlock detection/priority inheritance: victim has no legal rollback point once dirty; diagnostics only.

## Verification (ruling's plan, condensed)
1. 3× ./run.sh 32 caw scaling_curve PASS in 90s, restart counters NONZERO (path exercised), no P67 loop. 2. Deterministic ring test: node i adopts AG i, dirty ILOCKed inode, all request AG (i+1)%N behind barrier → ring collapses via restarts, no timeout/death. 3. Assert clean-cancel boundary (fault-inject would-block at every AG iteration point). 4. Debug assertion: blocking AG wait ⇒ no txn + no drain-dependent lock. 5. Home-AG-exhausted test (disproves reliance on (b)). 6. BAST race injection at 7 points around restart/pregrant. 7. DIO semantics (NOWAIT, signals, EOF-extend, fsync). 8. Admission fairness (CLOSING bounds BAST-to-release under continuous local load). 9. Post-stress unmount + chk_mxfs + crash/remount. 10. RULE 0 perf: no new platter read, no global serialization; compare 1/2/8/16/32-node vs native.

## Rig state end of sess260
Fleet idle mounted 0.11.490 (sv B8A561D0), released cleanly after dd death. Board on .490: 11 PASS (chunks A+B), scaling_curve FAIL 3/3 (this defect), remaining chunks not run (rsync_paired crash_consistency dir_reuse fence_during_write fault_netpartition soak dirent_durability node_responsive kernel_health ag_strand_repair sustained_load dirent_publish/type_integrity open_defects dlm_lock_correctness). Verify no stranded AG bits w/ tools/caw_slotdump before reuse.

## Next
Implement restart protocol: start with (5) remove inline scan from alloc context + (1) NOQUEUE-only in lock-bearing context + restart plumbing in xfs_direct_write_iomap_begin path; then (4) CLOSING admission. One fix per RULE 4 cycle; scaling_curve is the measurement.
