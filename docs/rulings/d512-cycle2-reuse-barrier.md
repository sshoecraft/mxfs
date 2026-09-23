<!-- sess415 RULE-5 ruling D-512 cycle-2: reuse barrier mostly present; closure needs extent-publication proof, drain-error fail-stop, dirty diff-gen cont… -->
# sess415 GPT ruling (gpt-5.6-sol) — D-512 cycle-2 CLUSTER REUSE BARRIER

## Tree facts brought to the consult (verified sess415)
1. dialloc reuse = mxfs_v5_dlm_inode_reserve_try (dlm/v5_mount.c:7426) = EX NOQUEUE on the SAME per-ino
   DLM resource (CAW slot CAS; MXFS_LKF_DEMAND sticky revoke after a full failed sweep). Called from
   mxfs_dialloc_try_reserve (xfs/libxfs/xfs_ialloc.c:1590), used at pick (1676).
2. Holder-side BAST release drain (xfs_mxfs_dlm.c:17228-17246): filemap_write_and_wait +
   invalidate_inode_pages2 (unmaps PTEs) + i_dlm_stale=true BEFORE on-disk unlock. IOLOCK/ILOCK map onto
   the ONE per-inode DLM lock, so in-flight local ops (incl. DIO) pin the grant.
3. Re-acquire -> protective reload -> di_gen mismatch -> mxfs_incarn_poison (cycle-1 gates+revocation,
   verified 0.28.0: d512_ref_matrix 8/8, zsl x2, board 25 PASS).
4. Eviction ring = lossy optimization only.
5. Poison arms fire on CLEAN shells only; P52-RELOAD-FREEDREUSE-DIR-SKIP (xfs_mxfs_dlm.c ~25938) KEEPS a
   dirty dir shell whose disk image is a different-gen FREE slot.

## Ruling essentials
- Barrier "structurally mostly present" but component 7 closure requires:
  (a) EXTENT-publication proof — #1 critical hazard: the ino reserve interlock does NOT cover reuse of the
      freed file's extents. Every extent-free publisher (unlink/ifree, truncate, punch, reflink/COW cancel,
      orphan processing, replay, repair) must drain old-inode holders BEFORE the extent reaches free space.
  (b) DRAIN-ERROR FAIL-STOP: nonzero return from invalidate_inode_pages2 / writeback wait / flush during the
      release drain must BLOCK the unlock and escalate to withdraw/fence — never best-effort.
  (c) DIRTY DIFFERENT-GEN = INVARIANT VIOLATION (type-independent): add the containment arm NOW at the
      protective reload: predicate = in-core G1 + authoritative disk free-or-different-gen + ANY G1 dirty/
      in-flight provenance (dirty pagecache, writeback, DIO, ioends, COW, dirty metadata). Action: freeze,
      RETAIN grant (never publish unlock), poison, zap, discard REG pagecache after quiescing submission,
      loud persistent counter + forensics, WITHDRAW the mount (self-fence if withdraw can't stop LUN IO),
      quarantine the ino/AG. DISCARD+counter+continue is INSUFFICIENT. The P52 dirty-dir different-gen keep
      is UNSOUND — replace with the same arm; keep "disk behind us" only on positively-proven same-gen
      provenance.
  (d) Recovery/replay serialization: replay participates in the barrier (global recovery epoch OR replay
      acquires the same authorities); replay must never overwrite an already-reused dinode/extent; F1-F4
      obligations reconstructed or subsumed.
  (e) Fencing-before-grant-reassignment asserted on both transports (membership timeout alone never
      reassigns; PR fence confirmed first).
- Unlock publication order (mandatory): stop new ops -> wait local holders -> zap+TLB -> drain writeback/
  DIO/ioends/COW/DAX -> invalidate -> handle pins (GUP/RDMA/DAX layouts: pin grant or fail-stop) ->
  blkdev_flush -> mark stale -> ONLY THEN publish unlock. CAW CAS is not a substitute for the flush.
- W4 audit list beyond writepages: direct iomap writeback helpers, filemap_write_and_wait*, reclaim/
  migration/compaction, async+io_uring DIO, iomap DIO completion, ioend workers, delalloc conversion, COW
  completion, DAX, metadata buffer writeback, GUP pins, error paths leaving dirty pages.
- Hazard ranking: crit 1 extent-free-before-drain; 2 unlock-before-complete-drain; 3 replay racing
  allocation; 4 dirty diff-gen kept/adopted; 5 grant reassignment before confirmed PR fencing.

## Verification matrix T1-T9 (cross-node, both transports)
T1 clean lazy shell + exact ino reuse (old fd -ESTALE, no old bytes, fresh lookup G/ENOENT, P34H counters).
T2 pausepoint ladder in holder drain (before-writeback / writeback-outstanding / pre-invalidate /
   pre-flush / pre-unlock): free/extent publication must not pass; after unlock: no dirty, no PTEs, no DIO.
T3 DEMAND escalation (loser reserve, full sweep, DEMAND, bounded release; dropped demand = liveness only).
T4 fenced holder w/ dirty + paused async IO: PR fence FIRST, replay, reuse ino+extents, content+chk clean.
T5 crash/replay phase matrix (5 crash points from pre-logcommit to pre-unlock) x race a peer allocator.
T6 EXTENT reuse without ino reuse (unlink/truncate/punch) with a paused old holder — required, not optional.
T7 async-path drain (paused buffered bio / io_uring DIO / ioend / COW): unlock blocked until completion side.
T8 impossible-state containment via debug-only injector (synthesized dirty+mismatch, invalidate failure,
   flush failure): must freeze/withdraw, never return to service. NO remotely-reachable force-reuse knob in
   production; true barrier-bypass only on a sacrificial LUN.
T9 repeat T1/T2/T4/T5/T8 under CAW + TCP + master failover + partition-then-fence + stale membership.

## Build order (ruling)
1 document/assert publication state machine; 2 audit extent-free + async completion paths; 3 drain errors
block unlock + containment; 4 dirty-mismatch invariant arm REG+DIR (narrow P52); 5 replay serialization
asserts; 6 fencing-before-reassignment asserts; 7 pausepoints+counters; 8 cycle-1 race legs (safe NOW on
current build: poison-timing/fault-vs-zap/writeback-gate/clean-shell reuse); 9 T1-T3+T6-T7; 10 T4-T5/T9;
11 T8 synthetic; 12 sacrificial bypass; 13 close D-512 only after ALL pass.
