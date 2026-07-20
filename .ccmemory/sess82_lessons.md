---
name: sess82_lessons
description: "sess82 (ccloop, 2026-06-04) — ROOT-CAUSED & FIXED the cross-node eviction-ring never delivering in CAW mode (the INODE_FREE + DIR_MODIFY coherency signals sess55/sess80 added NEVER fired cross-node). UNIFIED the unlink_visibility shutdown: trans_cancel = xfs_dir_removename rc=-2 ENOENT = node can't find its OWN just-created dirent = durable dir-block LOST-UPDATE. Same class as bnobt double-free. Durable-on-release flush attempts deadlocked/regressed — reverted."
metadata:
  node_type: memory
  type: project
  originSessionId: 65619bf7-be8e-4e84-9eb7-237e01f00557
---

# sess82 lessons (ccloop run 29df431e, 2026-06-04)

## BIGGEST WIN: the heartbeat eviction-ring NEVER delivered cross-node in CAW mode
- sess55 added an INODE_FREE eviction ring; sess80 added DIR_MODIFY to it. Both
  ride the disklock heartbeat (producer stages into evict_stage + bumps
  evict_head_seq; HB write serializes into the on-disk HB slot; the HB MONITOR
  loop reads peer slots and dispatches to mxfs_dlm_evict_inode_cb).
- **PROVEN with new markers P-EVICT-STAGE (producer) vs P-EVICT-DISPATCH
  (consumer): producer staged fine (DIR_MODIFY type=1: 37-80/node), DISPATCH = 0
  on EVERY node.** The consumer loop in disklock.c disklock_hb_fn gates every
  peer slot on `if (!ctx->monitored[slot]) continue;`. **mxfs_disklock_monitor_node
  is ONLY called from the TCP path (dlm/mount.c:614,1004). The CAW path
  (dlm/v5_mount.c v5_discovery_peer_cb / v5_refresh_active_nodes) NEVER calls it
  → monitored[] all-false → consumer skips every peer → 0 dispatch.** So sess55's
  AND sess80's coherency signals have been DEAD cross-node the whole time on the
  real (CAW) test cluster.
- **FIX (KEEP): self-healing auto-monitor in disklock_hb_fn.** Removed the early
  `if (!monitored) continue;`; now read every non-local slot's HB, and on an
  ACTIVE peer HB auto-monitor it (set monitored=true, slot_node_id=rhb->node_id).
  Inactive+unmonitored slots are skipped; dead-detection still gated on monitored.
  Marker P-EVICT-AUTOMON. After fix: DISPATCH ~200/node, EVICT-RING-DIRMOD
  (gate-pass) 34-52/node. unlink_visibility soft failures **10 → 2**.

## UNIFIED SHUTDOWN DIAGNOSIS (decisive new evidence)
unlink_visibility has TWO faces, same root:
1. SOFT: node1 sees node3_file26 still present after node3 deleted it (reader
   dir-block staleness) — auto-monitor cut this to ~2.
2. SHUTDOWN (stochastic, the sess47-81 "bnobt" blocker): trace =
   `MX-INSTR remove dp=135 ip=4194433 name="node3_file1" xfs_dir_removename rc=-2`
   then `xfs_trans_cancel at line 1060 ... Caller xfs_remove` →
   `Corruption of in-memory data ... Shutting down`.
   **rc=-2 = -ENOENT: node3 is deleting its OWN just-created node3_file1 but the
   dirent is MISSING from the on-disk shared dir block.** removename fails ENOENT
   while the unlink transaction is already DIRTY → xfs_trans_cancel(dirty) →
   SHUTDOWN. (P-SFDIR-RELOAD ino=135 fmt=2 + P-ACQ-DRAIN-SKIP done=0 just before
   = node3 slow-EX-acquired the dir, invalidated, FUA-read disk → disk missing
   node3_file1.)
- ⇒ Both faces = **durable dir-block LOST-UPDATE under concurrent 4-node
  shared-dir modify**: node A's committed dirent gets clobbered on disk when node
  B RMWs the same shared dir block off a stale cached copy. Same class as the
  bnobt durable double-free (sess81 disk_differs=0, CAW-DUP-SLOT=0 → concurrent-EX
  already refuted). The dir inode DLM serializes EX holders (single-holder proven),
  so the gap is DURABILITY-ORDERING across EX handoffs: node B acquires EX and
  FUA-reads disk before node A's dir DATA block destaged, or node A didn't drain
  its dir block durable before BAST-release.

## What FAILED this session (do NOT repeat)
- **Per-unlink durable-on-release in xfs_remove (after commit, dp ILOCK held).**
  - Attempt 1: mxfs_dir_push_data_ags(dp) = whole-AG xfs_ail_push_ag_sync →
    **3 nodes WEDGED** (whole-AG sync waits for the whole AG to drain; under peer
    AG contention it hangs while holding dp ILOCK_EXCL). Matches sess39 "whole-AIL
    push deadlocks".
  - Attempt 2: targeted single-buffer flush (mxfs_dir_flush_data_blocks: pin +
    xfs_buf_incore(flags=0 blocking lock) + xfs_bwrite per dir block) WITHOUT
    log_force → **WEDGED** (xfs_bwrite→xfs_buf_wait_unpin hangs on a PINNED
    buffer; the drain path does xfs_log_force(SYNC) first to clear pins).
  - Attempt 3: + xfs_log_force(mp, XFS_LOG_SYNC) before the targeted flush → no
    wedge but **REGRESSED 2 → 31 fails** + new mode "node1 only sees 90/120
    files; Failed to delete node1_file1" (per-unlink log_force+flush desyncs
    nodes badly + likely drops in-flight state). **REVERTED all of it.**
  - The dormant helpers mxfs_dlm_dir_durable_signal + mxfs_dir_flush_data_blocks
    remain in xfs_mxfs_dlm.c (exported, unused) for a future correct call site.

## Build state
- **KEEP build B5C1FA0F** = auto-monitor fix + P-EVICT markers + **defensive
  REMOVE-REVALIDATE (sess82, KEEP)**. Deployed test1-4. (Prior D7DAE795 was
  auto-monitor only; durable-signal call already REVERTED.) Auto-monitor +
  defensive-revalidate are both real fixes — do NOT revert.
- **Defensive REMOVE-REVALIDATE (xfs_inode.c xfs_remove, after xfs_trans_alloc_dir,
  BEFORE xfs_dir_remove_child):** multi-node only, `xfs_dir_lookup_locked(tp,dp,
  name,&ino)` (lock-free, dp ILOCK_EXCL already held, FUA-fresh) — if -ENOENT or
  ino!=ip->i_ino, `error=-ENOENT; goto out_trans_cancel` on the still-CLEAN txn.
  Converts the catastrophic trans_cancel-dirty SHUTDOWN into a benign "rm: No such
  file". **PROVEN: 0 shutdowns / 0 trans_cancel across a 3-iter run** (was
  ~stochastic node-death). Marker REMOVE-REVALIDATE-MISS.

## CRITICAL NEW INSIGHT — auto-monitor EXPOSES the durable lost-update
- After auto-monitor, unlink runs went 2 fails → **31 fails** (iter1: node1 saw
  only 90/120 files + 30 "Failed to delete" = node1 LOST ITS OWN 30 FILES). The rm
  fails at VFS-lookup level (REMOVE-REVALIDATE-MISS=0 → not the removename path).
- Mechanism: the now-working evict-ring bumps i_dlm_dir_gen → node1 INVALIDATES its
  own CLEAN cached dir block → FUA-re-reads a DISK image **missing node1's own
  creates** = the durable lost-update, previously HIDDEN because nodes never
  re-read (kept their complete-but-stale cache). **Auto-monitor is correct; it
  reveals that the DISK dir blocks are durably corrupt (a peer's concurrent
  RMW clobbered node1's committed dirents).** So the root is the WRITE-side
  durable lost-update during CONCURRENT shared-dir CREATE (not just unlink).
- DIR-STALE-SKIP=0 AND P-EVICT-SKIP=0 across the run → Gemini's specific
  "in_AIL read-side skip" mechanism is NOT firing here. The stale block is being
  served as gen-FRESH (b_gen==i_gen, no mismatch) OR the corruption is purely on
  disk. NEXT decisive datum: run a CONCURRENT-CREATE-ONLY test, then FUA-read the
  shared dir on-disk vs in-core and COUNT dirents — if disk < 120, write-side
  lost-update CONFIRMED as root (then fix the EX-handoff durability ordering /
  acquire-side refresh). Async HB-ring signal is INHERENTLY too slow for
  write-write RMW serialization (multi-second propagation); only the DLM EX +
  durability-on-handoff can serialize concurrent dir RMW.

## Gemini (RULE 5) consult — saved guidance
- Root hypothesis: across EX handoff, a node's OWN just-written dir buffer is
  CLEAN-on-disk but still `in_AIL` (log tail not advanced); on re-acquire the
  gen-hook SKIPS in_AIL → node RMWs its own stale buffer → clobbers peer. FIX =
  in the BAST-RELEASE drain worker (NO ILOCK held), after log_force+bwrite, also
  push AIL to DETACH those buffers' LSN so in_AIL=false on re-acquire. (CAUTION:
  whole-AIL sync deadlocks — sess39; use targeted/LSN wait. And markers say the
  read-side in_AIL skip isn't the firing path here — instrument before coding.)
- Defensive ENOENT in xfs_remove (DONE this session, works).
- Why per-unlink targeted-bwrite regressed: it wrote ONLY the dir block →
  peers FUA-read a TORN transaction (new dir block, old inode/bnobt) = "sees
  90/120 files". Never selectively flush one buffer of a multi-block txn.

## Next (RULE 5 — consulting Gemini on the durable lost-update)
The durable dir-block lost-update has resisted sess39-81. Consult Gemini with:
the EX-handoff durability-ordering gap, why per-unlink flush deadlocks/regresses,
and ask for the correct place to enforce "predecessor's dir block durable BEFORE
successor's FUA-read-on-acquire" without the hot-path cost. ALSO: defensively
handle removename==-ENOENT in xfs_remove (cancel CLEAN, not dirty→shutdown) so the
lost-update degrades to a soft miss instead of a node-killing SHUTDOWN that also
fails cross_write_read.

## Infra (unchanged from sess81, still true)
- After reset4, nodes NFS-mount /mnt/mxfs-src from host (192.168.120.1:/src/mxfs);
  export lost on host reboot — re-add exportfs fsid=42 + per-node mount.
- A wedged/shutdown node: umount busy + rmmod "in use" → `sudo virsh reset testN`,
  wait ~75s, re-mount /mnt/mxfs-src, then reset4.
- Isolated run: `MXFS_NODE_OFFSET=16 bash tests/run_tests.sh --nodes 4 --phase
  cluster --test test_unlink_visibility --pass-file /tmp/.mxfs_pass --device
  /dev/sda --mount-point /mnt/shared`. Shutdown manifestation is STOCHASTIC
  (some runs 2 soft fails ~25s, some hit trans_cancel shutdown).

State head = sess82. See [[sess81_lessons]] [[sess80_lessons]] [[sess47_lessons]].
