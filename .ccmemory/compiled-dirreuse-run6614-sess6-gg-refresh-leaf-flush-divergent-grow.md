---
name: compiled-dirreuse-run6614-sess6-gg-refresh-leaf-flush-divergent-grow
description: sess6/run6614: gg_refresh+leaf_flush fix dir_reuse to 4/tcp 100%; 8/tcp blocked by divergent-grow torn extent-map + inode-reuse cascade.
metadata:
  type: project
tags: [compiled, dir_reuse_coherency, tcp-dlm, divergent-grow, inode-reuse, gg-refresh, leaf-flush, 8-node]
---

## Compiled: dir_reuse_coherency across 1/2/4/8-node TCP DLM (sess6, run 6614)

**Criterion**: "get 1/2/4/8-node TCP DLM test suite to 100%." Session outcome
(final build `9AA569A0`): **1/tcp, 2/tcp, 4/tcp = 100% ✓; 8/tcp = the sole
remaining column, incomplete.** Criteria-met **marker NOT written.** All coordination
via `xfs_mxfs_dlm.c`.

### The two-part fix that won 1/2/4-node (both DEFAULT-ON, KEEP)

The ~50-session dir_reuse_coherency blocker was closed at 4/tcp (12/12 reliability)
by two default-on module params in `xfs_mxfs_dlm.c`. Build progression:
`FF572585` (phantom counters) → `8AEAC90F` (gg_refresh alone, 10/12) → `9AA569A0`
(gg_refresh + leaf_flush, 12/12). Details: [[sess6-ccloop-FIX-COMPLETE-gg-refresh-plus-leaf-flush-12of12]], [[sess6-ccloop-FIX-gg-refresh-wholeblock-loss-10of12]].

1. **`mxfs_dir_gg_refresh=1`** (NEW; ~line 3990 param, armed ~line 14862). Arms the
   loss-safe EVICT-ONLY refresh (`mxfs_dir_drain_evict_data_blocks`) on every
   `grant_gen` change (`hgg != ip->i_dlm_cached_grant_gen`) inside the
   `S_ISDIR && mode==EX && multinode` block, right before `cached_grant_gen` updates.
   - **Why**: the prior fast-path refresh armed off the master's `dg_shadow` handoff
     bit (`lk->handoff`) which sess13/sess53 proved UNDER-FIRES ~80% on TCP
     (P51-HANDOFF-UNDERFIRE). `grant_gen` always advances on any re-grant episode =
     reliable "lock changed hands" signal.
   - **Why loss-safe**: does NOT set `dir_ex_handoff` (no disk-adopt → no revert of
     uncommitted work). Evicts clean/destaged blocks, SKIPS undestaged/dirty/pinned
     in-flight work. On re-affirm-while-holding (grant_gen also advances = the sess63
     over-fire root) our dirty blocks are kept; on real cross-node re-grant our work
     was drained durable so cold-read gets the peer's superset.
   - **Effect**: eliminates the WHOLE-BLOCK (100-entry, entire node's contribution)
     data loss. Alone = 10/12.

2. **`mxfs_dir_release_flush_leaf=1`** (was SILENTLY 0 — the sess48 "DEFAULT 1"
   comment lied, initializer was missing; now `= 1` at ~line 4286). Force-completes
   LEAF/NODE/FREE dir index blocks at release (`mxfs_dir_flush_one_daddr`) so the
   next acquirer cold-reads a self-consistent data fork. Fixes the residual single
   leaf-hash hole (readdir=400 lookup_fail=1 missing=node2_f47).
   - **SAFE ONLY WITH gg_refresh**: gg_refresh gives a fresh leaf base each handoff,
     so force-completing our (peer-superset + our-adds) leaf cannot revert a peer's
     hash. The sess22/sess48 "leaf force-write reverts peer hash" harm was WITHOUT
     acquire-side leaf eviction.
   - **Effect**: gg_refresh + leaf_flush = **12/12** on `drc_reliability 4 12`. Each
     run = fresh mkfs (distinct UUIDs) + module reload, so genuine.
   - **REFUTED combo**: `dir_tenure_evict=1` on top of gg_refresh REGRESSED (run2 FAIL
     + DABUF_MAP_HOLE leaf-flood shutdown). Do NOT combine.

### Refuted root causes (don't re-chase)

- **Phantom-EX / DLM-serialization-hole (sess50/sess52)**: REFUTED on current build.
  P6-DIRPHANTOM atomic counters (no-heisenbug, not dirwr-gated) showed `phantom_total=0`
  on all 4 nodes during a live 4/tcp FAIL (serve_total ~2336–12016). The dir-EX cached
  fast-path serve (~14590) is never served while local `held_rawmode < EX`. The many
  double-grant fixes since sess52 closed it. [[sess6-ccloop-REFUTED-phantomEX-progress-1and2tcp-100pct]]
- **`dir_ex_revalidate=1`** (force master re-acquire on every published shared-dir EX
  modify): ~5 PASS / 2 FAIL of 7 + SLOW. Insufficient, consistent with phantom not being root.
- **Disk-space env (NOT an mxfs bug), masked ~5+ tests**: mxfs's heavy always-on
  kernel logging (P15-REL-ABORT, P28E, P-BLKWR, P64 via pr_warn) → rsyslog fills
  `/var/log/{syslog,kern.log}` → root 100% full → `/tmp` writes fail. test5-8 have
  SMALL 6.1G root disks (test1-4 = 26G) and refill fast. This produced the false
  1/tcp failures (integrity_filetypes/online_resize/dkms_install/fault_io_error) and
  the false cross_write_read failures (node5 file=4096, node7=8192, node8=0 —
  `dd if=/dev/urandom of=/tmp/src` wrote SHORT because /tmp full; strace showed
  `read(/tmp/src)=0`; dd to /mnt/shared 50G worked fine). FIX: truncate logs +
  `systemctl stop/mask rsyslog` + journald Storage=volatile RuntimeMaxUse=50M on all 8.
  dmesg kernel ring unaffected. **NEXT session MUST ensure rsyslog stays masked / disks
  have room before trusting any 8/tcp result.** [[sess6-ccloop-8tcp-16of17-diskspace-was-masking]] [[sess6-ccloop-REFUTED-phantomEX-progress-1and2tcp-100pct]]

### 8-node TCP: the remaining blocker (build 9AA569A0)

After the disk-space env fix, 8/tcp = **16/17** with **dir_reuse_coherency (0/8) the
SOLE failing test** (early snapshots reported 11/17 before some failures were traced to
disk space). PASS at 8/tcp: precond, cache_coherency, strong_consistency, posix_multi,
mmap_coherency, zero_silent_loss, dlm_fairness, dlm_membership, scaling_curve,
dlm_scaling, rsync_paired, crash_consistency, fence_during_write, fault_netpartition,
soak, tcp_dlm_scaling. (The earlier-reported cache_coherency/zsl/rsync/fence/soak 0/8
were the disk-space masking, not independent bugs — [[sess6-ccloop-CURRENT-STATE-head]] vs [[sess6-ccloop-8tcp-16of17-diskspace-was-masking]].)

8-node dir_reuse is genuinely flaky (~1/3: run1 PASS, run2/run3 FAIL) at 8-node
contention. Multiple fault FACES (dmesg): [[sess6-ccloop-HANDOFF-3of4-columns-100pct-8tcp-divergent-grow]] [[sess6-ccloop-8node-dirreuse-inode-reuse-cascade-faces]]

1. **Divergent-grow torn extent map (PRIMARY, highest-leverage)**: test1
   `P-IFLUSH-GAP-DETECT ino=131 nextents=8` — in-core dir data fork has a HOLE between
   data blocks → `XFS Internal error !(flags & XFS_DABUF_MAP_HOLE_OK) at
   xfs_da_btree.c:2885 xfs_dabuf_map` → shutdown. Root: a CONCURRENT DIR-GROW at 8
   nodes — a node reloads a STALE on-disk dinode (peer's dir-grow not yet IFLUSHED =
   sess105 stale-inode-core hole), sees the dir too short, RE-GROWS it → torn/holey
   extent map. gg_refresh rebuilds the fork from disk but ADOPTS the stale on-disk
   dinode (extent map / di_nextents not durable).
   - **LIKELY NEXT FIX**: `mxfs_dlm_dir_durable_signal` (`xfs_mxfs_dlm.c:18481`) flushes
     data+leaf BLOCKS but NOT the DINODE. The growing node must `xfs_iflush` the dinode
     (extent map) BEFORE EX release so the next acquirer reloads a CURRENT map. Careful:
     don't regress 4/tcp. Reference sess105/sess54 fork-rebuild + iflush-before-release.
   - Note: the sess49b TORN-DISK RELOAD GATE + iflush-gap detector DETECTS and PREVENTS
     some of these (test1 ino=131 detected, no shutdown) but is EXTENTS + same-incarnation
     ONLY — may miss BTREE-format or the local-grow tear.

2. **Inode-reuse cascade (distinct coherence domain)**: `mxfs: DLM inode reload
   imap_to_bp failed: ino=<fileino> rc=-5` (test3/test4) — reload can't map a FILE
   inode to its cluster buffer (rc=-5 EIO) = stale inode imap after the rm-rf freed the
   inode cluster and recreate reallocated it; a peer's inobt/imap view is stale → wrong
   cluster location. This is AG INODE ALLOCATION (inobt/finobt) + inode-cluster
   coherence across rm-rf+recreate churn — distinct from dir-block. Find
   `mxfs: DLM inode reload imap_to_bp failed` in `mxfs_dlm_reload_inode`
   (xfs_mxfs_dlm.c). FIX direction: on reload, if imap_to_bp fails, re-derive
   in-core inode/imap from a FRESH inobt (evict cached AGI/inobt/inode-cluster buffers
   on the AG); likely needs a grant_gen-triggered inobt/AGI refresh analogous to the
   dir-block gg_refresh. [[sess6-ccloop-8node-dirreuse-inode-reuse-cascade-faces]]

3. **Residual single-dirent leaf loss** (readdir=793/800, 7 lost, or 799/800; no
   shutdown) — the fine leaf/data stale-base tail, rarer but present at 8-node. May
   shrink once (1)/(2) fixed.

4. **Secondary/cascade faces**: `mxfs_dlm_fence_notify` Metadata I/O Error at
   `+0x3c xfs_mxfs_dlm.c:23348` (test5-8, fence_during_write face); alloc btree
   corruption `Internal error i != 1 at xfs_alloc.c:657 xfs_alloc_fixup_trees`
   (test5, AG-level at higher node count). run.sh runs all tests on ONE mount (no
   per-test remkfs), so an early shutdown breaks later tests — determine independent
   vs cascade.

### Repro / ops

- FAST repro: `scripts/drc_reliability.sh 8 6` (each 8-node run ~7–9 min; runs got
  slower with gg_refresh+leaf_flush ~4–5 min/run — watch RULE 0 wall-vs-budget).
- Isolated: `scripts/ccloop_reset.sh 8; ./run.sh 8 tcp dir_reuse_coherency`.
- Clean `/root/drc_*.dmesg` between runs (16MB dumps fill test5-8's 6.1G disks).
- Ensure rsyslog stays masked on all 8 (esp. test5-8) or disks refill and mask everything.
- Recover wedged nodes (test3 wedged mid-run) via `virsh -c qemu:///system destroy+start`.
- Prefer fresh full virsh reboot before trusting any slow 8-node result (cluster-state
  accumulation over resets-without-reboot can inflate the residual).

### Full-context head snapshot
[[sess6-ccloop-CURRENT-STATE-head]] — build 9AA569A0, deployed test1-8, 3 of 4 columns
done, marker NOT written; 8/tcp dir_reuse is the whole remaining task.
