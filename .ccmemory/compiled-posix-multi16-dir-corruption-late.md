---
name: compiled-posix-multi16-dir-corruption-late
description: sess77-80 posix_multi16 dir corruption: durable sf→block format/content tear, dir-bmap HOLE, iget sched-while-atomic FIX (305641B7), 2-node repro.
metadata:
  type: project
tags: [compiled, posix-multi16, dir-corruption, dir-bmap-hole, sched-while-atomic, sf-to-block, read-staleness, ship-gate]
---

## posix_semantics_multi16 >600s FAIL — durable directory corruption (sess77→80, ccloop run 14d31183)

Central topic: the late `posix_semantics_multi16` ship-gate blocker is NOT pure 16-node slowness
— it is **durable on-disk directory corruption** produced under concurrent same-dir modify during
the shortform→block→leaf→node growth of a *barrier* directory. The corruption causes a single
random node to force-shutdown (all ops EIO → barrier_wait 120s timeouts × many tests → cumulative
>600s hang, NOT a single hang). Across these sessions two distinct root causes were separated and
one was fully fixed.

### Gate context (evolving, read `.criteria_results.json` not state.md/`p` prompt — both go stale)
- sess77/78: `posix_semantics_multi16` + `rsync_paired` (148%) FAIL; `tcp_dlm_scaling` pending;
  `fence_during_write` FIXED sess77 (build 3DC74E7D). `posix_semantics_multi2` is NOT a gate
  criterion (a diagnostic only) — ignore it in gate math.
- sess79/80: 17/20 PASS. Real FAILs = **rsync_paired** (235% of XFS, threshold 120% — regressed
  from 148%) and **posix_multi16** (>600s). cache_coherency / strong_consistency / zero_silent_loss
  / crash_consistency / fence_during_write all PASS (any resume-summary citing cache_coherency as
  the blocker is stale).

### ROOT CAUSE A — durable dir-inode format/content tear (sess77, build 3DC74E7D)
[[sess77-posix-multi16-durable-dir-format-content-corruption]] proved on a freshly-rebooted clean
16-node cluster:
- The shutting-down node's dir inode (run: node11, ino `0x1c001b2`=29360562 =
  `/mnt/shared/.mxfs_barriers/cwr_write`, a barrier dir 16 nodes concurrently `touch nodeN` into →
  grows shortform→block).
- dmesg: `xfs_bmap_validate_extent_raw` "Bmap BTree record corruption in inode 0x1c001b2 data fork";
  `!(flags & XFS_DABUF_MAP_HOLE_OK)` at `xfs_da_btree.c:2814` (`xfs_dabuf_map`); `DLM inode from_disk
  FAILED ino=29360562 rc=-117` (EFSCORRUPTED) → `xfs_trans_cancel` in `xfs_create` → shutdown.
- DECISIVE evidence: "First 16 bytes of corrupted metadata buffer: `0d 00 00 60 00 82 05 00 60 6e
  6f 64 65 37 01 01` …`node7`.." — the bytes decoded as a bmbt extent record are actually SHORTFORM
  DIR DATA (`0d`=count 13, ASCII "node7" = a dirent name). => on-disk inode has di_format=EXTENTS/BTREE
  while its data-fork literal area still holds SHORTFORM dir content. A **format/content mismatch**
  from a raced `xfs_dir2_sf_to_block` / `xfs_bmap_local_to_extents` conversion under concurrent
  16-node EX adds.
- DURABLE: even healthy test1 (never shut down) gets "Structure needs cleaning"/EFSCORRUPTED on
  `ls cwr_write`. Only 1 node shuts down because a node shuts down only when it READS that dir inode
  while its cached image is invalidated (DLM from_disk reload); the writer and nodes with a still-valid
  cache survive.
- This is the sess39/53-57/84-90 family ("dir-data clobbers inode cluster" / "shortform-dir lost
  update" / "inode double-alloc"). sess90 FIX1 `mxfs_buf_has_uncheckpointed_mods` likely does not
  cover the dir-inode conversion case.

### Repro difficulty + contamination trap (sess77)
[[sess77-posix-multi16-repro-notes-and-starvation]]: standalone concurrent mkdir-race + distinct-add
+ file-create does NOT reproduce (repro_barrier_coherency 16-node PASS 6s; repro_sfblock_corrupt.sh
[NEW/KEEP] 16×30 rounds = 0 corruption; + shared 64k file-creates = 0). The corruption needs the
REAL mxfs_test.sh pattern: an aggressive `find`/readdir (PR) barrier_wait loop running CONCURRENTLY
with the create storm (EX), AND only fires after several prior cluster tests accumulate state.
Intermittent, 1 random node of 16.
- Side finding (distinct symptom): a 6s concurrent readdir storm during the create storm caused a
  cluster-wide LIVENESS STALL — 9+ nodes with ~16 D-state readdir procs each, round never completes,
  no shutdown. This is sess50 CAW writer-starvation (PR readers re-grant among themselves, EX create
  starves) amplified at 16 nodes; contributes to posix_multi16 slowness independently of the corruption.
- **Contamination mandate (recurring):** earlier "lost dirent" leads were an orphaned pkill'd
  run_tests.sh leaving D-state procs holding AGI buffer locks. MUST `virsh destroy+start` ALL nodes
  (not just reset4.sh rmmod) before trusting any 16-node result.

### 2-node cheap deterministic repro (sess78, user directive: ladder 2→4→8→16, stop jumping to 16)
[[sess78-dirstress-2node-asymmetric-block-dir-read-staleness]]: `run_tests.sh --nodes 2 --phase
cluster` (bypasses posix_semantics wrapper → no internal reboot) → concurrent_mkdir/touch/write,
cross_visibility, cross_write_read, cv_disc all PASS fast; **test_dir_stress FAIL — 40 failures/81
assertions in 7.7s.** So the blocker is a CORRECTNESS bug reproducible at 2 nodes in ~8s, not 16-node
contention.
- Symptom = ASYMMETRIC block-format-dir read staleness. Both nodes mkdir -p shared parent
  `dir_stress`; each adds 20 subdirs (nodeN_dir1..20 ×10 files) → 40 entries → parent grows
  shortform→BLOCK/BTREE. **node1 (parent-dir creator/owner via mkdir -p race): 40 FAILs** — sees only
  its OWN 20, "directory not found"/"actual=0" for all of node2's. **node2: 0 FAILs.** The node that
  OWNS/caches the block-format parent dir fails to reload a PEER's later additions; the cold-reading
  peer reads from disk fine. This is the block-format-dir reader-staleness family (v0.4.7 read-time
  `i_dlm_dir_gen` invalidation; sess41/46/83 F08CE615) — passes cache_coherency because that uses
  small/shortform dirs.
- Undetermined at sess78: write-loss vs read-staleness. Decisive test = after failure, umount+remount
  node1 (or fresh node3) and re-count node2's dirs (appear → pure read-cache staleness; absent →
  node2's adds not durable).
- Build **7D1492FC** (P78 format/literal torn-dinode barrier) deployed all 16 nodes; P78 did NOT fix
  dir_stress (different mode) but is correct-by-construction for the torn-format case — KEEP.
- Infra: SCST abort-reclaim fix DEPLOYED+LIVE (target 3.11.0-pre+caw-abort-reclaim.1; rebuilt
  iscsi/isert-scst.ko to match version string or SCST rejects "Incorrect version of target iscsi";
  old modules *.pre-caw* in extra/). Cleared a D-state iscsi_conn_cleanup wedge WITHOUT reboot via
  scst_unwedge.ko.

### ROOT CAUSE B — FIXED: iget diagnostic sched-while-atomic → inobt corruption (sess79, build 305641B7)
[[sess79-iget-checkfreestate-sched-while-atomic-corruption-FIXED]] — VERIFIED FIX, KEEP:
- Root (PROVEN via kernel BUG + stack): `xfs_iget_check_free_state` (xfs/xfs_icache.c ~669-714) has
  an ALWAYS-ON diagnostic block `P-IGET-ENOENT` (from sess40/sess127) doing SLEEPING I/O
  (`xfs_buf_incore` + `mxfs_pal_scsi_read_fua_bdev`, FUA SCSI read = blk_execute_rq wait) on the
  mode==0 ENOENT cache-HIT path. `xfs_iget_cache_hit` (line 981) calls check_free_state while holding
  BOTH `rcu_read_lock()` AND `ip->i_flags_lock` (spinlock) ⇒ preempt_count=2. Sleeping there =
  `BUG: scheduling while atomic: mxfs-worker preempt_count=2`, reached via
  `bast_recv_fn→v5_bast_cb→mxfs_dlm_bast_notify→xfs_iget(XFS_IGET_INCORE)`. The forced schedule lets
  an RCU grace period reclaim/free the inode → use-after-free → inobt record corruption in AG8 →
  Metadata I/O Error at `xfs_inactive_ifree` (xfs_inode.c:2391) → SHUTDOWN. The concurrent
  unlink/create storm constantly produces mode==0 (freed/reused) inodes so it fired every run.
- Patch: guard the sleeping probe with `if (!in_atomic() && xfs_buf_incore(...))`. `in_atomic()` is
  reliably true at the dangerous site (spinlock bumps preempt_count regardless of RCU config).
  Diagnostic-only, no functional change. The two OTHER `xfs_buf_incore` diagnostics in the same fn
  (~544/~594) are on the XFS_IGET_CREATE non-atomic path — left as-is.
- Verified: before, `run_tests --nodes 2 --phase cluster` → rename_vis_dbg + unlink_visibility FAIL,
  dmesg = sched-while-atomic ×N + inobt corruption + shutdown. After (305641B7): 12 PASS/1 FAIL,
  **0 sched-while-atomic, 0 corruption, 0 shutdown**; unlink_visibility + rename_vis_dbg PASS.
- Remaining after B fixed: test_dir_stress block-format-dir READ STALENESS still fails, but reduced
  from sess78's 40 to **3 fails/81**, still asymmetric (node1 the parent-owner misses some of node2's
  later dir adds e.g. node2_dir14/15; node2's dirs ARE durable — a cold reader sees them). = v0.4.7
  read-time `i_dlm_dir_gen` invalidation NOT covering the parent-OWNER case once dir is block/btree.
  Cheap repro: `MXFS_NODE_OFFSET=16 MXFS_TESTS_DIR=/src/mxfs/tests tests/run_tests.sh --nodes 2
  --phase cluster` (~90s).
- Infra: run_tests.sh MUST be invoked with `MXFS_TESTS_DIR=/src/mxfs/tests` (default /mnt/mxfs-src
  NOT mounted on nodes → rc=127 masquerading as test failures; /src is the QNAP NFS on nodes).
  test1-4 /dev/sda = QNAP iSCSI (192.168.1.4) FLAPS conn-error(1020) per-initiator → power-cycle the
  node (virsh destroy/start) for fresh iSCSI sessions THEN reset4.sh. Repro: tests/repro_lost_entry.sh.

### ROOT CAUSE A refined — dir-bmap HOLE / lost extent (sess80, build 305641B7, diagnosis only)
[[sess80-posix-multi16-root-dir-bmap-hole-and-contamination]] — after fix B, posix_multi16 still
FAILs >600s and it is STILL corruption→shutdown→hang, same signature as sess77:
- This run: test_cv_disc (6th cluster test) → `xfs_dabuf_map: bno 8388609/8388610 inode 131 …
  Internal error !(flags & XFS_DABUF_MAP_HOLE_OK) at line 2814 xfs_da_btree.c` on multiple nodes
  (t2,t3,t4,t12) → `mxfs: DLM shutting down` → all ops EIO → many barrier_wait 120s timeouts → hang
  (>16 min). bno 8388608=0x800000 = dir2 LEAF address space; HOLE at 0x800001/2 = the dir grew
  leaf→node but the **data-fork bmap extent for the new block is MISSING** → `xfs_da3_node_lookup_int`
  hits a hole. = durable dir-bmap lost-update under 16-node same-dir modify across sf→block→leaf→node.
- chk_mxfs -v post-unmount: inodes 137,138 nlink=0 (allocated but parent dirent LOST = durable dirent
  lost-update orphans); SB icount=320 but inobt sum=5120, ifree mismatch (durable SB counter drift
  across nodes). chk is SHALLOW (8/11 inodes) — did NOT deep-validate inode 131's dir bmap, so
  on-disk(H2) vs in-core(H1) of the HOLE remains OPEN.
- Timing depends HUGELY on contamination: clean reboot → concurrent_mkdir 22s, concurrent_touch 30s,
  concurrent_write 15s, cross_visibility 127s, cross_write_read 9s; CONTAMINATED (orphan run_tests
  D-state AGI locks) → concurrent_touch 182-264s. sess77 kill-orphans mandate reconfirmed. NEW tool
  tests/reboot_cluster.sh (virsh destroy+start all N).

### Perf side (rsync_paired 235% + create-throughput, sess80)
- ct_decompose microbench (tests/ct_decompose.sh): 16-node concurrent touch into ONE dir — CREATE
  phase dominates (55s of 182s), stat/ls fast. Uncontended 510/s; under 16-way contention ~29/s =
  ~17× CAW EX-handoff penalty; slowest node starved 54.8s for the lock.
- `mxfs_dlm_dir_modify_refresh`→`mxfs_dir_evict_data_blocks` evicts ALL dir blocks per create when
  peer-modified → O(dir-blocks)/create = O(n²); reads are lazy O(log n). MHT (`inode_mht_ms`, default
  50, runtime-writable /sys/module/mxfs/parameters/inode_mht_ms) amortizes by batching a node's creates
  per tenure: 250→create 55s→16s (3.4×), 150→7.8s — BUT durable divergence appears (test1 sees 600,
  test8/16 see 0, no converge). **Raising MHT trades correctness for speed — NOT a safe fix; default
  50 is tuned to the correctness edge.** Fix the dabuf_map HOLE first, then attack handoff throughput.

### Decisive NEXT (RULE 4, carried into sess81+)
- test_cv_disc has built-in drop_caches H1/H2 discrimination but HUNG before logging. Re-run cluster
  phase on clean reboot; capture FIRST `xfs_dabuf_map` inode#, the DISC H1/H2 line, chk that inode.
  - **H1** (in-core stale, on-disk present) → reload bug: `mxfs_dlm_reload_inode` /
    `xfs_idestroy_fork`+from_disk rebuilds the extent map but from stale bytes.
  - **H2** (on-disk lost) → writer drains dir DATA but releases dir EX WITHOUT durably flushing the
    INODE carrying the new extent (Architectural Invariant #1 gap; cf sess135 "dinode iflush refused
    by P119 non-EX authority guard"). Then guard.
- Also instrument the sf→block conversion (`xfs_dir2_sf_to_block` / `xfs_bmap_local_to_extents`) +
  inode-cluster FUA reload for DIRECTORY inodes (log ino, di_format transition, di_nextents, whether
  data-fork bytes match the format), gated behind mxfs_instr; catch di_format flipping to
  EXTENTS/BTREE while literal area still holds shortform dirents. Target: cluster phase 0 shutdowns,
  suite <600s, then rsync_paired.

### Build progression
3DC74E7D (sess77, fence fix) → 7D1492FC (sess78, P78 torn-dinode barrier, KEEP) → **305641B7**
(sess79 iget sched-while-atomic FIX, VERIFIED KEEP; unchanged through sess80 diagnosis).
