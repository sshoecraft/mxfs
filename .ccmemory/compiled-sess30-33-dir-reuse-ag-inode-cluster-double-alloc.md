---
name: compiled-sess30-33-dir-reuse-ag-inode-cluster-double-alloc
description: sess30-33 dir_reuse 2/tcp: FACE-C data-over-inode-cluster double-ownership root, FACE-B fix (5E706CBF), SB-counter incoherence lead.
metadata:
  type: project
tags: [compiled, dir_reuse_coherency, double-alloc, inode-cluster, AG-coherency, sess30-33, tcp]
---

# dir_reuse_coherency 2/tcp — sess30-33: the multi-face reuse-clobber, FACE-C double-ownership root

Central subject across sess30-33 (all ccloop 8ddb16a2): the ONLY failing ship
criterion is `dir_reuse_coherency` under `./run.sh 2 tcp` (16/17 or 17/18 other
tests pass; marker NOT written in any of these sessions). The test runs 24
rounds; each round rank1 `mkdir D`, BOTH nodes concurrently write 50 files + 50
`.md5` (200 entries) into a SHARED dir (ino 131), `sync`, `drop_caches`,
readdir + stat-each, then rank1 `rm -rf D` (reuses inodes/daddrs). The dir grows
SF→block→leaf (nx=3, size=8192, block0+block1 data + leaf). The reuse churn is an
ABA/double-alloc stressor. The failure presents as multiple intermittent
**faces** that flip run-to-run; the deepest (FACE C) is a block double-OWNERSHIP
that shuts the FS down and blocks the criterion outright.

## The three faces (established sess30, stable framing through sess33)
Per [[sess30-three-faces-FACEC-double-alloc-is-root]] and
[[sess30-FACEC-bnobt-double-alloc-deep-dive]], all present in baseline AB435ACC:
- **FACE A (DATA)**: readdir<200 (e.g. 185/186, 181/200), lookup_fail=0 — a
  contiguous create-order range (= one dir DATA block, e.g. node1_f1..f12)
  durably missing on BOTH nodes = durable write-side loss of a dir data block.
- **FACE B (LEAF / inode-revert)**: two distinct sub-symptoms got labeled "B" —
  (1) readdir=200 but lookup_fail=N (leaf hashval gone → stat ENOENT,
  P26-DSCAN-MISS under-reads), and (2) the inode-revert / `P26-IGET-FAIL`
  (dirent → inode X, iget returns -ENOENT because in-core X mode==0). Sub-symptom
  (2) was FIXED in sess31 (below).
- **FACE C (INODE-CLUSTER CORRUPTION → SHUTDOWN, severest, ~1/3 runs)**:
  `xfs_inode_buf_verify` EFSCORRUPTED (-117 "Structure needs cleaning") reading
  an inode cluster daddr (observed 0xc00, 0xc40, 0xcc0 across runs); the
  buffer's first 128 bytes are RANDOM urandom file data (no "IN"=0x494e magic).
  `P26-IGET-FAIL` inum == that block (e.g. 3072-3076 @0xc00, 3136-3143 @0xc40,
  startino 3264 @0xcc0) = the exact `.md5` files that fail stat. **A file's DATA
  block and an inode cluster share a daddr = block double-OWNERSHIP.** This is
  the proven root ([[sess33-PROVEN-ROOT-inode-data-block-double-alloc]]).

Common root of all faces: stale cached state (dir DATA/LEAF block, inode-cluster
buffer, file/dir extent-map) survives daddr/inode REUSE across rm-rf+recreate.

## FACE C mechanism — M1 vs M2 (the central diagnostic fork)
- **M1-intra-node allocator double-alloc: RULED OUT.** `P55-ALLOC-OVER-INODE`
  (per-AG 256-ring of this node's inode-chunk extents) + `P55-ALLOC-OVER-
  CACHEDINODE` (xfs/libxfs/xfs_alloc.c ~4092) both fired 0× on both nodes.
  sess47 double-FREE detectors (INACT-SKIP-STALE/P47/P81) also 0×. Those rings
  CANNOT see a PEER's inode chunk, so intra-node only.
- **M1-cross-node allocator double-alloc: NOT fully ruled out.** The only
  on-disk cross-node check (`P55/P33-ALLOC-OVER-DISKINODE`, plain-read the
  allocated daddr's di_magic, LIO-coherent) was removed for perf. sess33 re-added
  it but a per-alloc sync disk read (~19k reads holding AGF) TIMES OUT the test
  (RULE 0, 300s no-result) → REVERTED. A cheap variant is still owed.
- **M2-stale extent-map mis-WRITE: leading theory.** A node's in-core dir/file
  extent map points at a reused daddr now backing an inode cluster; the file-DATA
  write lands urandom over the cluster. CRITICAL: file-data writes go via
  iomap/bio and BYPASS the xfs_buf metadata chokepoint
  (`mxfs_buf_xfsaild_skip_dir_write`), so no metadata-buffer guard can catch or
  prevent FACE C. [[sess30-FACEC-bnobt-double-alloc-deep-dive]] aligns this with
  the 16-node [[sess55-faceB-is-M2-stale-bmap-not-allocator]] conclusion.

### sess33 decisive evidence favoring M2 (chk_mxfs on frozen corrupt image)
[[sess33-chkmxfs-SB-counter-incoherence-new-lead]]: after a corrupting run
(inode cluster 0xcc0, startino 3264), `umount -l` then `tools/chk_mxfs -v
/dev/sda` on the frozen image (zero hot-path cost):
- **All per-AG btrees internally CONSISTENT** — AGF/AGI OK, BNO/CNT OK,
  inobt/finobt OK on every AG; `AG0 inobt rec2 startino=3264 count=64
  freecount=52` records the corrupted chunk as normally allocated; 11/11 key
  inodes passed. NO btree-level double-alloc → weakly favors M2 over M1. CAVEAT:
  chk_mxfs does per-btree internal validation, NOT an xfs_repair-style
  block-ownership cross-map, so a true double-OWNERSHIP would NOT be flagged →
  M1 not 100% excluded.
- **NEW CONCRETE BUG — SB summary counters durably incoherent with btrees:**
  `AGF freeblks sum 13015695 > SB fdblocks 12990486` (undercounts free by
  ~25209); `inobt total inodes 1856 != SB icount 1728` (undercounts by 128);
  `inobt free inodes 1616 != SB ifree 0`. **ifree=0 is the smoking detail**: a
  node reading ifree=0 believes NO free inodes → allocates a NEW inode chunk
  instead of reusing → extra inode-chunk block allocs in the contended dir AG →
  more reuse churn → more data-over-inode-cluster clobber chances.
- Hypothesis: sb_fdblocks/sb_icount/sb_ifree are per-mount in-core percpu
  counters folded to disk periodically; two nodes maintain independent counters
  and clobber each other (last-writer-wins, local-only view) with no cross-node
  coordination. FIX directions: FUA re-read SB counters at alloc; drive alloc
  decisions off per-AG AGF/AGI counts (coherent via AG-DLM) not the global SB
  summary; or coordinate SB writeback. Possibly MORE tractable than per-buffer
  coherency patches. PROBE: re-run chk_mxfs after a CLEAN (non-corrupting) run to
  see if drift exists without corruption (⇒ standing bug, not artifact).

### sess33 M2 supporting evidence
[[sess33-PROVEN-ROOT-inode-data-block-double-alloc]]: `P62-RELOAD-FORK-SHRINK
ino=131 incore_nx=1 size=4096 (stale BLOCK-fmt) vs disk_nx=3 size=8192 (correct
LEAF), post_release=1` — in-core dir inode stale-SMALL while disk correct-large.
`P26-RDDIR ino=131 reload_armed=0` while dir_gen advanced (5,18) — the cross-node
`MXFS_IF_DIR_RELOAD` signal is NOT armed, so modify/consumer reload may not fire →
stale extent map used → FMT_BLOCK mis-decision (dir3_block_verify 0x78 face) or
mis-write (data-over-cluster face). AG-coherency audit found both read and
release sides look correct: read hook `mxfs_ag_meta_invalidate_stale`
(xfs_alloc.c:3733, xfs_ialloc.c:3171, xfs_btree.c:1420) FUA-re-reads bnobt every
acquire (TCP `mxfs_v5_dlm_ag_read_generation`=-ENODEV → pag_dlm_meta_gen bumped
unconditionally ~xfs_mxfs_dlm.c:12091); release `mxfs_dlm_ag_drain_meta_buffers`
(12465) drains AGF/AGI/bnobt/cntbt/inobt with blkdev_issue_flush before unlock.
Both sides looking correct makes M1-cross-node less likely than M2.

## FACE B FIXED — the one durable win (sess31, build 5E706CBF, KEEP)
[[sess31-FACEB-FIXED-p116-grant-held-discriminator]]: FACE B (inode-revert /
P26-IGET-FAIL / lookup_fail sub-symptom). Root: a reload ADOPTS the stale-free
on-disk image and reverts the node's OWN live inode to free in-core
(`P-RELOAD-IOPS-REWIRE old_ifmt=0100000 new_mode=00`). Proven via detectors
P31B-RELOAD-BUF (xfs_mxfs_dlm.c ~5990) + coherent plain-read showing SAME gen G
across free+live = the node's own inode (not a stale-gen resurrect). The existing
`P116-RELOAD-SELFCLOBBER-SKIP` guard (~6276) kept in-core only when DIRTY
(pin/ili_fields/in_AIL); by verify phase the node's own create is CHECKPOINTED
clean → guard fell through → self-clobber.

**THE FIX**: add `sc_grant_held = (ip->i_dlm_mode != MXFS_LOCK_NL)`, keep in-core
when `sc_dirty || sc_grant_held`. Rationale (i_dlm_epoch invariant): while
i_dlm_mode != NL the on-disk grant is HELD, so no peer can have freed this inode;
a disk image reading FREE while we hold the grant + in-core ALLOCATED is provably
STALE. Node-affine inode alloc (sess45, xfs_ialloc.c:2103 `node_slot % maxagi`)
means a peer can't own this inode's cluster → held grant is authoritative. A
genuine peer-free requires the peer to acquire EX (BASTs us to NL first), so
NL is the only state where disk-free is authoritative → no resurrection
regression. RESULT (build 5E706CBF, run 20260619T095321Z): P116 held=1 fired 40×
on test2; P-RELOAD-IOPS-REWIRE new_mode=00, P26-IGET-FAIL, lookup_fail,
P31B-RELOAD-BUF, dir3_block_verify all = 0×. FACE B gone; cache_coherency /
zero_silent_loss / crash_consistency all PASS 2/2.

## dir-DATA-block loss (FACE A) — sole residual after FACE B fix
[[sess31-dirblock-face-all-fixes-present-residual]]: after 5E706CBF, every run
fails ONLY with `readdir=185/200 lookup_fail=0` (~12-16 of one node's first-wave
dirents durably missing, both nodes agree = durable write-side loss; the sess29
xfsaild-stale-dirblock-flush root, comm=xfsaild mode=5 EX-held). PROVEN this
session: ALL release-side fences present and working (P-SF-DURABLE-FAIL=0,
P97-RELFENCE-WEDGE=0, P35F-STALE-RETRY-EXHAUSTED=0) — the dir-EX→NL release path
(xfs_mxfs_dlm.c ~4409) runs an unbounded durable loop (xfs_log_force SYNC +
xfs_ail_push_ag_sync + mxfs_dir_flush_data_blocks) then a sess99 flush→xfs_buf_stale
loop (500-iter) then shortform durable + inode-cluster quiesce, so at release
every dir block is landed durable AND staled (next acquire = cold read).
- **DIR-STALE-SKIP (30-71×/run) is mostly FALSE POSITIVES**: cold-read fresh
  buffers have b_mxfs_dir_gen=0, trip the gen!=inode_gen compare, but content is
  fresh. Don't chase the count.
- **dirskip=1 REFUTED**: `mxfs_buf_xfsaild_skip_dir_write` tenure-mismatch arm
  false-positives on block→leaf conversion → skips a legit write → barrier
  HANG/wedge, no-result both nodes. The proven sess29 xfsaild-stale-flush CANNOT
  be fixed via dirskip. dir_force_evict already default=1.
- Leading UNPROVEN hypothesis for the residual: **cold-read staleness at the
  storage layer** — a plain bio read after a peer's release returns a transiently
  STALE image (LIO per-initiator read cache / write-propagation window), so the
  acquire cold-read base is stale → RMW stale → xfsaild persists it. Under-tested;
  verify plain-read coherency across initiators directly (caw_verify/fua_verify or
  scratch-LBA write/read). NOTE this partly contradicts the sess30 established
  fact that LIO fileio write-through makes cold-reads coherent — reconcile.

## GPT-5.5 consults (RULE 5) and what they refuted
[[sess30-GPT-NL-refresh-design-and-superset-refuted]]:
- **Write-side SET-SUPERSET discard** at the xfsaild chokepoint (discard write iff
  disk dirent/inumber set ⊋ buffer set): GPT REFUTED as UNSOUND — legit-remove
  resurrection (rm A → buf={B}, disk still {A,B} → discard → A resurrected), and
  the chokepoint discard marks XBF_DONE + xfs_buf_ioend (pulls BLI from AIL) →
  crash before publish loses committed metadata. Inumber sets are insufficient
  identity (hardlink/rename/reuse); leaf (hashval,addr) superset also unsound
  (legit compaction/rebalance is non-superset). DO NOT add an EX-held write-side
  discard; keep the chokepoint detector-only / NL-owner-only.
- **GPT's minimal correct fix = NL-side remote refresh**: refresh the stale cache
  OUTSIDE EX (at NL, before acquiring/reusing EX), reloading the inode mapping
  FIRST. Never reread/evict/wait-pins under EX (extends hold → peer 120s DLM
  timeout rc=-110). Order (mandatory): (1) wait pins — log_force(SYNC) + wait
  inode pincount==0 + dir-buffer pins==0 (safe at NL, no peer blocked); (2)
  reload inode core + data-fork extent map from disk BEFORE any cold-read (else
  block→leaf XDD3-as-XDB3 verifier fail); (3) stale CLEAN cached dir
  DATA/LEAF/FREE buffers (never clear XBF_DONE, never stale a pinned DONE buf).
  Treat ANY peer dir-generation advance as needing refresh (not just the
  DIR_MODIFY heartbeat flag). Implementation point: pre-DLM-request in
  `mxfs_dlm_ilock_begin` (called BEFORE xfs_ilock takes i_rwsem, so holds no
  local ILOCK — confirmed safe), NOT under ILOCK_EXCL.
[[sess31-dirblock-face-all-fixes-present-residual]]: a later GPT consult
confirmed the architecture (DLM EX as coherency token; release-drain log_force
CIL before pin/AIL wait; acquire discard+re-read) but VERDICT: all already
implemented in mxfs. GPT advised AGAINST acquire-side log-force-after-peer-mod
(makes stale image AIL-eligible), 3-way merge of pinned dir buffers (WAL
violation), and clearing XBF_DONE on pinned. Gap is elsewhere.
[[sess31-GPT2-ABA-datainit-detector-next-run]]: GPT-5.5 2nd consult verdict — the
"bounded-100ms-wait-then-SKIP pinned dir buffer" in mxfs_dir_evict_data_blocks /
xfs_da_btree read-refresh is a CORRECTNESS HOLE: a pinned old-epoch dir block
must NOT be used as a modification base (skip → XFS uses stale XBF_DONE → logs+
pins it → xfsaild checkpoints stale = durable revert). Once a stale buffer is
logged into the CIL there is NO safe reconcile (forcing makes it MORE durable) →
prevention before first log-dirty is the only fix. Invariant: "first use of dir
block 0 as a modification base in an EX epoch must use a current-epoch validated
(cold-read or newly-allocated) image, never an old cached/pinned buffer."
[[sess32-GPT2-verdict-handoff-checkpoint-iflush-fence]]: GPT-5.5 #1 gap = dir-grow
BLOCK ALLOCATION modifies the AGF/bnobt/cntbt of an AG coordinated by the
SEPARATE AG-DLM (not inode-DLM); if node B's cached AG free-space is stale, its
dir-grow allocates a block node A already used → xfs_dir3_data_init zeroes A's
committed data block. GPT (c) fallback: extend dir EX release to also flush the
AGF/bnobt buffers for AGs touched by the dir's block allocs — RISK:
xfs_ail_push_all_sync DEADLOCKS (awareness Invariant #1); use targeted per-buffer
bwrite, not whole-AIL push.

## Refuted fixes / dead-ends (DO NOT REPEAT)
- **Acquire-side pin-drain EXTENSION** (mxfs_dir_drain_evict_data_blocks loop
  50→2000 + periodic log_force): REGRESSED to readdir=0/200 + dir3_block_verify
  corruption — forced cold-reads of block 0 while reader's extent-map was stale
  block-format vs disk leaf-format (XDD3-read-as-XDB3). Lesson: reload extent-map
  BEFORE cold-reading. Reverted. ([[sess30-three-faces-FACEC-double-alloc-is-root]])
- **NL-side pin-drain** (log_force+wait dir-buffer pins at pre-DLM-request, no
  evict): did NOT fix A/B; FACE C still fired (proved pre-existing). Reverted.
- **Write-side set-superset discard**: GPT-refuted (above).
- **merge-while-EX** → DLM -110 timeout.
- **publish-at-create** (`mxfs_dlm_publish_inode(du.ip)` in xfs_create): SHUT DOWN
  the FS — xfs_trans_cancel "Corruption of in-memory data" at ~round 6 of
  single-node churn. Reverted (BE10EB0B = single-node CLEAN).
  ([[sess32-reused-dir-dualEX-gap-sync-publish-fix]], [[sess32-GPT2-verdict-handoff-checkpoint-iflush-fence]])
- **Root (a) stale-iflush extent-revert (nx2→1): REFUTED** (sess32) — P32-IFLUSH-
  NXSHRINK fires ONLY on `comm=rm` (legit end-of-round rm -rf, AFTER verify
  already failed); no non-rm flush writes a smaller extent map over a larger one.
- **Intra-dir double-alloc: REFUTED** — P32B-DOUBLEMAP=0 (sess33), sess32
  handoff root (b) dead.
- **P33-DIRGROW-REVERT-SKIP reload guard: NO-OP** (fires 0×) — the
  same-incarnation reload revert it guards does not occur; reverts are reuse via
  gen-gated xfs_iget_recycle, not reload. Harmless, candidate revert.
- **Per-alloc on-disk di_magic check (P33-ALLOC-OVER-DISKINODE)**: correct but
  ~19k sync reads holding AGF → 300s timeout (RULE 0). Reverted; need a cheap
  variant.

## sess32 PROVEN reframe — AG free-space double-alloc on cross-node dir grow
[[sess32-reused-dir-dualEX-gap-sync-publish-fix]] (supersedes earlier sess32
notes): at the clobber the growing node's fork is legitimately adding lblk 1
(incore_size=8192 nx=2), and the daddr the allocator returns (e.g. 25118768,
2093304) ALREADY holds a live committed dirent (P31E `first_name="node2_f50.md5"`
or the PEER's `node1_f50.md5`) → xfs_dir3_data_init zeroes it → dirents vanish
from the DATA block but remain in LEAF → readdir lists, lookup ENOENTs
(P26-DSCAN-MISS=93 on test2). **Single-node is CLEAN** (`tests/drc_single_node.sh
test1` = 0/12 short) ⇒ the free-space staleness is CROSS-NODE (AG bnobt/cntbt
coherency), exercised only when both nodes alloc/free in shared AGs under reuse.
CAVEAT: **P31E-DATAINIT-ABA is AMBIGUOUS** — it also fires benignly (test1
first_name="." = sf→block reuse of a prior incarnation's `.`/`..` at the reused
daddr, readdir stays 100); only cases with REAL names (node{1,2}_f*) are true
clobbers. NOT reload-stale (P34D-RELOAD-FRESHSRC correct, P133-DINO-READSTALE=0).

## The two highest-value NEXT moves (sess33 plan)
[[sess33-NEXT-action-plan-cheap-decisive-and-AG-separation-fix]]:
- **MOVE 1 (zero hot-path cost, decisive M1 test)**: let the test CORRUPT
  (~1/3 runs), then `tools/chk_mxfs -v /dev/sda` on the frozen on-disk image.
  Block owned by BOTH inobt chunk AND a file/dir extent → M1 cross-node
  allocator double-alloc confirmed → fix AG free-space coherency (verify the
  inode-CHUNK alloc takes the SAME AG-DLM path as data alloc, and
  mxfs_dlm_ag_drain_meta_buffers runs for the RECLAIM/evict release path
  mxfs_dlm_evict). bnobt/inobt consistent but a file extent points into an inode
  chunk → M2. (Executed in sess33: btrees consistent, no double-alloc flagged →
  favors M2; but chk_mxfs lacks a cross-map so M1 not excluded.)
- **MOVE 2 (structural fix, addresses ALL faces)**: per-node AG affinity for
  SHARED-dir file allocations. ROOT ENABLER: the test's files get inodes+data in
  the SHARED dir's AG (XFS locality) → BOTH nodes hammer the SAME AG concurrently
  → AG-affinity (preferred_ag = slot%agcount) is DEFEATED for shared-dir
  children. Override the inode/bmap alloc target (xfs_dialloc / xfs_bmap_btalloc
  start-AG) to the node's slot-preferred AG when the parent dir is SHARED
  (multi-node, !self_created), not XFS_INO_TO_AGNO(parent) → the two nodes never
  contend on one AG's free-space. Most likely path to actually CONVERGE the
  criterion vs 30+ sessions of per-buffer coherency patches. Risk: changes
  layout; verify single-node + other tests + ENOSPC fallback.
Also owed: a CHEAP cross-node M1 check (per-AG ring of daddrs THIS node freed this
round via xfs_free_extent/xfs_bunmapi, cross-ref at alloc; or check only the
cluster-START block once per alloc + ratelimit); an M2 fix making the dir reload
fire reliably WITHOUT the flaky MXFS_IF_DIR_RELOAD heartbeat (arm on
i_dlm_dir_gen advance, or unconditional reload for shared dir on modify/lookup);
and the sess30 EVICT-ON-FREE candidate — on xfs_free_extent/xfs_bunmapi,
xfs_buf_stale any cached buffer at the freed daddr cluster-wide so no stale
buffer/extent survives reuse (sound: a freed block's cached buffer is dead).

## Instrumentation & infra lessons (recurring failure modes)
- **dmesg ring buffer WRAPS during a 24-round run** ([[sess33-dirreuse-faces-and-instrumentation-lessons]]).
  A CAPPED probe (`atomic_inc<=N`) fires only on the FIRST N events = early =
  WRAPPED OUT by collection → reads "0 fires" even though it ran. ALWAYS use
  `pr_warn_ratelimited` (DEFINE_RATELIMIT_STATE), NOT a one-shot atomic cap.
  P31E/FROMDISK (fire throughout) survived; P33-ENTER/DSCAN-ONDISK (capped)
  read 0. Cost ~4 build/run cycles.
- **instr=1 is 100× slower and HIDES the race** — run dir_reuse WITHOUT
  instr/dirwr modargs to preserve it ([[sess30-ready-detector-build-and-next-run]]).
- **RULE 0 timeout trap**: per-alloc disk reads time out the test → REVERTED.
  Prefer zero-hot-path chk_mxfs on frozen image over kernel per-alloc probes.
- **EXTREME run-to-run variance**: each run a DIFFERENT face
  (data-over-inode-cluster 0xc40 shutdown / dir3_block_verify 0x78 shutdown /
  lookup_fail stale-leaf / readdir-short 181/200 / hang no-result), and WHICH
  node fails flips. Run the SAME build 3-5× before concluding a fix worked or a
  theory is refuted.
- **The ONLY reliable failure signal** is `criteria.json .runs["2/tcp"].reason`
  (e.g. `round=17 readdir=200/200 lookup_fail=8 missing=[node1_f43.md5..f50.md5]`).
  The per-name P26-DSCAN-MISS dmesg count includes WRITE/md5-phase noise — ignore
  it. NO P26-DSCAN-MISS + P22-DATASCAN-HIT=0 ⇒ lookup errored before the datascan
  fallback (FS degraded / leaf read err), not a plain hash-miss.
- **tests/reset2.sh before EVERY run** ([[sess33-dirreuse-faces-and-instrumentation-lessons]]):
  the leftover mxfs mount WEDGES on unmount (xfs-reclaim kworker + umount in
  D-state, refcnt=1, won't rmmod); prep's mkfs reformat self-fences a still-mounted
  node (P131-SELF-FENCE fs_uuid mismatch). Only a VM reboot recovers —
  virsh-destroy+start both VMs (host clyde reboot is BANNED per RULE 2, VM reboot
  fine). tests/reboot_cluster.sh 2 is the sess30-era equivalent. On-disk
  corruption persists across VM reboot; chk_mxfs needs the FS unmounted
  (`umount -l` works on a shut-down/frozen FS). Device is /dev/sda; tools/chk_mxfs
  is NFS-visible at /src/mxfs/tools.
- Prior AG-free-space double-alloc fixes to reuse: sess42 (`C6970FF9`,
  b_mxfs_ag_gen advance only when genuinely fresh), sess43 (`BB54A138`, in-AIL
  AG-meta must NOT be discarded), sess47 (stale cached inode inactivation),
  sess24. This dir-block-grow double-alloc may be an uncovered case of that
  family on TCP.

## Build progression
- **AB435ACC** — sess30 clean baseline (all sess30 experiments reverted); all 3
  faces reproduce.
- **01E60C6E** — sess30 relay = AB435ACC + un-gated capped P-DBLALLOC detector
  only (log-only, xfs_alloc.c ~4214). ([[sess30-ready-detector-build-and-next-run]])
- **5E706CBF** — sess31 FACE B fix (P116 grant-held discriminator), KEEP,
  regression-free.
- **63035077** — sess31 relay = 5E706CBF + P31E-DATAINIT-ABA detector
  (xfs_dir2_data.c xfs_dir3_data_init ~740, log-only capped 800).
- **BE10EB0B** — sess32 publish-at-create REVERTED, single-node CLEAN.
- **7408B4DF** — sess32 build with P31E first_name detector (KEEP detectors,
  log-only), FS healthy.
- **125DD68A → DBD3A375** — sess33 head; log-only probes P33-DSCAN-ONDISK
  (xfs_dir2_leaf.c, ratelimited), P33-FROMDISK/TODISK-DIRSHRINK (xfs_inode_buf.c),
  P33-DIRGROW-REVERT-SKIP (xfs_mxfs_dlm.c, NO-OP fires 0×). alloc.c probe reverted.
  Tree CLEAN/BUILDABLE.

## KEEP detectors (log-only) across these sessions
P116 grant-held (the FIX, 5E706CBF); P31-FACEA (xfs_dir2_readdir.c); P31B-RELOAD-BUF
(xfs_mxfs_dlm.c); P31E-DATAINIT-ABA (xfs_dir2_data.c, ambiguous — only
node{1,2}_f* names are true clobbers); P32-IFLUSH-NXSHRINK (harmless);
P33-DSCAN-ONDISK / P33-FROMDISK/TODISK-DIRSHRINK.

## Tools
scripts/drc_parse.sh (per-round A/B/C summary); tests/suite/dir_reuse_coherency.sh;
tests/drc_single_node.sh (fast single-writer regression guard, must stay CLEAN);
tests/reset2.sh / tests/reboot_cluster.sh 2 (VM reboot before every run);
tools/chk_mxfs -v /dev/sda (frozen-image fsck, decisive M1 test).
