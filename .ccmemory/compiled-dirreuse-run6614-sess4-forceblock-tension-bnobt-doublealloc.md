---
name: compiled-dirreuse-run6614-sess4-forceblock-tension-bnobt-doublealloc
description: sess4/run6614: force_block tension = committed-undestaged dir-block0 evicted (not bnobt); config settled force_block=0, 2/tcp 17/17.
metadata:
  type: project
tags: [compiled, ccloop, run6614, sess4, cache_coherency, dir_reuse, force_block, bnobt, dir-block, tcp, cache-coherency]
---

## sess4 (ccloop run 6614aa96) — the force_block tension, its true root, and the config decision

Central topic: a single cross-node dir-block bug drives the `mxfs_dir_force_block`
config tension. Both hard ship tests fail on the same block0 read → verify → shutdown
path. This article traces sess4's build progression from "bare defaults win" through
"it's bnobt double-alloc" to the PROVEN mechanism: a committed but **undestaged** dir
block0 whose BLI is retired without the bio ever landing on disk, then LRU-purged and
cold-read as 0xFF. Criterion NOT met; marker NOT written.

### The tension (measured, build 75F2759C = probes only)
- `force_block=0`: cache_coherency PASSES deterministically (dirs stay shortform, no
  block alloc → bug hidden); dir_reuse_coherency flaky at 4/8 under sf→block churn
  (`xfs_dir_create_child -117`, `xfs_ifree -117` inobt double-free).
- `force_block=1` (tree DEFAULT, sess67, `xfs/xfs_mxfs_dlm.c:6607`): dir_reuse reliable
  (forces block-format dirs) but cache_coherency **deterministically FAILS 0/N at 2 AND
  4 nodes** (~34s at 2N, 47–330s at 4N). sess67's fb=1 default REGRESSED sess58's green
  2/tcp. See [[sess4-ccloop-ROOT-forceblock-tension-is-bnobt-dirblock-double-alloc]].

### Chronology of sess4's understanding
1. **3A16A85A (KEY, early)** — bare defaults (`force_block=1` + 4 dir levers=1:
   `dir_release_invalidate/dir_relinval_clean/dir_gen_per_handoff/dir_modify_extent_adopt`
   at `xfs_mxfs_dlm.c:4214,4222,5325,5345`) → `drc_reliability.sh 4 3` dir_reuse 3/3
   PASS. Concluded sess3's `dir_force_block=0` override was HURTING dir_reuse.
   [[sess4-ccloop-KEY-bare-defaults-beat-force_block0-dir_reuse-3of3]]. **This was
   later overturned** by the cache_coherency evidence below.
2. **75F2759C (MILESTONE/ROOT)** — full `dir_force_block=0 run.sh 2 tcp` = **17/17
   PASS** (recovers sess58; all 4 VMs must be up, fence_during_write forces 4 nodes
   internally). But cache_coherency at DEFAULT fb=1 fails 0/2 too. **CONFIG DECISION:
   run the entire criterion at force_block=0** — cache_coherency is in every node-count
   suite and requires fb=0; dir_reuse's fb=1 win can't justify breaking cache_coherency
   everywhere. Column status @fb=0: 1/tcp 13/16 (single-node tooling residuals:
   online_resize, dkms_install stale 88MB dumps in tests/tcp/loss_cap2/ from Jun26,
   fault_io_error), **2/tcp 17/17 GREEN**, 4/tcp 14/17 (dir_reuse 0/4 flaky + 2 cascades:
   fault_netpartition, tcp_dlm_scaling), 8/tcp unrun.
   [[sess4-ccloop-MILESTONE-2tcp-17of17-at-forceblock0-config-decision]]
   [[sess4-ccloop-HANDOFF-full-column-status-and-next-step]]
3. **0FB8EBA3 (UNIFIED/REFINE)** — both tests unified to ONE bug: a dir inode's block0
   maps to a WRONG physical block. Two sub-faces of the read failure
   (`xfs_dir3_block_verify` struct err117 / `_read_verify` CRC err74 →
   `xfs_trans_read_buf_map` shutdown):
   - **owner-mismatch**: valid XDB3 block owned by a DIFFERENT live dir (reader
     4194432 = cache_coherency's fresh sf→block dir; block owner 4194437 =
     rename_visibility, real entries, at daddr 4186568=0x3fe1c8). Stack:
     `mkdir → xfs_dir_lookup_locked → xfs_dir2_block_lookup_int → xfs_dir3_block_read
     → xfs_da_read_buf → read_verify`. Initially read as cross-node **bnobt
     double-allocation** (stale AG free-space on a CACHED/fast-path acquire — the
     sess42/43/46/47 family; `mxfs_ag_dlm_lock` at `xfs_alloc.c:3971,4756` only
     invalidates on a FRESH acquire). REFUTED for this session: disabling
     `dir_release_invalidate=0 dir_relinval_clean=0` does NOT fix it (0/3) — bad map is
     created at ALLOCATION/conversion, not at release-invalidate. `mxfs_dir_conv_genbump`
     ruled out (in-core gen bump can't fix a disk-double-allocated block).
     [[sess4-ccloop-REFINE-owner-mismatch-is-disk-level-bnobt-not-dirgen]]
     [[sess4-ccloop-UNIFIED-bug-corrupt-dir-extent-map-both-tests-same-root]]
   - **CRC-garbage**: `P-BLKRV-CRC daddr=112/120 blkno=<random> owner=<random>` — all-0xFF.
4. **6C7545D5 (REFUTE double-alloc for the garbage face)** — P-DBLALLOC-BIRTH: FUA
   READ(16) read-back at `xfs_dir3_data_init` block0 before init. **foreign hits = 0 on
   both nodes** → the allocator did NOT hand out a block live in another dir. So the
   0xFF/garbage face (daddr 112/120, dominant) is **NOT bnobt double-alloc** — it is a
   cold read of an UNDESTAGED, never-written block0. The two faces are DISTINCT: the
   valid-foreign face (daddr 4186568, owner 4194437) is still unsettled/possibly a stale
   extent map, but the dominant garbage face is undestaged-block.
   [[sess4-ccloop-REFUTE-doublealloc-garbage-face-is-undestaged-unwritten-block]]
5. **C7C10753 (BREAKTHROUGH — proven mechanism + GPT-5.5 consult)** — see next section.

### PROVEN chain (build C7C10753; probes P-DIFREE-*, P-BLKRV-*, P-BLKLK, P-DBLALLOC-BIRTH, P-BLKWR, P-RDPATH, P-DIRSTALE, P-DIRFREE)
1. Multinode dir data BLOCKS are NEVER written by xfsaild (P16-DIRBLK-SUBMIT count=0
   whole run) — by design they destage ONLY via the DLM release-drain on EX
   release/BAST (background write would clobber a peer's dirent).
2. A self-created EX-held dir (fb=1 sf→block, or dir_reuse@fb0 churn) get_buf-inits
   block0 at low daddr 112/120, commits. In-core extent map == disk dinode map, same
   gen (NOT divergent). Disk block content = never written = all-0xFF (thin LUN).
3. P-RDPATH: at T0 block0 buffer is `in_cache=1 DONE=1 in_ail=1 undest=1` (committed-
   unwritten, authoritative in-core). ~1.5ms later same daddr: `inc_rc=-ENOENT` = GONE.
4. P-DIRFREE: the free happens DURING a read — `xfs_buf_read_map→xfs_buf_rele→
   xfs_buf_free`, valid XDB3 content but `has_bli=0` (BLI already retired). =
   `xfs_buf_get_map` PURGES a buffer marked XBF_STALE, re-reads disk → 0xFF →
   `xfs_dir3_block_verify` EFSCORRUPTED → shutdown.
5. P-DIRSTALE (gated undest||in_ail + dir magic) did NOT fire for block0 → at stale time
   it was already `undest=0` (written_seq==logged_seq: FALSELY destaged) AND `in_ail=0`
   (BLI retired). **The undestaged→destaged transition happened WITHOUT a write** —
   release-drain (or mxfs_dir_zombie_push_retire) marked block0 destaged and retired its
   BLI without flushing to disk. **THAT is the root bug** — an MXFS buffer-lifecycle
   violation (Invariant 1). [[sess4-ccloop-BREAKTHROUGH-undestaged-dirblock-evicted-GPT-architecture]]

### GPT-5.5 consult (RULE 5) — architectural fix
- Confirmed: a committed dirty metadata buffer with a BLI in the AIL must NOT be
  reclaimable before its home-block write completes; `b_lru_ref` is not the correctness
  primitive — need a real buffer hold. Never retire/stale/clean the BLI of an
  undestaged dir buffer until its home-block write completes.
- **Option B (soundest)**: allow xfsaild/AIL writeback of dir blocks WHILE the node owns
  the current EX epoch (no peer can modify under our EX), and make DLM release-drain WAIT
  for all in-flight dir writes before unlock. Don't gate on "no BAST pending" — we own
  the epoch until we actually unlock; if a write is in flight when a BAST arrives, the
  drain waits. Keeps disk current so eviction is harmless; preserves Invariant 1.
- **Option A (defensive)**: `xfs_buf_hold()` every dir buffer when it becomes undestaged,
  attach to an inode/epoch list, `xfs_buf_rele()` at release-drain write completion — so
  it can never be LRU/purge-freed while its content is the only copy. Must NOT replace
  BLI/AIL crash-consistency correctness.

### Refuted levers this session (do NOT retry) — build C7C10753
1. `dir_ail_defer=0` — already default 0 (AIL push-defer hook off); not why blocks aren't
   written. No effect.
2. `dir_wseq_at_completion=1` — defers b_mxfs_written_seq stamp to real bio completion.
   Did NOT fix → the false-destage is not (solely) via the submit-time write_seq stamp at
   `pal/xfs_buf.c:4394`.
3. Read-path keep-guard in `xfs_da_btree.c` (keep undestaged blocks regardless of in_ail)
   — INERT, because at the failing read the buffer is already a TRUE cache MISS
   (inc_rc=-ENOENT), not an in-core invalidate. REVERTED.
- Earlier (0FB8EBA3): `dir_release_invalidate=0 dir_relinval_clean=0` does NOT fix
  cache_coherency@fb1 (0/3) — bug is at allocation/conversion, not release-invalidate.
- Earlier (6C7545D5): P-DBLALLOC-BIRTH refutes double-alloc for the garbage face (0
  foreign) — supersedes the disk-level-bnobt reading of the dominant face.
[[sess4-ccloop-REFUTED-levers-and-BLI-retire-is-next-target]]

### NEXT SESSION — the one decisive instrument (GPT-5.5's list)
Probe the BLI-retire / AIL-delete path for block0's daddr (112/120):
`xfs_trans_ail_delete`, `xfs_buf_item_done`, `xfs_buf_item_unpin`,
`xfs_buf_item_release`, and the RELEASE-DRAIN dir flush (`xfs_mxfs_dlm.c ~2409`
`werr=xfs_bwrite(dbp)`, plus the sess37 "missing BLI retirement at release-drain" and
`xfs_buf_stale` immediately after). Find who retires the BLI and bumps written_seq
WITHOUT the bio actually landing on daddr 112/120. STRONG suspect: the release-drain
`xfs_bwrite(dbp)` — does the bio actually target daddr 112/120 (+ `bt_sector_offset`
envelope) or is it skipped/misdirected? Also check the 3rd written_seq site. Then apply
GPT Option A or B, build, and verify.

### Config / state (settled)
- **Run everything at force_block=0** (or flip compiled default 1→0 at
  `xfs/xfs_mxfs_dlm.c:6607` — but VERIFY dir_reuse 4/8 first, it stays flaky at fb=0).
- Final build C7C10753 = probes ONLY; da_btree keep-guard reverted; force_block=0 config
  unchanged. 2/tcp = 17/17 green. 4/tcp 14/17 (blocker = this dir-block bug via dir_reuse
  + 2 cascades). Criterion NOT met, marker NOT written.
- FAST repros: `./run.sh 2 tcp cache_coherency` at DEFAULT fb=1 (mostly-fails ~34s,
  P-BLKRV) · `scripts/drc_reliability.sh 4 5 dir_force_block=0` (dir_reuse ~25–50% fail).
- Tooling in tree (RULE 3): `scripts/ccloop_reset.sh <N>`, `scripts/drc_reliability.sh <N> <RUNS> [modargs]`.
