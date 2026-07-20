---
name: compiled-sess36-37-dir-reuse-datainit-leaf-clobber-bnobt-doublefree
description: Compiled sess34-37: dir_reuse 2/tcp correctness — datainit-clobber refuted benign, real root = stale block0/leaf RMW + bnobt double-FREE from stale b…
metadata:
  type: project
tags: [compiled, dir-reuse, cache-coherency, bnobt, double-free, dir-block, leaf-hash, stale-rmw, inode-reuse, tcp]
---

## dir_reuse_coherency 2/tcp — the last ship blocker (sess34→sess37 compiled)

Criterion: full `./run.sh 2 tcp` = 17/17; `dir_reuse_coherency` is the SOLE failing test. **Timing is
solved** (MHT=300 via `MXFS_EXTRA_MODARGS='inode_mht_ms=300'`, ~280s). Everything below is the
CORRECTNESS face. Marker NOT written through sess37. The test rm-rf's + recreates the shared dir every
round, **recycling inode numbers (#131 dir, 174-181 files) and their block daddrs** — that reuse churn
is the shared root of all failure modes.

### The test is FLAKY across THREE failure faces — all one stale-state-survives-REUSE root
1. **DATA loss**: `readdir` short (182/184/187/188 of 200), `node1_f1..fN` CONTIGUOUS first files gone
   from dir DATA block 0. Both nodes agree → durable on-disk, not read-cache. `lookup_fail=0`.
2. **LEAF-HASH hole** (P21H-LEAFHOLE): `readdir=200` but `lookup_fail=N`, last entries (`node1_f47..50.md5`)
   present in DATA blocks but missing from the LEAF1 hash index (leaf blk=8388608). Both nodes, durable.
3. **bnobt double-FREE SHUTDOWN** — the SEVEREST mode. `Internal error ltbno + ltlen > bno at
   xfs_alloc.c:2254, Caller xfs_free_ag_extent` + EFSBADCRC (err74) at `xfs_trans_read_buf_map` +
   `!(flags & XFS_DABUF_MAP_HOLE_OK) at xfs_da_btree.c:2814` (stale dir extent map → block maps to a
   HOLE) + `xfs_group_free xg_ref!=0`. After it, nodes WEDGE (rmmod fails); recover only via
   `virsh -c qemu:///system destroy+start test1 test2` (test1=dom184, test2=dom185), ~45s.

### Chronology of root-cause characterization

**sess34** ([[sess34-dirreuse-acquire-side-stale-rmw-trylock-skip]], build 327ED8B2): PROVED release
durability is FINE — P34-LEAF-DRAIN showed leaf/data blocks already destaged by xfsaild at release
(P21F-RELFLUSH-LEAF=0). So the loss is an **ACQUIRE-side stale-RMW**, not a release gap. Prime suspect
identified: `xfs_da_read_buf` TRYLOCK-skip (`xfs_buf_incore(...,XBF_TRYLOCK,...)` at
xfs/libxfs/xfs_da_btree.c ~3100) — on -EAGAIN it SKIPS the read-time dir-block invalidation and serves
the STALE cached XBF_DONE buffer → RMW on stale base. Also flagged slowness: P-CONVBLK-DENY=80
(PR→EX conversion deadlocks → EDEADLK → full cross-node handoff per deadlock, dlm/dlm.c:2416).

**sess36 — the P31E "datainit" false root** ([[sess36-PROVEN-datainit-zeroes-live-block0-root]] build
4D56CB92; [[sess36-correctness-aba-dirblock-clobber-fix-plan]] build BC6D7A5E). Believed PROVEN at the
time: `xfs_dir3_data_init` (xfs/libxfs/xfs_dir2_data.c:868/895) ZEROES block 0 (daddr 120) that already
holds 14 live committed dirents. P31E-DATAINIT-ABA detector reads the physical daddr before the init
zeroes it: `disk_magic=0x58444233 (XDB3 block-fmt) disk_owner=131 live_dirents=14 reused=0 stale=0
ex_gseq==dirty_seq(6==6) bast_pend=1 P32B-DOUBLEMAP=0`. P31E is DETECTOR-ONLY → logs then proceeds to
zero. Rounds lost EXACTLY `node1_f1..f12`/`f14`. Callers: `xfs_dir2_sf_to_block+0x1fe` (block 0),
`xfs_dir2_leaf_addname+0x605` (block 1). The sess36 modify-path-evict retry (P36-EVICT-RECOVERED, in
4D56CB92) fired but did NOT fix the loss — KEEP as a real-but-different gap. Flakiness: drc-FAIL across
runs = 0,10,1,1. Higher MHT did NOT fix (fails @ mht300). **This root was overturned in sess37.**

**sess37 — MAJOR COURSE CORRECTION: P31E datainit clobbers are BENIGN**
([[sess37-drc-real-root-is-stale-block0-leaf-RMW-not-datainit]], builds 4734B03F→92F442C7). Added
`caller=%pS` + P31F-BMAP (in-core extent map vs coherent plain-read of on-disk inode). DECISIVE: at
EVERY clobber the on-disk INODE 131 is SHORTFORM/small (`disk_fmt=1 disk_nx=0 disk_size=6`;
`disk_gen==incore_gen`) → the zeroed block is a **prior-incarnation freed-block leftover** (freed dir
blocks keep old dirent bytes, never zeroed), NOT part of the current durable dir. The test PASSED once
with 31 P31E fires → benign. Recurring `first_name="node2_f50.md5"`/`live_dirents=16` are leftover
bytes. P31E/P31F now GATED behind `mxfs_instr_enabled` — their synchronous plain-reads PERTURB timing
and MASK the race (heisenbug: extra latency flips PASS).

### What sess37 PROVED and what it REFUTED (RULE 4 step 2a — do NOT re-chase)
REFUTED:
- P31E/P31F datainit clobbers harmful → benign prior-incarnation reuse.
- Read-hook bounded `cond_resched()` retry on -EAGAIN (xfs_da_btree.c ~3101): P34R-RETRY-OK=0 (never
  recovered) AND the hook is gated `!owned_ex` = NON-modify (lookup/readdir) path anyway → WRONG PATH,
  REVERTED. Buffer is held PERSISTENTLY the whole window (self delwri/AIL writeback of the stale block).
- Stale in-core BMAP at modify: P37-STALEBMAP-MODIFY fired 0× (reload refreshes bmap; loss is a CONTENT
  RMW with a CORRECT bmap).
- Evict KEEPS stale undestaged block-0 (FACE A candidate): P37D-KEPT-STALE-DATA=0 (in-core always ≥ disk).
- Allocator double-ALLOC over inode: P55-ALLOC-OVER-DISKINODE=0 and P55-ALLOC-OVER-CACHEDINODE=0
  (confirms sess55; the allocator never hands a DATA request a live-inode-cluster block).
- Modify-path evict does NOT fail on locks (P36-EVICT-LOCKED=0; its 25×msleep retry works).
- Medium is COHERENT under EX hold (sess69, differs=0) — NOT a storage/FUA durability bug for 2/tcp
  (LIO write-through target).

PROVEN — the two real roots:
- **Data/leaf loss = stale cached block-0/leaf-block RMW lost-update.** P34-TRYLOCK-STALE fired 64×/29×
  on blk=0 (daddr 120/112) AND blk=8388608 (leaf). An RMW on a stale-served base durably erases the
  peer's committed dirents (first-N) or leaf-hash entries (f47-50.md5).
- **The shutdown is a stale-bmap double-FREE, NOT a double-ALLOC**
  ([[sess37-bnobt-is-doubleFREE-stale-bmap-not-doublealloc]], baseline A695EC5C). P15-INSTR at
  xfs_alloc.c:2254 captured: `FREE-AG-EXTENT-FAIL-LEFT agno=1 bno=297 len=1 ltbno=248 ltlen=261405
  agf_freeblks=261628` — left free extent [248,261653) ALREADY covers 297 → freeing an already-free
  block = DOUBLE-FREE, during rm-rf inactivation (P25 sync-inactive-DONE ino 174-181). This is the
  **M2 class**: a STALE in-core EXTENT MAP under inode/daddr REUSE. A RECYCLED inode retains a stale
  in-core bmap (reuse path doesn't fully reset the data fork) → inactivation double-frees the prior
  incarnation's blocks (bnobt double-free) OR a data write hits a reused daddr (inode-cluster clobber,
  daddr 0xc00). Both symptoms are one M2 root, not an allocator bug.

### Fixes attempted / landed in sess37
- **B5 inactivation TOCTOU fix** (`mxfs_b5_nolock`, xfs_inode.c ~2960) — dropped the
  `!mxfs_local_unlink` requirement. Rationale: `MXFS_IF_LOCAL_UNLINK` LEAKS across inode-number reuse
  (set when this node unlinked the prior incarnation, never cleared because the stale copy wasn't
  reloaded), so old B5 fell through, the racy mutex-less disk read at CHECK saw the inode still
  gen-G/live, peer freed+reused in the post-check window → double-free. NEW B5: when EX acquire FAILED
  and we don't hold EX (outside log recovery), SKIP regardless of local_unlink. SAFE because a node's
  OWN live files acquire EX cleanly (`mxfs_inact_dlm_locked=true`) so B5 only fires when a PEER holds
  EX = the stale-copy case that must skip. Landed in builds 658CCD35, then 1A5116E4 (+ P15 free-caller
  instr `caller=%pS caller2=%pS`).
  - **B5 is INERT for dir_reuse**: `INACT-SKIP-STALE=0` across 5 runs (the EX acquire for the
    inactivating inode always succeeded, so `!mxfs_inact_dlm_locked` was never true on the failing
    path). A shutdown STILL occurred with B5 not firing → **the P47-INACT `inact_ino=2099107` global
    (mxfs_dbg_inactive_ino) is likely STALE**; the block-297 free almost certainly comes from a
    DIFFERENT caller (a dir-block free during rm-rf, or a bmap/bunmapi path). KEEP B5 as a documented
    low-risk candidate OR revert for a clean baseline — next-session call after full-suite validation.
    ([[sess37-CLOSE-build-1A5116E4-shutdown-caller-instr-ready]], [[sess37-B5-toctou-fix-landed-dir-faces-remain]].)
- **Leaf rebuild exists but DISABLED** (`mxfs_dir_leaf_rebuild` module_param, default 0, xfs_mxfs_dlm.c
  ~2029). Gates `mxfs_dir_rebuild_leaf_from_data` (xfs_dir2_leaf.c:615 / consumer xfs_dir2.c:564),
  armed once-per-tenure via MXFS_IF_DIR_LEAF_STALE. The evict KEEPS an undurable (in-AIL-undestaged)
  stale leaf (P21S-EVICTSKIP-LEAF 375-1200×) → durable leaf-hash hole. Enabling `dir_leaf_rebuild=1`
  RAN it (P26-REBUILD-OK 400×, fills holes) BUT tripped a SHUTDOWN: `xfs_inode_buf_verify` block 0xc00
  (50×) + metadata I/O err117 (15×) + P117-AGMETA-STALE-CLEAN agno=1 bnobt (3×) + P33 fail-bnobt-snap.
  The rebuild's leaf growth ALLOCATES a block that double-allocs onto an inode cluster — it EXPOSES the
  latent AG free-space double-alloc, not its own bug. Chicken-and-egg: leaf merge needs the
  AG/free-space coherency fixed FIRST. B5+rebuild=1 → readdir=0 ×39 (not B5-fixable).
  ([[sess37-leaf-rebuild-off-and-AG-freespace-doublealloc-root]], [[sess37-NEXT-action-plan-dir-evict-keepguard-and-leafrebuild]].)

### Build markers
327ED8B2 (sess34 P34 probes) → 4734B03F/92F442C7 (sess37 P31E/P31F instr + reverted retry) →
4D56CB92 / BC6D7A5E / D11B791A / 7D7CBC37 (sess36 datainit-era) → **A695EC5C** (sess37 clean baseline,
P15/P31E/P31F/P37 gated behind mxfs.instr, read-hook retry reverted) → 658CCD35 (+B5) → **1A5116E4**
(B5 + P15 free-caller instr) → **3BDA8147** (clean diagnostic baseline, session-end). All "clean
baseline" builds are functionally identical — diagnostics only, no functional change/regression.

### NEXT-session decisive steps (converged plan)
1. **Instrument the bnobt double-FREE directly** — the severest mode and the shared AG root. Clean the
   dmesg ring first (`dmesg -C` OR virsh destroy+start — the ring PERSISTS across mkfs/remount and
   drc_cap2.sh streams the WHOLE ring → PRE-RUN RESIDUE causes false shutdown/stale-P47 readings). Run
   `MXFS_EXTRA_MODARGS='inode_mht_ms=300' bash tests/drc_cap2.sh` REPEATEDLY (~1-in-3..6 flaky) until a
   shutdown, grep `FREE-AG-EXTENT-FAIL.*caller=` to pin whether the stale free is dir-inode bmap
   (rm-rf dir shrink) or a file inode. Cross-ref P102-ACQ (fresh vs cached/nested/reclaim acquire),
   P117-AGMETA-STALE-CLEAN, pag_dlm_meta_gen freeze.
2. **Likely fix loci**: (a) inode-reuse fork-reset — `xfs_iget_recycle`/`xfs_init_new_inode` must
   `xfs_idestroy_fork` + rebuild the data fork from the fresh on-disk dinode, not inherit the prior
   incarnation's bmap; (b) defensive inactivation guard — skip freeing an extent the bnobt says is
   already free (lower-risk, directly stops the shutdown); (c) AG-meta coherency at AG-EX slow-path
   acquire — force AGF + bnobt/cntbt roots FUA-reread/evict so the allocator never works off a stale
   free-space view. NOTE sess118 reverted generalizing the fresh-discard to AGF/AGI/inobt (pagf/pagi
   desync) — must reset pagf/pagi CONSISTENTLY.
3. **Data/leaf loss fix at EX ACQUIRE, not at read**: force-invalidate ALL the dir's cached DATA+LEAF
   blocks at slow-path acquire (blocking documented-safe per sess97, no concurrent self-modify). The
   eager evict `mxfs_dir_drain_evict_data_blocks` (xfs_mxfs_dlm.c ~3198) uses TRYLOCK + CLEAN-only +
   LACKS the ABA bypass that the read-hook has (owner_aba via `mxfs_dir_data_buf_owner_mismatch`,
   incarn_aba via `b_mxfs_dir_incarn != VFS_I(dp)->i_generation`), so it skips the stale block-0/leaf.
   Mirror the AG-meta sess117/120 fix (`mxfs_ag_meta_coldread_discard(pag,true)` discards in-AIL
   bnobt/cntbt UNCONDITIONALLY on the genuine fresh-from-peer path): on genuine fresh-from-peer dir
   acquire discard even "undestaged" dir DATA blocks unconditionally (Invariant 1 drained our work at
   release → disk is a superset). KEEP the sess64 PINNED-buf pin guard (re-reading a pinned buf → shutdown).
4. THEN enable `dir_leaf_rebuild=1` for the leaf-hash face — OR run the rebuild on the LOOKUP/verify
   path so a holey durable leaf self-heals on read.

### Validation bar & tooling
Need ≥3 consecutive clean PASS with instr OFF (true-speed; instr masks the race) before trusting, then
full `./run.sh 2 tcp` = 17/17. `tests/drc_cap2.sh` (instr off) → analyze via `python3
tests/drc_analyze.py /tmp/t1.log /tmp/t2.log` (slice off the pre-run ring using the stream-start
`lines=NNNN`). Markers to grep: drc-FAIL, drc-RDMISS, readdir=0 (shutdown), P34-TRYLOCK-STALE,
P21H-LEAFHOLE, P21S-EVICTSKIP-LEAF, P47-INACT, INACT-SKIP-STALE (B5), P117-AGMETA-STALE-CLEAN,
FREE-AG-EXTENT-FAIL...caller=, xfs_inode_buf_verify, P33. Reset nodes between runs after any shutdown
(umount -l + rmmod does NOT recover a shut-down FS → virsh destroy+start required).

Related prior fixes on the inode-reuse family (context, not to re-derive): sess103 (gate size-drop-skip
on di_gen), sess47 (skip inactivation of STALE cached inode via di_mode/di_gen), sess19 (clear
MXFS_IF_LOCAL_UNLINK on reload), sess40 (IRECLAIMABLE reused-inode iget). This is the 37-session
"Mode A / bnobt" AG free-space corruption family, now correctly re-characterized as a stale-bmap
double-FREE under inode/daddr reuse rather than an allocator double-alloc.
