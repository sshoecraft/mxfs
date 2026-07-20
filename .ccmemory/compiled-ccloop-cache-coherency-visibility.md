---
name: compiled-ccloop-cache-coherency-visibility
description: Compiled ccloop cache_coherency thread: reused-inode stale cache, durable-before-visible, mkdir-race, shortform lost-update, xfsaild deadlocks → 4/4…
metadata:
  type: project
tags: [compiled, cache_coherency, ccloop, inode-coherency, xfsaild, dlm, shortform-dir, ship-gate]
---

# ccloop cache_coherency — the 4-subtest visibility thread (compiled)

> **RESOLVED — `cache_coherency` was fixed at sess130 (build `5EDDFF58`); as of 2026-07-08
> all 17/17 criteria PASS at ≤8 nodes, both CAW and TCP. The "current blocker" framing below
> is dated/historical.**

This thread's single ship-blocker WAS the **`cache_coherency` criterion**
(`tests/criteria/cache_coherency.sh --nodes 4`), then the last failing entry of 12 recorded
criteria (other 11/12 PASS the entire time). Four subtests, all shared-LUN 4-node
(test1–test4, `MXFS_NODE_OFFSET=0`; note `cache_coherency.sh` hardcodes OFFSET=16 for
test17-32, so subtests were run with OFFSET override):

- **cross_visibility** — peer sees a just-created file/dir.
- **rename_visibility** — concurrent renames converge; content preserved.
- **unlink_visibility** — 4 nodes each create 30 files into a shared dir, barrier, list (expect 120), delete own.
- **cross_write_read** — each node writes 1MB `data_nodeN` + tiny `data_nodeN.md5`, barrier, peers read+verify md5.

**End state: 4/4 PASS at build `CA701441` (sess [[sess128-root-fix-phantom-ex-rearm-unpublished]]).**
Marker still NOT written at that point — full `verify_ship.sh` end-to-end plus the never-recorded
criteria (posix_semantics 1+16 nodes, strong_consistency, zero_silent_loss, crash_consistency,
fence_during_write, scaling_curve/16-node) remain; 16-node criteria need test1–test16 (`lib.sh`
DEFAULT_NODES = test1-16); deploy `CA701441` everywhere first.

## The one recurring root family: reused-inode / new-inode coherency
Nearly every failure in this thread reduces to **a node serving or writing an inode incarnation that
disagrees with the durable on-disk image**, in one of these forms:
1. **Reused-inode stale cache-HIT** — after rm+realloc a node keeps a stale FREED incarnation
   (incore mode=0, gen=disk_gen+1) and serves it → readdir 0 entries, create/rm ENOENT.
2. **New-inode durable-before-visible** — creator commits dirent+child dinode in one txn; parent-dir
   BAST-release flushes the PARENT durable but the new CHILD dinode sits in the creator's AIL; under
   CAW a peer's cold read never BASTs the creator → peer reads a FREE dinode.
3. **xfsaild write-side resurrection** — xfsaild's `xfs_iflush` copies a live in-core inode over a
   peer-FREED on-disk dinode (or the reverse: flushes a freed in-core ghost over a live disk inode),
   corrupting inobt/finobt or zeroing di_size.
4. **Shortform-parent lost-update / invisibility** — new dirent lives inline in the parent's dinode
   (shortform fork); flush paths that only touch DATA-fork blocks are no-ops → parent cluster never
   destaged → peers ENOENT the new child.

di_gen / di_size comparisons are **NOT valid coherency signals** (repeatedly refuted): XFS stamps a
random per-chunk gen at `xfs_ialloc_inode_init` then re-prandoms per alloc, and freed vs legit-delete
signatures are mathematically identical. The durable fixes all key off **DLM lock-lineage / tenure
state**, not gen.

## Build progression (hash → session → what it did)
Two numbering schemes overlap in the same ccloop run `4eef1f39` (per-run "sNN" count and global
"sessNNN"); the build hashes give the real order.

- `6B8A19F5` — [[sess13_ccloop_lessons]]: shortform-PARENT new-child invisibility FIXED. Proactive
  `mxfs_dlm_dir_inode_durable(dp)` (xfs_mxfs_dlm.c ~482, reuses sess85 `mxfs_inode_cluster_durable`:
  log_force→imap_to_bp→iflush_cluster→bwrite→blkdev_flush), called from `xfs_create` AFTER
  `xfs_iunlock(dp)` (must be ILOCK-free), **gated to `S_ISDIR` (mkdir only)** — the ungated variant
  (`F260DFCC`) caused per-create log_force(SYNC) storms → CAW EX starvation → -110 ETIMEDOUT shutdown.
  Decisive prover: `tests/diag_uv.sh` `DROP_ON=creator` → all peer creates succeed (proves creator-side
  durability). Refuted sess120's "block-format dir-data lost-update" framing.
- `5E2660AC` — [[sess114_lessons]]: drain-wedge TRUE ROOT = **xfsaild NULL-deref oops** in
  `xfs_iflush_fork` FMT_LOCAL memcpy (if_data==NULL, if_bytes=6) mid-push, dies holding ino-cluster
  buf lock → IFLUSHING stuck → BAST drain waits forever → SIGKILL@900s. Cause: `mxfs_dlm_reload_inode`
  reloads a live dirty inode to a peer's mode=0 free image; `xfs_inode_from_disk` early-returns SUCCESS
  on mode=0 WITHOUT reformatting the fork, leaving `xfs_idestroy_fork`'s torn state (format=LOCAL,
  if_bytes>0, if_data=NULL). Fix: after `from_disk` success on a mode=0 reload, reset data fork to
  canonical-empty (EXTENTS, if_data=NULL, if_bytes=0). Refuted sess113 merge_dirs/FUA theory.
- `1853FF8F` — [[sess115_lessons]]: drain-wedge (the OTHER half) = create-path flush **leaks
  IFLUSHING** via manual `xfs_bwrite` on an alloc-buflist-trapped SHARED cluster. Gemini root: bwrite
  clears `_XBF_DELWRI_Q` but not `list_del(&b_list)`; a fresh child sharing the parent's 4KiB cluster
  was queued on `pag_mxfs_alloc_buflist` (`_XBF_DELWRI_Q|_XBF_MXFS_ALLOC_QUEUED`) → orphaned sibling
  IFLUSHING. Fix in `mxfs_inode_cluster_durable`: never manual bwrite; if trapped on alloc-buflist →
  relse + `mxfs_dlm_ag_drain_alloc_buflist`, else native `xfs_buf_delwri_queue`+`_submit` (iodone
  clears IFLUSHING). A/B PROVEN: WITH create-path flush unlink=1 fail but wedge; WITHOUT, wedge=0 but
  unlink regresses 1→30 — so the flush is NECESSARY for durability, the LEAK is the wedge. Also proved
  the root inode cluster (ino=128, `/mnt/shared`) genuinely never destaged (FUA fua_cnt=0, di_gen=0).
- `9F289917` (VERIFIED 2/4) → `92CE435D` — [[sess16_ccloop_xfsaild_deadlock_fix]]: **xfsaild
  self-deadlock FIXED** → cross_visibility + rename_visibility PASS. Root = accounting asymmetry:
  `xfs_ilock_nowait(ILOCK_SHARED)` skips MXFS DLM for ILOCK (atomic ctx, no holder ref) but
  `xfs_iunlock` unconditionally runs `mxfs_dlm_ilock_end`→inline `bast_process` drain that waits on the
  very cluster buffer xfsaild holds. Fix: 3× `xfs_iunlock(ip,ILOCK_SHARED)` in `xfs_iflush_cluster`
  → raw `up_read(&ip->i_lock)`. P113=0 everywhere. `92CE435D` adds cross_write_read `.md5` fix:
  `filemap_write_and_wait` for S_ISREG at top of reg/dir durable block (dirty DATA PAGES weren't
  flushed, only the cluster).
- `7BBF740C` → `C3B5DFE4` — [[sess17-ccloop-relflush-sidecar-fix]]: **cross_write_read `.md5` sidecar
  empty-read FIXED & VERIFIED 4/4 on a clean cluster.** Root: `bast_process` set `i_dlm_mode=NL`
  BEFORE the reg-durable di_size flush → sess119 P119 guard skipped writing di_size → peer FUA-read
  di_size=0 → empty. Fix: per-inode iflag `MXFS_IF_DLM_RELFLUSH (1U<<18)`; bast_process sets it around
  the reg-durable iflush loop, P119 guard adds `&& !RELFLUSH`. `C3B5DFE4` (built, untested) adds a
  Gemini DLM-**epoch lineage guard** for rename_visibility flaky empty-content (bidirectional
  inode-reuse ghost, BOTH dlm_mode=EX so P119 misses): new `i_mxfs_ex_grant_seq` + `i_mxfs_dirty_seq`,
  global `atomic64 mxfs_ex_epoch`; stamp grant_seq on every transition INTO EX, dirty_seq in
  `xfs_trans_log_inode`; guard in `xfs_iflush_int`: dirty_seq != ex_grant_seq → skip (P17B-EPOCH-GHOST-SKIP).
- `86420BFE` (3/4) — [[sess116-lessons]]: two KEEP fixes. (a) **bast NULL-deref unmount crash** — pending
  inode bast work holds an irele, inode survives unmount, work fires after `m_log` freed → NULL
  `l_icloglock` → dedicated per-mount wq `m_mxfs_inode_bast_wq`, `flush_workqueue` in `xfs_fs_put_super`
  before DLM shutdown, plus `!mp->m_log || xfs_is_unmounting` guard. (b) **Inode SELF-CLOBBER on
  reused-ino create** — reload of an ino REUSED by rm+mkdir reads on-disk cluster still FREE (di_mode=0,
  create only logged) → clobbers fresh in-core dir to mode=0; existing `di_format==0` skip misses it
  because reused cluster keeps prior nonzero di_format. Fix in `mxfs_dlm_reload_inode` (~2751): on-disk
  `di_mode&S_IFMT==0` but in-core `!=0` AND in-core dirty (pincount/ili_fields/LI_IN_AIL) → skip reload
  (P116-RELOAD-SELFCLOBBER-SKIP). Remaining fail = cross_write_read (node1's `.md5` read empty by peers).
- `DF34891E` (untested) — [[sess118_lessons]]: sess117 AG-meta hard-barrier **REFUTED** (evicting all
  AG-meta on release desyncs agf_freeblks/btree-root cache → reintroduced bnobt double-free +129s
  rename; Gemini rule: evict on ACQUIRE not release; acquire-side `mxfs_dlm_invalidate_ag_meta` already
  covers all AG-meta). PROVEN corruption root = **inode RESURRECTION at xfs_iflush**: xfsaild copies a
  live in-core inode over a peer-FREED dinode → dialloc badmagic -117 → shutdown → peers hang barrier →
  timeout. Fix: `MXFS_IF_FIRST_FLUSH (1U<<17)` set in `xfs_iget_cache_miss` on XFS_IGET_CREATE, cleared
  on first flush; `xfs_iflush` skips content copy iff multi-node + valid magic + !FIRST_FLUSH + !INEW +
  disk_gen!=incore_gen. The flag makes gen-compare reliable ONLY after our own first flush (gen is
  random for new inodes — all bare-gen discriminators false-positive on new-inode first flush).
- `C69013B3` — [[sess119_lessons]]: **iflush→DLM-EX discriminator (KEEP, corruption gone)** —
  resurrection guard skips disk copy iff `ip->i_dlm_mode != MXFS_LOCK_EX` (replaces gen compare); 0
  shutdowns. ROOT re-proven = **concurrent same-name mkdir cross-node TOCTOU on a SHORTFORM parent**:
  all 4 nodes allocate DISTINCT dir inodes for the same name (4 distinct `.mxfs_test` under root 128),
  losers orphaned → invisible + dangling-dentry EIO. EXACT hole: `xfs_create`'s cross-node EEXIST
  re-check calls `mxfs_dlm_dir_modify_refresh`/`_consumer_refresh` which only `mxfs_dir_evict_data_blocks`
  — a **NO-OP for shortform dirs** (dirents inline in `if_data`). Fix direction: for shortform parents,
  modify-refresh must `mxfs_dlm_reload_inode(dp)` the inode core FUA-fresh (gated multi-node/dir/clean).
  GPT-5.5 design: hold parent dir DLM **EX** across the whole create-intent lookup→mutation (not PR).
- `E9963FFA` — [[sess121-dir-block-lost-update-next]]: bnobt SHUTDOWN fixed (P122 write-side interlock,
  KEEP), which EXPOSED the next blocker: **concurrent block-format dir RMW lost-update** in
  rename_visibility. All 4 nodes RMW the same dir block (`daddr=4174760`, owner ino 4194433) within ms;
  node1's entire 20-rename add-set PERMANENTLY LOST (after=60, should be 80); never converts to leaf (80
  would fit — pure lost-update, exact analog of the bnobt clobber). Dir coherency uses per-inode
  `i_dlm_dir_gen`/per-buffer `b_mxfs_dir_gen` read-invalidation (`xfs_da_read_buf`); like the frozen
  `pag_dlm_meta_gen`, the dir gen isn't bumping / in_ail block not refreshed on EX re-acquire.
- `1F7AF33C` / `C01185FA` (2/4, REGRESSED from sess23's 3/4) — [[sess122-ccloop-RESUME-p110-readside-regression]]
  + [[sess122-ccloop-unlink-3failmodes-agfence-gap]]: on a CLEAN cluster cross_visibility +
  rename_visibility PASS; unlink_visibility FAILs 3 ways (all same root, missing AG-lock fence): (1)
  divergence livelock `P-CAWEXH` all-CAS-counters-ZERO (in-core i_dlm_mode=EX re-adds the bit each
  iteration → -ETIMEDOUT shutdown — refutes sess39 CAS-storm framing); (2) `xfs_defer_finish_noroll`
  corruption in the two-EX-holder window; (3) **P110-BIO-OVER-LOGGED read-side interlock misfires** on a
  legit AGI update during `xfs_inactive_ifree` → Metadata I/O Error → shutdown. P110 has the EXACT flawed
  premise sess23 disproved for the write side ("in-core is always authoritative" is FALSE for a legit AGI
  update). **Fix-first: make P110 LOG-ONLY** (mirror sess23's write-side disable — keep pr_warn, delete
  the `b_error=0;XBF_DONE;ioend;return` action; under fua_disable=1 the plain read hits the coherent SCST
  write-back cache). Architectural directive (user 2026-06-07): the 3-invariant FENCE was applied to
  DIR/INODE locks but NEVER to AG locks (AGI/AGF/AGFL/bnobt/finobt) — substituted by write-side interlocks
  (P110/P122/P124) that now misfire. STOP band-aiding: fix the **frozen `pag_dlm_meta_gen`** so acquire-time
  invalidation fires for AG-meta (sess19b shared on-disk AGF-epoch), then REMOVE the band-aids. High-water
  mark noted: sess23 build `2C16B9C9` = 3/4 (only cross_write_read failing).
- `1371EA35` (still RED) — [[sess125-shortform-parent-dir-lost-update-is-the-root]]: shortform parent
  (ino 131) proven a **RED HERRING** — node1 reloads it fine and keeps it. ROOT = **reused-inode
  stale-cache on the WINNER DIRECTORY inode 4194433**: on-disk = live dir (040755, gen 2861374702);
  node1 CACHED it as a stale FREED incarnation (P-IRESURRECT incore_mode=0, gen=disk_gen+1) → readdir 0
  entries. `mxfs_drevalidate` misses it: positive dentry, same ino → valid=1; the GENMISS/TYPEMISS FUA
  rechecks are GATED on `S_ISDIR(incore mode)`/nonzero ftype, and incore mode==0 skips BOTH. Fix
  directions: (1) drop the S_ISDIR gate for the mode==0 case → unconditional FUA di_gen/di_mode recheck →
  set stale+XFS_ISTALE_CAW; (2) `xfs_iget_cache_hit` force coherent FUA reload of a dir cached mode==0
  while a dirent shows it live. Also KEEP (both no-regression, no effect on this test): modify-time (not
  read-time) tenure stamping in `mxfs_ag_meta_track`; dir-flush reorder after the sess29 settle.
- `104BEBA0` (untested, RED) — [[sess126-mkdir-race-loser-cannot-create-poslx-root]]: TRUE ROOT =
  **mkdir-race LOSER can't create files into the winner dir** (POSIX violation — after `mkdir -p` returns,
  dir must be usable). The 58–90 "missing" files were NEVER CREATED (P-GENCREATE shows losers' creates
  fail in VFS path-walk at the parent component → ENOENT, never reach `xfs_create`). Mechanism:
  d_revalidate's **affine fast-path** blesses any positive own-AG dentry valid with no coordinated
  re-lookup → loser trusts its STALE cached shared parent (missing the peer-winner's child) between
  reloads; the async DIR_MODIFY signal loses the race against the create-loop. Two fixes (Gemini): (1)
  set `dp->i_dlm_stale=true` in the EEXIST loser branch so next path-walk reloads the durable parent; (2)
  DIR dentries skip the affine fast-path (`!S_ISDIR` gate in `mxfs_drevalidate`) → coordinated
  ILOCK_SHARED reload-if-stale; files keep the fast-path.
- `1C7F8320` — [[sess127-root-fix-durable-before-visible-new-inode-iget-coord]]: **unlink_visibility TRUE
  ROOT found + FIXED, PASS in 33s** (was FAIL 132–370s). Deterministic repro `tests/repro_uv_create_race.sh`
  (4 nodes concurrent `mkdir -p` + 30 creates each) reproduced 100%. Decisive: ungated **P-IGET-ENOENT**
  (had been `mxfs_instr`-gated for MANY sessions = multi-session blind spot) fires on all losers with
  `fua_disk_mode=0x0` = winner's new dir dinode reads FREE off the platter. This is the **new-inode
  durable-before-visible** gap: creator commits dirent+child in one txn; parent BAST-release flushes the
  parent (loser sees the dirent) but NOT the child dinode (in creator's AIL); sess44 deferred-publish =
  creator's child-EX is LOCAL (no CAW slot) and `xfs_lookup` igets with lock_flags=0 → loser does NO
  inode-DLM acquire → nothing BASTs the creator to flush → loser reads free dinode → ENOENT for a name
  that exists → downstream `xfs_difree_inobt i!=1` double-free shutdown on all 4 nodes. FIX in
  `xfs_iget_cache_miss` at check_free_state: on `-ENOENT && !tp && !dlm_acquired && !XFS_IGET_CREATE &&
  mode==0 && multi-node` → ONE coordinated `mxfs_dlm_ilock_begin(PR)` + `mxfs_dlm_reload_inode` +
  `ilock_end`, then re-run check_free_state (the PR acquire BASTs the creator whose sess38 writer-flush
  release makes the dinode durable). This is the sess40 "Type-A reuse_dlm" dance relocated to the PROVEN
  cache-MISS site and ungated. Also: **REMOVED sess126's harmful Phase-1** (`i_dlm_stale=true` in EEXIST
  loser reintroduced the sess91 stuck-stale d_revalidate thrash — 8× P-DREVAL-STALEFLAG); KEPT sess126
  Phase-2 (dirs skip affine fast-path). Refuted: "loser's cached parent is stale" (sess126 premise —
  FALSE, EX-reload makes it fresh); PR-storm starvation as root (real but secondary).
- `CA701441` — [[sess128-root-fix-phantom-ex-rearm-unpublished]]: **cache_coherency 4/4 PASS.** Last
  fail was cross_write_read (readers saw a just-created md5 as EMPTY). ROOT = **phantom-EX on reused-inode
  create**: a local CREATE satisfied from the inode CACHE (recycle of an IRECLAIMABLE freed incarnation /
  `mxfs_dlm_reset_inode_for_create`, freed mode==0 hit) keeps the prior incarnation's `i_dlm_mode=EX`,
  `i_dlm_unpublished=false`, but `xfs_inactive`→`mxfs_v5_dlm_inode_unlock` already released the prior
  ON-DISK slot without touching in-core state. So `mxfs_dlm_publish_inode` fast-bails on the clear unpub
  flag → creator runs on a **phantom in-core EX with NO on-disk slot** → peer's acquire of the reused
  number grants CLEAN (empty slot, NO BAST) → creator never flushes the new dinode → peer adopts the
  reused incarnation at not-yet-durable disk_size=0 (P103-RELOAD-REUSE-ADOPT) → cat empty. FIX:
  `mxfs_dlm_rearm_unpublished(ip)` restores the brand-new-inode invariant (creator-exclusive local EX,
  fresh EX epoch, linked on unpub list) WITHOUT touching holder counts, called from `xfs_iget` on every
  cache-hit `XFS_IGET_CREATE` (multi-node). Probes: P128-PUBLISH-BAIL, P128-INACT-EXREL, P128-REARM-UNPUB
  (fired 11× on node1; PUBLISH-BAIL dropped to 0).

## Refuted leads / dead ends (do not revisit)
- Block-format dir-data lost-update as the unlink_visibility root ([[sess13_ccloop_lessons]], corrected
  sess120); the "disk has 120" observation was a create-only+sleep2 variant masking the race.
- sess113 merge_dirs/FUA drain-wedge theory ([[sess114_lessons]]).
- sess117 AG-meta hard-barrier / evict-all-AG-meta-on-release ([[sess118_lessons]] — reintroduced bnobt
  double-free).
- Shortform parent (ino 131) as the unlink root ([[sess125-shortform-parent-dir-lost-update-is-the-root]]
  DISPROVEN — it's the winner DIR inode 4194433 stale-cache).
- "Loser's cached parent dir is stale" / PR-storm starvation as the unlink root
  ([[sess127-root-fix-durable-before-visible-new-inode-iget-coord]] refuted both).
- P110 read-side interlock premise "in-core is always authoritative"
  ([[sess122-ccloop-RESUME-p110-readside-regression]] — same premise sess23 disproved write-side).
- CAS-storm framing of the 100-retry exhaustion ([[sess122-ccloop-unlink-3failmodes-agfence-gap]] —
  P-CAWEXH all-CAS-counters-0 proves it's divergence livelock, not a storm).
- di_gen / di_size / disk_mode==0 as standalone coherency discriminators — all false-positive on
  new-inode first flush; use DLM lock-lineage/epoch/first-flush-flag instead ([[sess118_lessons]],
  [[sess17-ccloop-relflush-sidecar-fix]]).

## Instrumentation / probes worth keeping
P-IGET-ENOENT (UNGATE it — the multi-session blind spot), P-IRESURRECT (xfsaild ghost detector),
P-GENCREATE (does a create reach the FS), P-CAWEXH (per-continue-site counters: distinguishes CAS-storm
vs divergence-livelock vs yield-livelock), P113-DRAIN-WEDGE (must be 0), P-DIRWR (dir-block RMW),
P105-ACQ-DIRINODE, P106-STALE-EX, P128-PUBLISH-BAIL/REARM-UNPUB, P17B-EPOCH-GHOST-SKIP,
P-SFDIR-REVERT FUA fua_cnt. Reproducers (KEEP, in-tree): `tests/repro_uv_create_race.sh`,
`tests/diag_uv.sh` (DROP_ON={creator,peers,all}), `tests/repro_double_alloc.sh`,
`tests/repro_rename_concurrent.sh`, `tests/repro_blockdir_visib.sh`.

## Binding test-infra rules (learned the hard way, every session)
- **ALWAYS full power-cycle ALL 4 (`virsh -c qemu:///system destroy+start`, boot ~50s) then
  `bash tests/reset4.sh 4` (fresh mkfs) before ANY trusted run.** The first run on a stale/old-build or
  contaminated mount gives FALSE failures — cluster contamination flakes runs to 2/4 or shows phantom
  data loss (nodes silently DROP their mount from evict-ring churn, no shutdown/oops). Multiple sessions
  burned 2 runs each ignoring this.
- Run with `INSMOD_OPTS="fua_disable=1 instr=0"`, verify `/sys/module/mxfs/srcversion` matches the build,
  `dmesg -C` before the run.
- **Slowness IS failure.** Healthy cache_coherency runs in ~20–60s; a 200s+ run means a node is still
  shutting down / a barrier is wedged. Use a ~200s cap for DIAGNOSIS only; never widen a timeout to make
  it pass (RULE 0 / [[feedback_timing_is_first_class]]).
