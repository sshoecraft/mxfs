---
name: compiled-fua-read-coherency-staleness
description: Compiled: SCST FUA-reads-stale-platter root, fua_disable=1 default, inode-cluster over-logged clobber guard, atime-on-read EX clobber.
metadata:
  type: project
tags: [compiled, fua, cache-coherency, scst, clobber, staleness, cache_coherency-criterion]
---

# FUA-read staleness & clobber roots (cache_coherency criterion)

Compiled from [[sess45_lessons]], [[sess62_lessons]], [[sess91_lessons]],
[[sess94_lessons]]. All four converge on ONE architectural fact and its
consequences: **on the SCST iSCSI target every initiator shares ONE write-back
cache; a SCSI-FUA read pierces PAST that shared cache to the un-destaged platter,
so an FUA read of a peer's just-committed (not-yet-destaged) block returns STALE
data.** A normal BIO read, by contrast, sees the coherent shared cache. This
inverts the LIO-era assumption (FUA=fresh) that the whole `_XBF_FUA_FRESH`
machinery was built on. The remaining `cache_coherency` ship blocker is the
family of read-staleness / write-clobber bugs this and related grant-less caching
produce. All bugs reproduce only under concurrency (isolated write→sync→read is
fully coherent — [[sess45_lessons]] `tests/dur_probe.sh`).

## The FUA-stale-platter root and the fix arc (chronological)

- **[[sess45_lessons]] (2026-06-02, build `3D36F352`→`5ED458EB`, head `F6C9DAAC`).**
  First test of `mxfs.fua_disable=1` (reads via bio, SCST shared cache) — it did
  NOT fix the di_size=0 blocker there, correctly ruling FUA OUT as the di_size
  root (that one was write-side, see below). So FUA-disable was shelved this
  session as not-the-cause for di_size.
- **[[sess62_lessons]] (2026-06-05, build `7DF27971`).** GPT consult (RULE-5)
  rank-1 root was "`_XBF_FUA_FRESH` is node-local, served stale AG-meta on
  reacquire." Code analysis PARTIALLY REFUTED that: MXFS already has the epoch
  (`pag->pag_dlm_meta_gen` bumped on fresh acquire at `xfs_mxfs_dlm.c:4925` +
  release paths; buffers carry `b_mxfs_ag_gen`; read hook
  `mxfs_ag_meta_invalidate_stale` ~3656 FUA-rereads when stamp<pag_gen). The
  cached fast-path at `xfs_mxfs_dlm.c:4667` is the only no-bump reacquire but is
  safe (BAST clears `pag_dlm_cached` at 6386 before yielding CAW at 6608). The
  REAL gap identified: the gen mechanism correctly decides to re-read, but the
  re-read is an **FUA read → older platter**, so even correct gen-invalidation
  returns stale bnobt → double-alloc. Levers: `mxfs.fua_disable=1` /
  `mxfs.fua_always=1`. Attempt to test it FAILED — `INSMOD_OPTS="fua_disable=1"`
  did NOT propagate through `fresh_cluster_mount` (param read back 0 on all nodes).
- **[[sess94_lessons]] (2026-06-05, build `354813F9` = fua default only;
  `7B2C2B6D` = +neutral probe).** Made it the module DEFAULT: `int
  mxfs_fua_disable = 1;` at `xfs_mxfs_dlm.c:5562`. MEASURED WIN on a clean run
  (`354813F9`): `rename_visibility` 372s+SHUTDOWN → **8s, no shutdown**;
  cache_coherency passed=2 (cross_visibility + rename_visibility), fast. Best,
  healthiest state in many sessions — this is the "NON-FUA coherency mechanism"
  [[sess45_lessons]]/sess43 said was needed (FUA-reread dir-coherency was
  "fundamentally too slow at scale", 180s timeouts). **KEEP `fua_disable=1`
  default regardless of everything else.** Correctness > the LIO-era FUA
  workaround, since the test cluster is SCST (`project_test_cluster_scst`).
  - Propagation gotcha (carry forward): `INSMOD_OPTS`/`fresh_cluster_mount` does
    NOT pass the param. Use the module DEFAULT or runtime
    `echo 1 >/sys/module/mxfs/parameters/fua_disable`.

## fua_disable is PARTIAL — three distinct roots survive it

`fua_disable=1` eliminated ~45x slowness and a whole CLASS of read corruption but
is NOT a full fix. High run-to-run variance (passed 0..2 across identical
configs — the shutdowns are stochastic; average several runs before trusting a
delta). Three roots are FUA-independent:

### 1. Inode-cluster FUA over-logged clobber — FIXED [[sess91_lessons]]
Confirmed root (sess90): mxfs FUA-re-reads an inode-cluster buffer that carries
this node's LOGGED-but-not-yet-checkpointed mods, clobbering them. **FIX (build
`BD2A94BA`, VERIFIED, KEEP):** helper `mxfs_buf_has_uncheckpointed_mods(bp)`
(`xfs_mxfs_dlm.c`, decl in `.h`) — true if pinned / non-empty `b_li_list` / has
BLI / DIRTY / IN_AIL / delwri. Guards 3 sites that previously cleared XBF_DONE /
FUA-re-read unconditionally:
1. `xfs_iget_cache_miss` cluster-invalidate (`xfs_icache.c` ~L1159) — the PROVEN
   daddr=128 clobber site (P90 fired 7×) → `P91-CLUSTER-PROTECT`.
2. `xfs_iget_recycle` cluster-invalidate (`xfs_icache.c` ~L411).
3. `mxfs_buf_read_fua` backstop (`pal/linux/xfs_buf.c` ~L1536): if pinned/logged,
   SKIP the SCSI read, keep in-core, `xfs_buf_ioend`+return 0 → `P91-FUA-SKIP-LOGGED`.
Verified: `P91-FUA-SKIP-LOGGED` 12×, `P91-CLUSTER-PROTECT` 1×, ZERO
`P90-FUA-OVER-LOGGED`, no shutdowns. `rename_visibility` PASS. Safe because inode
alloc is node-affine per AG — a peer never allocates into a cluster we have
logged changes in, so skipping the invalidate when in-core-authoritative won't
reintroduce sess38 peer-create-invisible.

### 2. Stuck `XFS_ISTALE_CAW` → d_revalidate thrash → 120s barrier timeouts [[sess91_lessons]]
After FIX1, cache_coherency still passed=2/failed=2: `unlink_visibility` (138s) +
`cross_write_read` (124s) — both ~120s BARRIER TIMEOUTS, not the cluster clobber.
Decisive probe `P91-STALEFLAG-DISK` (FUA disk di_mode/di_gen at d_revalidate
stale-flag branch, `xfs_super.c` ~L1885): on `.mxfs_barriers` (a live shared dir)
291× the inode was a perfectly valid dir, disk and in-core AGREE EXACTLY (mode
AND gen), yet flagged stale → d_revalidate returns INVALID(0) every call →
path-walk thrashes → 120s timeout. ROOT: the eviction-ring INODE_FREE handler
`mxfs_dlm_evict_inode_cb` (`xfs_mxfs_dlm.c:4490`) sets
`XFS_ISTALE_CAW | i_dlm_stale` when a peer frees an inode number, but
**`XFS_ISTALE_CAW` has NO clear site anywhere in the tree** (grep confirmed 0
`xfs_iflags_clear(...ISTALE_CAW)`). After the number is legitimately realloc'd,
the flag persists forever; the d_revalidate branch is `i_dlm_stale || ISTALE_CAW`
so the stuck CAW flag alone keeps failing. `xfs_lookup` ISTALE-CAW eviction
(`xfs_inode.c` ~L690) does d_prune_aliases+irele+retry, but a heavily-referenced
LIVE shared dir can't be reclaimed → cache-HITs same inode, flag persists.
- **FIX2 v1 (`EDA54DB1`) REGRESSED rename** 0→40 fails: it cleared the flag IN
  d_revalidate and returned VALID(1), which removed the dir-CONTENT re-read
  trigger (a dir's inode gen is UNCHANGED across a rename; only its dir BLOCKS
  change) → peer's rename invisible. The flag-clear logic is sound but was in the
  WRONG PLACE.
- **FIX2 v2 (build `ECDE1FC5`, built NOT yet verified):** revert d_revalidate to
  original (return 0 when flagged — preserves sess86 rename/unlink). Move the
  clear to the `xfs_lookup` ISTALE-CAW block (`xfs_inode.c` ~L690): FUA-read disk
  di_mode/di_gen FIRST; if MATCHES incore (false-positive current incarnation) →
  clear `i_dlm_stale` + `xfs_iflags_clear(ISTALE_CAW)` + KEEP inode (the fresh
  dir-block read already gave the fresh dirent so rename/unlink stays visible); if
  DIFFERS → evict + re-iget as before. Correct place because it's AFTER the fresh
  dir-block read. Next: verify grep `P91-CAW-FALSEPOS-CLEAR` (false-pos clears)
  vs `ISTALE-CAW-EVICT` (genuine reuse); rename must stay PASS while unlink/cwr
  stop timing out.

### 3. dialloc EFSCORRUPTED — FUA-independent, dominant surviving shutdown [[sess94_lessons]]
Persists with FUA fully OFF. `xfs_dialloc` returns -EFSCORRUPTED (err=-117):
`P-CREATE-ERR1 ... P-CR62 new_ino=0 agno=0 ... xfs_trans_cancel Caller
xfs_create` → SHUTDOWN_CORRUPT_INCORE. `new_ino=0` ⇒ dialloc itself returned
EFSCORRUPTED (never selected an inode; the 0xFFFF badmagic is just P-CR62 reading
nonexistent ino 0). **NO xfs verifier/corruption_error precedes it** ⇒ it's a
LOGICAL `XFS_IS_CORRUPT(i!=1)` check inside dialloc (~30 in
`xfs/libxfs/xfs_ialloc.c`), NOT a buffer-verifier failure — likely AGI/inobt/
finobt inconsistency (fresh AGI says inodes free, a cached/torn inobt/finobt
disagrees). DISPROVEN this session: shortform-dir cached-EX fast-path lost-update
(`P-SFDIR-STALE-RMW` fired 0× — unlink_visibility's 120-file TESTDIR is
BLOCK-format not shortform; the field `i_dlm_dir_loaded_gen` at `xfs_inode.h:115`
is behavior-neutral, harmless to keep). NEXT: instrument the exact `XFS_IS_CORRUPT`
site (candidates `xfs_dialloc_ag_inobt` 1177 / `finobt_near` 1461 / `newino` 1571
/ `update_inobt` 1623 / `xfs_dialloc_ag` 1671 / `good_ag` 1827 / `try_ag` 1900);
check whether `mxfs_dlm_invalidate_ag_meta` (`xfs_mxfs_dlm.c:6735`, walks
`pag->pag_bcache` via rhashtable_iter) MISSES an inobt/finobt block (rhashtable_iter
can skip during resize; or block not yet cached at acquire → read fresh but torn).
`P14-INSTR` staled only agi/agf, not inobt/finobt.

## The atime-on-read EX clobber (di_size=0) — separate WRITE-side root [[sess45_lessons]]
`cross_write_read` di_size=0: a node writes di_size=0 over on-disk 1048576. PROVEN
(P97 `owned=1` clobbered inode in flusher's `b_li_list`, `dlm_mode=5`=EX;
P100 `dump_stack`): **trigger = atime-on-read.** `filemap_read → touch_atime →
xfs_vn_update_time → xfs_ilock(ILOCK_EXCL) → DLM EX → iflush stale di_size` —
reading a peer's file takes EX and flushes the reader's stale in-core inode,
clobbering the peer's size to 0. (`rm`/`xfs_remove` is the other EX-on-peer path.)
DISPROVEN as PRIMARY here: read-staleness (P98/P99 disk=0 was a CONSEQUENCE of the
clobber); platter-vs-cache durability (`fua_disable=1` did NOT fix → not FUA);
pure atime (`noatime` alone cut clobbers 11→5, didn't fix).

**FIXES LANDED (build `3D36F352`, KEEP):**
1. **Node-affine regular-file alloc** — `xfs_dialloc_pick_ag` (`xfs_ialloc.c`):
   multi-node reg files use `node_slot % maxagi`, not the parent dir's AG (the
   shared TESTDIR forced all nodes' files into one AG → one cluster → cross-node
   clobber). Inode cluster is entirely within one AG → node-affine means one
   cluster is owned by exactly one node.
2. **atime-on-peer-file skip** — `xfs_vn_update_time` returns 0 for an atime-only
   update of a reg file in a PEER's affine AG (`mxfs_inode_is_peer_ag`). Removes
   the dominant clobber trigger.
3. **getattr inode-DLM refresh** — `xfs_vn_getattr` takes ILOCK_SHARED (→DLM PR
   reload) before reading attrs. Fixed the STAT path at 2-node.
4. `RELOAD-SIZE-DROP-SKIP` extended (dropped nblocks==0 requirement).
RESULT: 2-node cross_write_read di_size coherency FIXED (`cwr_probe2.sh` correct
both ways). Build progression `3D36F352`→`5E279368`→`5ED458EB`; stable head
`F6C9DAAC` (= `5E279368` + instr-gated `INODE-REUSE-DETECT`).

## Residuals under 4-node concurrency [[sess45_lessons]]
The di_size fix reduced but did not eliminate at scale. At 4 nodes cross_write_read
fails MOSTLY on STALE-READ (verify_hit=0 in 3/3 dump runs), with the rarer
`xfs_inode_buf_verify` SHUTDOWN (blocks 0x1fda18/0x5f8d48/0x3fb3b0) as secondary.
Decisive P98/P99 data: at failing reads UNIFORMLY `incore_size=0` AND
**`disk_di_size=0`** (P99-IGET-MISS fresh FUA disk read also 0) ⇒ **WRITE-side, not
read-stale** — the writer's inode is genuinely 0 on the platter (never destaged OR
clobbered to 0 by a stale-cluster flush). A node even reads its OWN small `.md5`
sidecar as empty cluster-wide → small-file write/durability, not just cross-node.

**Surgical per-inode inode-cluster write (build `5ED458EB`, param
`mxfs.surgical_inode_write`, default 0):** FUA-writes ONLY this node's dirty inode
sectors (`b_li_list` → `ili_inode->i_imap.im_boffset`, isize=sb_inodesize via
`mxfs_pal_scsi_write_fua_bdev`) then `xfs_buf_ioend`+return, skipping the whole-
cluster bio in `pal/linux/xfs_buf.c` `xfs_buf_submit`. RESULT: PARTIAL/NO fix +
SLOW — r1 PASS but r2 hit inode_buf_verify corruption AND ran 2+min (per-inode FUA
cost). ⇒ the clobber is NOT solely the whole-cluster write path. Stays DEFAULT-OFF.
Better direction identified: CLUSTER-GRANULARITY inode-DLM invalidation (bounded
cost, fixes both read-staleness and write-clobber). NOTE these di_size fixes
PREDATE the `fua_disable=1` default; several 4-node residuals here are the same
grant-less-cache / durable-before-visible class that `fua_disable` later cut down.

## Cross-cutting themes (all four)
- **The unifying architectural root** ([[sess45_lessons]] honest re-assessment):
  a peer trusts cached metadata (inode size, inode mode, dir contents) it holds NO
  DLM grant on; the first uncoordinated access serves stale state. di_size=0,
  dirent-not-visible (`No such file`), and EISDIR (inode-number reuse dir→file,
  driven by barrier-dir churn) are the SAME bug in different costumes — a CLASS,
  not a bug. Fixing one facet exposes the next. Reliable fix is architectural
  (GFS2 model: never cache grant-less, OR guarantee durable-before-visible on
  every release) — both have the known per-lookup-DLM barrier-timeout perf tension.
- **DEADLOCK LEARNING [[sess45_lessons]]:** in-place inode reload during
  `xfs_lookup` (`mxfs_dlm_reload_inode` + `xfs_setup_iops` under
  `xfs_ilock(EXCL)`) DEADLOCKS (stat D-state, needs virsh-reset). Inode REUSE with
  a mode change (dir→file) needs EVICTION (drop dentry → reclaim → recycle-
  reinstantiate), NOT in-place reload. `drop_caches` on the peer FIXES the
  EISDIR → confirms purely a peer cache-invalidation gap, not on-disk.
- **bnobt double-free is a REAL durable lost-update, not a red herring**
  ([[sess62_lessons]] P81-DEXT: `disk_claims_freed=1 disk_differs=0` = DISK-INODE-
  OWNS-FREED; contradicts sess93's "incore-stale" reframe). Root is AG-meta
  durability-ordering: a releasing node's bnobt/cntbt/agf write must be PLATTER-
  DURABLE (destaged, not just in SCST write cache) BEFORE the on-disk AG-DLM
  unlock. Prior attempts refuted: P81 release-FUA-write (too slow), P90 gen-bump
  (worse), P91 FUA-write-through (no change) — all [[sess45_lessons]].
- **Strategic pivot [[sess62_lessons]]:** stop chasing individual VISIBILITY races
  (the 40-session trap); attack SHUTDOWN CASCADES — a node that crashes mid-test
  fails ALL its remaining assertions and breaks peers' barriers, inflating
  visibility counts. Reducing shutdowns moved 2 subtests green.

## Config / build reference
- `mxfs.fua_disable=1` — module DEFAULT (`xfs_mxfs_dlm.c:5562`). KEEP. Routes reads
  through coherent SCST shared cache. `mxfs.fua_always=1` — opposite lever (untested).
- `mxfs.surgical_inode_write` — default 0, DEFAULT-OFF (partial+slow). Impl in
  `pal/linux/xfs_buf.c` before final `xfs_buf_submit_bio`; param in `xfs_mxfs_dlm.c`.
- Builds: `3D36F352`/`5E279368`/`5ED458EB` (di_size + node-affine + atime-skip +
  d_revalidate); head `F6C9DAAC`; `7DF27971` (SBCLAMP probes); `BD2A94BA` (FUA
  over-logged guard, VERIFIED KEEP); `EDA54DB1` (FIX2 v1, regressed rename, REPLACED);
  `ECDE1FC5` (FIX2 v2, unverified); `354813F9` (fua_disable default); `7B2C2B6D`
  (+neutral probe). srcversion is NOT a stable cross-session ID (hash quirks) —
  verify via `strings mxfs.ko | grep <probe>`.
- Test cluster is SCST (not LIO) — CAW works, FUA reads stale. 4 nodes, slots
  t1=0 t2=3 t3=1 t4=2, ~20 AGs, mount /mnt/shared dev /dev/sda. Clean reboot ALL 4
  (`virsh -c qemu:///system destroy+start testN`) before trusting any slow result.
  `make clean` wipes tools/ → `make tools` after. INSMOD_OPTS does NOT propagate
  through `fresh_cluster_mount` — use module default or /sys param.
