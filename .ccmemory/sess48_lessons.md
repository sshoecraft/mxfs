# sess48 lessons — 2026-06-02

## The remaining cache_coherency root, NAILED: reused-inode stale cache-HIT

cache_coherency's failures are TWO faces of ONE bug — a node returns a STALE cached LIVE
in-core inode on lookup because a PEER freed the inode number and REUSED it for a new
incarnation. We hold no DLM grant on a passively-cached (grant-less) inode, so the peer's
free/realloc never BAST'd us → the stale in-core inode lingers.
  1. **TYPE mismatch** (unlink_visibility ENOTDIR catastrophe, 30 fails + 120s barrier
     timeouts): a barrier/test DIR inode's number was reused from a prior regular file; peer
     has it cached as a reg file → ENOTDIR on EVERY op incl. CREATE of children → the barrier
     dir is unusable → barrier can't signal → 120s timeout. PROVEN: `INODE-REUSE-EVICT
     ino=131 incore_ftype=1(reg) dirent_ftype=2(dir) name=uv_delete`.
  2. **CONTENT empty-read** (rename/cross_write_read, `actual=''`): a reg file's number
     reused; peer cached the old/empty incarnation; ftype matches (reg→reg) → the type-check
     does NOT catch it → reads empty/stale.

## THE FIX (build `DDF05EA770E8090DE47542A`, deployed) — KEEP, don't revert
3 parts (see state.md for exact loci):
- (a) DETECTION zero-I/O: `xfs_dir_lookup` hands back the dirent on-disk ftype (new
  `uint8_t *ftypep`; all 4 dir2 lookup variants already set `args->filetype`). xfs_lookup
  compares `dirent_ftype != xfs_mode_to_ftype(VFS_I(*ipp)->i_mode)`.
- (b) EVICTION: `i_dlm_stale=true; d_prune_aliases(child); xfs_irele; goto retry_iget`
  (bounded 4×). Child-inode eviction, no parent lock held → safe.
- (c) RECYCLE RE-READ (xfs_iget_recycle): GEN-GATED — re-read disk dinode, adopt ONLY if
  `disk di_mode!=0 && disk di_gen != in-core i_generation` (genuinely reused). Then
  xfs_setup_existing_inode wires correct iops. **GEN-GATING IS CRITICAL**: ungated, the
  re-read clobbered same-incarnation reg files' good size with stale disk-0 (sess39
  RELOAD-SIZE-DROP) → rename worsened 1-3→4-7, node1 lost its OWN files. Gen-gated → rename
  content-fails 0 in isolated runs.

## Why recycle (not in-place reload): xfs_iget_recycle re-inits a torn-down inode that is
EXCLUSIVELY ours (XFS_IRECLAIM set, no users) → safe to fully re-type. In-place
reload+iops-swap on a LIVE inode deadlocks (sess45). BUT stock xfs_reinit_inode PRESERVES the
old mode and does NOT re-read disk → a plain recycle resurrects the stale incarnation; my
gen-gated disk re-read fixes that.

## RESULT: correctness UP, but SLOW (the new blocker)
- Isolated runs: unlink_visibility PASS (was 30 fails+120s); rename 0 content-fails;
  cross_visibility PASS.
- FULL criterion: passed=0 failed=4 BUT failure counts tiny (1-2 each, down from 3-30).
  It FAILS on SLOWNESS: rename 133s, unlink 264s, cross_write_read 124s = 120s BARRIER
  TIMEOUTS. The eviction's gen-gated re-read can only adopt the peer's new incarnation once
  it's DURABLE; a freshly-created barrier dir's child dinode isn't flushed when peers look it
  up → re-read sees old gen → loops 4× → returns stale → barrier_wait 120s → eventually
  durable. Correct but slow.

## NEXT (the #1 task): FORCE the peer flush, don't wait.
When type-mismatch persists after the cheap re-read (disk gen still == in-core ⇒ peer not
durable), acquire inode DLM PR (`mxfs_dlm_ilock_begin(ip,MXFS_LOCK_PR); mxfs_dlm_reload_inode;
mxfs_dlm_ilock_end`) → BASTs holder → drains+flushes new dinode → reload sees it. This is
sess40 `reuse_dlm` (xfs_icache.c ~L780/L848) applied ONLY to the bounded type-mismatch case
(broad use caused the 480-deleted-file unlink timeout → reuse_dlm defaults OFF). OR make the
CREATOR durable-before-visible. GOAL: barrier lookups resolve in ms.
Then: content empty-read trigger (di_size==0 reg file → FUA size/gen check → evict; gen-gated
recycle already fixes once it reaches recycle). Then re-run criterion (target all-4 PASS +
fast), then rsync_paired + verify_ship.

## Criteria: 10 PASS, 2 FAIL (cache_coherency, rsync_paired). Marker NOT written.
Env unchanged from sess47 (host clyde, VMs test1-4 by-path disks, /tmp/.mxfs_pass).
Tests auto-background under the harness (>~60s); read the task output file for results.
