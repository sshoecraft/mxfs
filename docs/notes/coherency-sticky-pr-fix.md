# MXFS cross-node read coherency — THE fix (sticky-PR), sess46

Status: diagnosis PROVEN; architecture CONFIRMED by Gemini review; NOT yet
implemented (6 wrong-model attempts reverted first). This is the definitive plan.

## The bug
Intermittent (~1-2/240, 4-node only): node A creates a regular file, writes
content, fsync+barrier; node B reads it as EMPTY (''). Surfaces in
cache_coherency: cross_visibility / rename_visibility / cross_write_read
"Content preserved ... actual=''".

## Root cause (proven by instrumentation)
1. Node B instantiates the inode via readdir/lookup = `iget(lock_flags=0)` —
   GRANT-LESS (DLM mode NL, no grant held).
2. That happens before node A's data lands → B caches di_size=0 / empty pages.
3. Node A writes (inode-DLM EX). EX BASTs only grant HOLDERS; B holds no grant →
   B is never invalidated; `i_dlm_stale` stays false.
4. B's read: a di_size==0 read short-circuits inside generic_file_read_iter
   BEFORE iomap/ILOCK → no reload path runs → empty. (di_size>0 stale variant:
   served from a stale cached page = page-cache HIT, also bypasses iomap.)

## THE invariant (how GFS2/OCFS2/VMFS all do it; Gemini-confirmed)
**No in-core VFS object may be trusted/read without holding its DLM grant (≥PR).
Grant-less (NL) caching is illegal for I/O.** The DLM can only BAST nodes that are
recorded grant holders; a grant-less cache is, by definition, incoherent.

## THE fix = STICKY PR LOCKS (not per-access acquire)
1. Intercept the VFS entry points — `read_iter`, `getattr` (write already takes EX)
   — and acquire ≥PR BEFORE touching i_size/pages. (The di_size==0 short-circuit is
   ABOVE iomap, so the coherency point MUST be at the top of the op, not in the
   block layer.)
2. Acquire the DLM grant as an ENVELOPE *around* (BEFORE) the VFS locks
   (IOLOCK/ILOCK/i_rwsem). Acquiring DLM while holding a VFS lock is the deadlock
   that wedged nodes in the failed attempts (`mxfs_dlm_reload_inode` does
   `down_write(i_lock)`; calling it under IOLOCK/ILOCK_SHARED deadlocks).
3. On the NL→PR transition, REVALIDATE: FUA-read the dinode; if di_size/mtime/seq
   changed → `truncate_inode_pages(mapping,0)` + update i_size; clear "unverified".
   (MXFS already has `mxfs_dlm_reload_inode`; sess46 added regular-file
   `invalidate_inode_pages2` to it. The slow-path of `mxfs_dlm_ilock_begin(PR)`
   already does this reload on a fresh NL→PR acquire.)
4. **STICKY: do NOT drop the PR grant after the op.** Keep it cached
   (`i_dlm_mode==PR` fast path serves repeat reads with ZERO CAW I/O). The peer's
   EX BAST is what drops it (bast handler: invalidate pages + mark unverified +
   downconvert to NL). Per-access acquire+drop is the perf wall (a CAW per read) —
   sess46 hit it; the fix is STICKINESS, not abandoning lock-on-read.
5. Optional perf later: a `seq`/generation counter in the inode CAW slot, read by a
   cheap bare SCSI READ (no CAW), lets a reader skip the revalidation FUA when
   unchanged (the VMFS trick).

## Concrete implementation in MXFS
- `mxfs_dlm_ilock_begin(ip, MXFS_LOCK_PR)` already: NL→PR fresh acquire (CAW) → sets
  i_dlm_stale → reloads (mode!=0) → (sess46) drops regular-file pages; and STICKS
  (i_dlm_mode stays PR after holders hit 0). The BAST path already invalidates +
  downconverts. So the machinery EXISTS.
- The ONLY missing piece: call `mxfs_dlm_ilock_begin(PR)` / `mxfs_dlm_ilock_end(PR)`
  as an envelope at the TOP of `xfs_file_read_iter` (pal/linux/xfs_file.c), BEFORE
  `xfs_file_buffered_read` takes IOLOCK — gated multi-node + regular file. getattr
  already has the sess45 ILOCK_SHARED reload; verify it's envelope-correct.
- Why prior attempts failed: they took ILOCK/IOLOCK FIRST then reloaded (deadlock),
  or acquired+dropped per read (perf wall), or reloaded from inside the VFS-locked
  region. The envelope-before-VFS-locks + sticky model fixes both.

## Validation
With the cluster mounted (build with the envelope): run cache_coherency
(--nodes 4). Expect cross_visibility/rename/unlink/cross_write_read all PASS,
fast (sticky → no per-read CAW), no wedge. Then verify_ship.
