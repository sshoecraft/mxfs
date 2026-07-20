# MXFS — grant-less reused-inode coherency: THE design (generation-in-dirent)

Status: DESIGN (Gemini-vetted). The corruption (cluster crash) is FIXED (sess47,
build 29977E5D). This is the remaining cache_coherency root: grant-less cached inodes
go stale when a peer reuses the inode number. This doc is the implementation plan.

## The bug (proven, sess47)
Nodes instantiate inodes GRANT-LESS (readdir/lookup/stat → iget(lock_flags=0), DLM mode
NL, no grant) for performance. A peer unlinks+frees that inode and REUSES the inode
number for a new file/dir (di_gen bumped on realloc). The grant-less node keeps the OLD
inode cached (old content/size/TYPE); its DLM has no holder record, so the peer's
EX-acquire BAST reaches no one → never invalidated. Symptoms: empty reads (di_size=0,
"actual=''"), ENOTDIR (cached as reg-file, now dir), content from a deleted file leaking
into the reused inode ("delete_me_4_16" seen in cross_write_read). This is the residual
behind cache_coherency (rename/unlink/cross_write_read) AND rsync_paired.

## Why per-access reload fails (all tried + reverted)
Disk-CAW DLM has NO network channel → readers must PULL invalidations. A per-access
di_gen FUA read = perf wall (sess46: load ~6, never completes). The i_dlm_stale
cached-PR fast-path fall-through (sess47 build 2F062298) fixed barrier-marker coherency
(257s→31s!) but REGRESSED rename (1-2→12-14/240) via forced re-acquires under
contention. Reverted. CONCLUSION (Gemini-confirmed): the fix must be EVENT-DRIVEN,
leveraging I/O the reader is ALREADY forced to do.

## THE design: store child generation IN the directory entry
The reader ALREADY FUA-re-reads a stale dir block on lookup/readdir (the sess46 dir-gen
mechanism: i_dlm_dir_gen bumps on DLM dir reload → xfs_da_read_buf re-reads stale dir
DATA blocks). Dirents currently store only inode NUMBER + ftype. ADD the child inode's
`i_generation` (__be32) to the dirent. Then on lookup, compare dirent.gen vs the
iget'd inode's i_generation: mismatch ⇒ the cached inode is a STALE prior incarnation
(peer reused the number) ⇒ evict + re-instantiate. ZERO extra I/O (the dir block read
already happens). This is exactly the precedent of XFS adding `ftype` to dirents —
proven feasible; generation-in-dirent is no worse.

## Implementation sketch
1. **On-disk format** (we own mkfs; fresh mkfs each test, so backward-incompat is OK):
   - Add a feature bit (e.g. an MXFS incompat flag) so mount/mkfs agree.
   - Extend `xfs_dir2_data_entry` to carry `__be32 gen` after the ftype byte (mind
     8-byte alignment / xfs_dir2_data_entsize). The ftype addition is the template —
     follow xfs_dir2_data_entsize / the DIRENT helpers (xfs_dir2.c, xfs_dir2_data.c,
     xfs_da_format.h). Update the dir2 data-entry accessors (xfs_dir2_data_get_ftype /
     a new _get_gen).
   - Shortform dirs (xfs_dir2_sf_entry, inline in the inode): small dirs read via the
     parent inode (coherent if parent held). The FAILING workloads use BLOCK/LEAF/NODE
     dirs (barrier dirs grow to 120 entries) → the data-entry gen covers them. Decide
     whether to also stamp sf entries (cleaner: yes, for completeness).
2. **Write path**: when adding a dirent (xfs_dir_createname / xfs_dir2_data_*_addname),
   stamp dirent.gen = VFS_I(child)->i_generation. The child's generation is known at
   create time (xfs_init_new_inode sets it). For rename (xfs_dir_replace) keep the
   moved inode's gen.
3. **Read/lookup path**: xfs_dir_lookup / xfs_dir2_*_lookup currently return the inode
   number; extend to ALSO return dirent.gen (out param). In xfs_lookup (xfs_iops.c /
   xfs_inode.c xfs_lookup), after xfs_iget(child), if multi-node && the dir block was
   FUA-re-read (or unconditionally) && child->i_generation != dirent.gen → the cached
   inode is stale-reused → DROP it: d_drop the dentry + mark the inode so the next iget
   re-instantiates (the VFS inode TYPE is fixed at instantiation, so it MUST be evicted,
   not reloaded in place). Cleanest: return a stale signal so xfs_lookup re-does iget
   after dropping, or invalidate and -ESTALE→retry.
4. **Eviction mechanism**: for a LIVE cached inode with gen-mismatch, force eviction:
   d_drop all dentries + remove from icache so the next access cache-misses and reads
   the fresh (correct-type) inode. Reuse the xfs reclaim/recycle machinery carefully
   (the inode may be referenced). This is the delicate part — VFS inode lifecycle.

## Validation
After implementing: `tests/criteria/cache_coherency.sh --nodes 4` (4 sub-tests on one
mount, has cross-test inode reuse — the exact failing pattern). Expect rename/unlink/
cross_write_read to stop reading stale content. Watch perf (must stay fast — this is
zero-extra-I/O so it should). Then rsync_paired + verify_ship.

## Pitfalls / open questions (Gemini answer was truncated; reason through these)
- dir2 leaf/node/free block formats and log/replay of the extended dirent.
- xfs_dir2_data_entsize / freespace bestfree accounting with the larger entry.
- chk_mxfs / the dir verifiers must accept the new entry size.
- Ensure the gen is stamped on ALL add paths (create, rename, link, mkdir, symlink).
- The reader-side evict must not deadlock under the lookup locks (xfs_lookup holds
  parent ILOCK_SHARED). Evict after dropping locks.

## CRITICAL design refinement (sess47 code-check of the premise)
Verified the "reader already reads the dir block" premise in xfs_da_read_buf
(xfs/libxfs/xfs_da_btree.c ~L2873-2954):
- i_dlm_dir_gen bumps 0→1 ONCE on the first multi-node dir read (L2890); the
  invalidation hook (L2944: `b_mxfs_dir_gen != dp->i_dlm_dir_gen`) re-reads stale
  cached dir blocks. Grant-less readers (lock_flags=0) never take the DLM slow path, so
  i_dlm_dir_gen does NOT keep re-bumping — the FUA-re-read is essentially one-shot.
- WHY THE DESIGN STILL WORKS: the gen check rides on the DIRENT content, not on a
  re-read. A CACHE-MISS lookup (peer reads a name/file it hasn't accessed on this node —
  the dominant failing pattern, incl. the cross-test contamination where a peer's inode
  is cached from a PRIOR test) calls xfs_da_read_buf → reads the dir block → the dirent
  carries the CURRENT generation (stamped when the entry was added). Compare vs the
  stale cached inode's i_generation → mismatch → evict. No extra I/O.
- CAVEAT (must handle): a dcache-HIT lookup of a reused SAME-NAME (node already has a
  dentry for that name) skips the dir-block read entirely → gen check skipped. MXFS has
  d_revalidate DISABLED (sess38, was destabilizing). For same-name reuse, either
  re-enable a LIGHTWEIGHT d_revalidate that compares the dentry's child i_generation vs
  the (re-read) dirent gen, OR rely on the fact that distinct test entries use distinct
  names (different-name reuse is caught by the cache-miss path). Scope the d_revalidate
  carefully — the sess38 version polled CAW per lookup (barrier timeouts); a pure
  in-core gen compare against an already-cached dir block is cheap.
- ALSO ensure the dir-block coherency (peer sees the CURRENT dirent at all) is solid —
  that's the existing dir-gen mechanism; gen-in-dirent rides on top of it.

## Feasibility confirmed (sess47 struct check)
`xfs_dir2_data_entry` (xfs/libxfs/xfs_da_format.h ~L351) = inumber(__be64) +
namelen(__u8) + name[] + [filetype(__u8), feature-gated] + tag(__be16 = starting
offset). `xfs_dir2_data_entsize` already computes size with ftype CONDITIONALLY behind
a feature flag — that is the exact template. Add a feature-gated `__be32 gen` after
filetype (before tag), extend entsize by 4 + keep 8-byte alignment, add
xfs_dir2_data_get_gen/put_gen accessors mirroring the ftype ones. Touch: xfs_da_format.h
(layout + entsize macros), xfs_dir2.c/_data.c/_block.c/_leaf.c/_node.c/_sf.c (entsize +
add/remove + tag offset), the createname/lookup/replace plumbing, a mkfs/sb feature bit,
xfs_lookup (read-side compare + evict), chk_mxfs (verify). It is a LARGE ATOMIC change
(getting entsize/alignment wrong corrupts dirs immediately) — do it as one complete,
compilable unit, validate with cache_coherency. NOT safe to do half-way.

## Cheaper interim alternative (if format change is too big near-term)
Gemini option (a): a per-AG on-disk "inode epoch" bumped on any inode alloc/free in the
AG; grant-less readers cache the epoch and, on a cheap epoch read (piggyback on AGI
which alloc/lookup paths already read), drop ALL cached inodes from that AG if changed.
Coarser (over-invalidates a busy AG) but no dirent format change. The dirent-gen design
is preferred (precise, zero-I/O).
