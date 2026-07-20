---
name: sess60-crash-fix-and-readdir-genbump-progress
description: sess60: FIXED dir_reuse 4-node kernel crash (igrab-NULL phantom bast UAF) + reader-side stale-dir-block (readdir gen-bump). Residual = writer-side du…
metadata:
  type: project
---

## sess60 — dir_reuse_coherency 4-node TCP: two fixes landed, one residual

Criterion = 1/2/4/8 node tcp 100%. State: 1/tcp 16/16✅, 2/tcp 17/17✅,
4/tcp blocked on `dir_reuse_coherency`, 8/tcp never run.

### FIX 1 (KEEP, PROVEN) — kernel crash BUG_ON(I_CLEAR) in iput, build F5D370D8
4-node dir_reuse crashed nodes: `BUG at fs/inode.c:1798` (`BUG_ON(i_state & I_CLEAR)`)
in `iput`, from the trailing `xfs_irele(ip)` in `mxfs_dlm_bast_work_fn`
(mxfs-ino-bast kworker). ROOT (proven by P-IGRAB-NULL site=EDEADLK +
P-BWFN-PREIRELE i_count=0 i_state=0x60 I_CLEAR=1 right before BUG): the EDEADLK
self-demote (xfs_mxfs_dlm.c ~9903) and ACQBAST-HONOR (~10139) queue sites call
`igrab(VFS_I(ip))` on a REUSED dir inode mid-eviction (I_FREEING|I_CLEAR =
0x60), igrab returns NULL, the NULL was IGNORED, bast_work_fn was queued anyway,
and its unconditional xfs_irele dropped a ref never taken -> UAF.
FIX: EDEADLK — if igrab fails, drain INLINE via `i_dlm_demoter=current;
mxfs_dlm_bast_process(ip)` (lock not held there; bast_process is re-entrant-safe
via demoter, same as the ilock_end inline path ~10302) then recurse. ACQBAST —
if igrab fails, skip the queue (ilock_end inline path + reclaim teardown
release). PLUS backstop in bast_work_fn: skip xfs_irele if i_count<1 or I_CLEAR.

### FIX 2 (KEEP, partial) — reader-side stale dir-block, build A1419A72
With crash fixed, residual = readdir miss (readdir=399/400 lookup_fail=0).
ROOT (P26-RDDIR: reader holds CACHED PR mode=3, i_dlm_dir_gen stuck at 1,
disk_size==incore_size): peers add dirents into an EXISTING data block (no
di_size growth) but nothing bumps this reader's i_dlm_dir_gen — the only
producers are the ASYNC heartbeat evict-ring + slow-path reacquire; a
fast-pathed cached PR hits neither. So xfs_da_read_buf's read-time invalidation
(re-reads a cached dir block only if b_mxfs_dir_gen < i_dlm_dir_gen) never
fires -> stale block enumerated. NOTE size-based Approach A was REFUTED
(P60-RDSYNC=0, miss is SAME-SIZE). FIX (xfs/xfs_dir2_readdir.c ~667): on readdir
of a contended (dir_gen>0) non-EX dir, `dp->i_dlm_dir_gen++` to force
xfs_da_read_buf to re-read all dir blocks from the durable platter (P60-RDGEN
probe). Reduced failures: round 2-5 (8 fails) -> round 12 (2 fails).

### RESIDUAL (the real remaining blocker) — writer-side durable lost-update
At round 12, ALL 3 peers (test2/3/4) miss the SAME entry **node1_f1** (rank1's
FIRST file in the freshly-recreated dir), lookup_fail=0. Same entry on all
peers => DURABLY ABSENT from the on-disk dir, NOT per-reader staleness. =
DURABLE dirent LOST-UPDATE under concurrent same-dir create (sess59 CORRECTED
root, this time NOT crash-contaminated). HYPOTHESIS: when a peer acquires dir-EX
(after rank1 commits node1_f1) and adds its own entry, its RMW reads a STALE
cached dir DATA block (missing node1_f1) and commits over it -> node1_f1 erased
durably. The EX-acquire-side dir-block invalidation (P-DE mxfs_dir_evict +
reload) uses XBF_TRYLOCK and skips under contention (P34-TRYLOCK-STALE), same
class as the reader side. NEXT: instrument the WRITE path (xfs_create / dir add)
to confirm the acquirer RMWs a stale base missing node1_f1; fix = force
coherent dir-block re-read on EX-acquire before the dirent RMW (analogous to the
reader gen-bump but write-side, TRYLOCK-robust). Also PERF: ~13s/round × 24 ≈
320s vs 300s TEST_TIMEOUT (RULE 0) — will timeout near round 23 even when
coherent; needs per-round cost cut (verify=4-node cold readdir+400 igets,
rm+4 MQTT barriers).

Builds on test1-4 via NFS insmod. Reliable repro = `./run.sh 4 tcp
dir_reuse_coherency` (suite, tight MQTT barrier). drc4_repro.sh looser timing
masks it (16/16 clean). virsh -c qemu:///system destroy+start test1-4 to reset.
See [[sess59-drc-root-grantless-readdir-async-evict-latency]],
[[sess59-drc-CORRECTED-root-durable-dirent-lost-update]].
