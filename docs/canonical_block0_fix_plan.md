# Canonical dir-block0 record — implementation plan (sess65)

## The bug (fully root-caused, sess64–65)
`dir_reuse_coherency` 4/tcp (and intermittently 2/tcp) durably loses exactly
`node1_f1` (rank1's first file). Proven:
- node1_f1 is **durable** in dir block0 = daddr=120 (fsb=15, AG0). P64-N1F1
  shows present=1 on every write to 120; never content-clobbered.
- The dir **inode-131 data-fork extent[0]** (logical block0 → physical fsb)
  **flip-flops** across nodes and time: the same node flushes inode-131 with
  extent[0]=fsb 15, 262153, and 6291465 at different moments (P-DIRIFLUSH).
- A reader whose cold-read dinode has extent[0]≠15 reads a *different* physical
  block0 that never held node1_f1 → misses it. All other 399 entries survive.

Cause: under concurrent same-dir creates, multiple nodes each convert
shortform→block in their node-affine AG (preferred_ag = slot % agcount),
allocating **their own** physical block0. The dir inode's extent[0] is then
whichever iflush landed last — a flip-flop, never stabilising to one block0.

## Why the local fixes failed (sess65, all reverted to default-off flags)
- `dir_epoch_adopt`: makes a node adopt disk's *current* extent[0] on
  post_release reload — but disk flip-flops, so nodes follow the flip-flop.
- `dir_iflush_fence` (lowest-block0-wins skip): fired 0× — at iflush the
  comparison uses the **local cached** dinode cluster buffer, which is NOT
  cross-node coherent; each node's local buffer matches its own in-core value,
  so the divergence is invisible. A correct fence needs a FUA disk read in
  xfsaild context = deadlock-prone + perf-prohibitive (~2000 dir iflushes/run).
- `dir_merge` + `dir_force_block` default-on: corrupts 2/tcp.
- pending-dirent replay: timing gap (loss only observed at cold-read, no tx).

## The fix: a durable, cluster-visible, WRITE-ONCE canonical block0 record
Per directory **incarnation** (keyed by {dir_ino, di_gen}), there must be
exactly one physical block for logical block0. The dir inode extent[0] alone is
insufficient (flush-time buffer incoherence + racing conversions). Use the
DLM master as the cluster-visible authority — extend the existing per-resource
`dir_epoch` grant-stamping plumbing (sess64).

### Step 1 — DLM wire/protocol (dlm/dlm.c, dlm/dlm.h, dlm/v5_mount.{c,h})
Mirror `dir_epoch` exactly:
- Add `uint64_t dir_block0_fsb` and `uint32_t dir_block0_gen` to the grant
  response struct (dlm.c:747/768 area) and the resource state.
- Master rule (WRITE-ONCE per incarnation): a node reports its block0 fsb +
  di_gen when it first materialises block0. Master sets the resource's
  {dir_block0_fsb,gen} ONLY if unset OR the reported gen > stored gen (new
  incarnation resets it). Never overwrite within the same gen → first publisher
  wins.
- Deliver {dir_block0_fsb,gen} on every grant (like dir_epoch at dlm.c:1230,
  1614).
- Add `uint64_t mxfs_v5_dlm_inode_dir_block0(ctx, ino, *gen)` query
  (v5_mount.c:1190 pattern) + a setter
  `mxfs_v5_dlm_inode_set_dir_block0(ctx, ino, fsb, gen)`.

### Step 2 — publish at first conversion (xfs/libxfs/xfs_dir2_block.c
`xfs_dir2_sf_to_block`, after block0 is allocated): call the setter with the
new block0 fsb + dp->i_generation. Cheap, no extra acquire (we hold EX).

### Step 3 — adopt at the modify prelock (xfs_mxfs_dlm.c
`mxfs_dlm_dir_modify_reload_prelock`, transaction-free context). Replace the
local-disk-FUA check with the master query: if
`mxfs_v5_dlm_inode_dir_block0()` returns a canonical fsb for THIS incarnation
(gen match) AND our in-core extent[0] != that fsb (or we are shortform), force
`mxfs_dlm_reload_inode(dp,…)` to adopt the canonical image BEFORE the create's
transaction starts. The master signal is reliable (not subject to the local
cluster-buffer incoherence that defeated the iflush fence). This makes every
late converter adopt the one canonical block0 instead of allocating a second.

### Step 4 — iflush fence as belt-and-suspenders (xfs/xfs_inode.c xfs_iflush,
the existing P65-IFLUSH-FENCE site, build 283EE4CF): change the comparison
from the local `dip` buffer to the master-delivered canonical fsb. If in-core
extent[0] != canonical (same gen), skip the flush (set XFS_ISTALE_CAW,
error=0, goto flush_out) so a stale node can never republish a divergent
block0. Now it has a coherent reference and will actually fire.

### Step 5 — incarnation reset: rm-rf+recreate bumps di_gen; the master's
write-once is per-gen so it auto-resets. Verify the master clears/over-writes
{dir_block0_fsb} when a higher gen is reported (Step 1 rule).

## Convergence argument
First converter (holding EX, master unset) allocates block0=A and publishes
{A,gen}. Master is now write-once at A for this gen. Every later converter's
prelock (Step 3) reads {A,gen} and adopts A instead of allocating B. iflush
fence (Step 4) refuses to publish extent[0]≠A. So inode-131 extent[0] is a
singleton {A} per incarnation; node1_f1 (in A) is reachable on every node.

## Test
`./run.sh 4 tcp dir_reuse_coherency` must be 4/4; then `./run.sh 2 tcp` full
must stay 17/17 (no regression); then 8/tcp. Watch P-DIRIFLUSH ino=131 shows a
SINGLE incore_blk0_fsb per incarnation.

## Safe baseline to build on
srcversion 283EE4CF: all new module params default OFF (dir_iflush_fence,
dir_epoch_adopt, dir_pending, dir_merge, dir_force_block, dir_adopt_block) =
baseline behaviour + diagnostic probes (P65-IFLUSH-FENCE, P65-EPOCH-ADOPT,
P64-N1F1, P-DIRIFLUSH, P62-REL-DIREXT, P42-SFCONV). Pending-replay
infrastructure (mxfs_dir_pending_add/replay) present but gated off.
