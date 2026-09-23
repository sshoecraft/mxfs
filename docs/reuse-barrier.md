# The Cluster Reuse Barrier (D-512 component 7)

Status: cycle-2 in progress (sess415).  Ruling: `docs/rulings/d512-cycle2-reuse-barrier.md`.

## The invariant

> No inode number or extent may become allocatable until every live holder
> of the old incarnation has completed revocation: all CPU mappings and
> writable pins neutralized, all G1 (old-incarnation) IO and post-IO
> metadata work completed, and the required storage flush completed.  Any
> observed generation mismatch combined with old-incarnation dirty or
> in-flight state is a fail-stop invariant violation — never an adopt/keep
> case.

"G1" is the dead incarnation a stale in-core shell represents; "G2" is the
live incarnation on the platter after reuse.

## The publication state machine (what exists, where)

### 1. Allocation-side interlock

`xfs_dialloc` pick → `mxfs_dialloc_try_reserve` (xfs/libxfs/xfs_ialloc.c:1590)
→ `mxfs_v5_dlm_inode_reserve_try` (dlm/v5_mount.c): an **EX NOQUEUE
acquisition of the same per-ino DLM resource** every holder of the old
incarnation holds.  On CAW it is a slot read + CAS; on TCP it is a
non-queued request the master answers with a deny.  A loser exits and
dialloc picks another ino.  `MXFS_LKF_DEMAND` is escalated to only after a
full failed sweep, and it must mean the same thing on both engines: on CAW
the sticky revoke bit in the slot, on TCP a BAST to every conflicting
granted holder fired on the deny (the requester is not queued).  The
wrapper carries the flag on both branches; a branch that drops it leaves
the escalation inert, and a peer's cached grant on a number it has already
freed is then released only by that peer's own lazy path (measured at
2.3 s per round on the 2-node TCP rig, 0.87.12).  Consequence: an inode
number cannot be reused while ANY node holds its resource, in any mode.

A refused candidate cools before it is probed again, and the cooldown
class follows what the refusal is waiting on: a silent (undemanded)
contention waits on nothing in particular and cools 500-1000 ms; a
publication-pending refusal waits on a LOCAL write this node just kicked
and cools 40-80 ms; a DEMANDED contention waits on the PEER's release
fence, which for a freed number is milliseconds, and cools 40-80 ms
(`MXFS_DEMAND_COOL_MS`).  The negative cache must never outlive the
release it asked for by two orders of magnitude, or the allocator spends
its whole backoff re-discovering a number that is already free.

### 2. Free-side authority

unlink/ifree and truncate/punch commit under inode DLM authority; the
F1-F4 publication-obligation machinery (0.19.40) pins >=PR until the home
write completes.  A peer therefore cannot free an inode this node holds —
it must BAST this node to NL first.

### 3. Holder-side release drain (drain site 1)

`mxfs_dlm_bast_process` (xfs/xfs_mxfs_dlm.c, drain site 1):
`filemap_write_and_wait` + `invalidate_inode_pages2` (also unmaps PTEs) +
`i_dlm_stale = true`, all BEFORE the on-disk unlock CAS.  IOLOCK/ILOCK map
onto the ONE per-inode DLM lock, so in-flight local ops (including DIO)
pin the grant; the drain cannot complete under them.  Consequence: after a
node releases, it holds NO resident pages, NO mapped PTEs, NO dirty pages
for that inode.

**0.28.2 (P-D512-REL-DRAIN-\*):** both drain calls' return codes are now
enforced.
Writeback failure → refuse the unlock + `xfs_force_shutdown` (the peer
must never adopt a platter missing this tenure's data; shutdown withdraws
from the DLM per D-409, so the tenure is disposed of via recovery).
Invalidate residue (pinned folio) → refuse the unlock, keep the grant,
retry via the CACHED+bast_pending dwork re-arm — an unrevokable pin holds
the grant for as long as it exists.

**0.28.6 (D-WEDGED-RELSTATE-CLOBBER-UNLOCK-PUBLISHED-0285):** the wedge's
"CAS refused pre-submit" promise was measured broken by the first T8
injector run: `WEDGED` is a terminal `i_mxfs_rel_state`, but the unlock
arms invoke the relbar proof body *before* their pre-CAS WEDGED re-check,
and the proof body rewrote DRAINING→PROVED over it — a drain-site-2 wedge
was followed 0.7ms later by a published unlock (`P141-UNLK-EXCLR`) and
the waiter was served in ~1s, ahead of any fence/replay.  Fix:
`mxfs_rel_state_set()` sticky setter — WEDGED can be entered, never
left; every rel_state writer routes through it.  The on-disk pin
(`P-WEDGE-PIN`) guards only the wholesale teardown `release_all`, not
the direct unlock CAS, so the sticky state + pre-CAS re-check are the
sole barrier on the live release path.

### 4. Re-acquire revalidation

Any later operation on a shell re-acquires the DLM lock → protective
reload (`mxfs_dlm_reload_inode`) → di_gen mismatch → `mxfs_incarn_poison`
(cycle-1: -ESTALE gates at 13 file_operations/vm_operations entry points +
5 iomap_begin paths + getattr + writeback; poison-time revocation worker
zaps PTEs, DISCARDS pagecache, DONTCACHE + prunes; lookup fails CLOSED).

### 5. Detection of the "impossible" state

**0.28.2 (P-D512-DIRTY-MISMATCH):** a DIRTY shell meeting a VERIFYING, LIVE, different-gen
FUA-fresh platter image is a proven barrier violation (the number was
freed, reused, and the new owner's init destaged while we held dirty state
under a grant).  The old `self_ahead` "platter is behind us" keep no
longer applies there: poison + loud forensics + fail-stop shutdown.
The FREE + different-gen + dirty case remains a KEEP: it is the
indistinguishable-and-benign creator case (our own alloc/create logged but
not yet destaged — sess116 / P5F / P52), which a genuine peer free cannot
produce because it would have had to BAST us to NL first.

### 6. Eviction ring

Peer-free notifications flag cached NL shells `XFS_ISTALE_CAW`
(xfs_inode.c lookup trap).  Lossy; an optimization only — correctness
comes from 3+4.  An entry names one incarnation exactly: it carries the
freed image's generation (bumped once by `xfs_ifree`), so the consumer acts
only on a cached shell whose generation is that value or one below it.
Generations are drawn at random per allocation, so no order relation between
two of them says which incarnation is older; a shell of any other
incarnation — in particular the successor a peer has just created on the
reused number, which this node may already hold open — is left alone, and
the grant-time reload is what settles its freshness.  The consumer also
poisons an open or mapped shell of the freed incarnation (open-holder marks,
D-0977), which is exactly why it must never act on a guess.

## Open holes (ruling, in hazard order — ledgered under D-512)

1. **Extent-free publication audit** (critical #1) — AUDITED sess415:
   - Runtime paths INHERIT the barrier.  `xfs_ilock()` recurses into the
     MXFS DLM acquire hook (xfs_inode.c:~74), so every extent-free that
     commits under ILOCK_EXCL carries per-inode cluster EX — truncate
     (`xfs_setattr_size` → `xfs_free_file_space` → `xfs_bunmapi` →
     `xfs_bmap_del_extent_real` → `xfs_free_extent_later`), punch,
     reflink end/cancel-COW, dir shrink, bmbt/symlink/attr-remote block
     frees.  All peer holders were BAST-drained (flush + invalidate)
     before EX granted; peers can only SEE the freed extents after the
     freeing node's AG-DLM release drain (architectural invariant 1).
   - `xfs_inactive` takes per-inode EX explicitly (xfs_inode.c:4655,
     iclus/dlm) and holds it across `xfs_inactive_truncate`/`_ifree`
     (verified: no release between :4726 and :5367); the sess47
     double-free guard additionally refuses inactivation of a peer's
     freed inode.
   - RECOVERY-context frees carry NO per-inode DLM:
     `xfs_extent_free_recover_work` (EFI replay) and
     `xfs_refcount_recover_cow_leftovers` free extents on log-recovery
     authority alone.  This is the ruling's replay-serialization hole
     (step 5) and folds into the D-FOREIGN-REPLAY-UNGATED-IMAGES /
     D-FOREIGN-SLICE-INTENTS-ABANDONED campaigns — replay must be inside
     the recovery lease/fence epoch so no live allocator races it.
   - scrub/repair reap paths free extents without inode DLM, but the
     live ioctl surface is the GOINGDOWN-only stub (xfs_stubs.c), so
     online scrub is unreachable in mxfs builds.  Re-audit if ioctls
     ever return.
2. **Drain site 2** (post-`mode=NL`, pre-wire-unlock in bast_process) —
   FIXED in-tree for 0.28.2: rc captured; on failure P-D512-DRAIN2-WBFAIL
   + `mxfs_inode_wedge` (pins the grant on disk, closes admission, refuses
   the pre-CAS unlock on both arms, force-shutdowns — no state surgery
   needed).  Site 1's hard arm likewise upgraded from bare shutdown to the
   wedge so teardown cannot clean-depart the unproven tenure.
3. **Recovery/replay serialization**: replay must participate in the
   barrier (overlaps ledger items D-FOREIGN-REPLAY-UNGATED-IMAGES and
   D-FOREIGN-SLICE-INTENTS-ABANDONED).
4. **Fencing-before-grant-reassignment** assertions on both transports.
5. **GUP/RDMA pins, DAX layouts**: the INVFAIL retry arm pins the grant,
   which is the ruling's required behavior; no explicit layout-break
   policy yet.

## Verification matrix

T1-T9 in the ruling memory.  Cycle-1's knob-forced matrix
(`tests/d512_ref_matrix.c`, `tests/d512_incarn_gate_verify.sh`) covers the
single-node gate/revocation legs; the cross-node reuse-race legs (T1-T7)
and the synthetic containment injections (T8: forced dirty-mismatch,
forced invalidate failure) are cycle-3 work.  P-D512-* must be ZERO on
every healthy board.
