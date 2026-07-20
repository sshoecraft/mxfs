---
name: sess27 lessons
description: Sess27 added TCP DLM transport to v5_mount.c. v0.3.111. Key bug found: phantom AG locks on single→multi transition for TCP path.
type: project
originSessionId: 48001cde-a0df-4390-b5d4-b3a57723f24f
---
# Sess27 lessons

## What was built (v0.3.111)
- Full TCP DLM transport in `dlm/v5_mount.c`.  Bypasses kernel SCSI CAW
  (sess26 root cause #2: kernel scsi_execute_cmd reports CAS-success
  without persisting writes under stress).
- Module param `mxfs.force_transport=1` selects TCP transport at insmod
  time.  Default 0 keeps CAW path unchanged.
- Wired all DLM-engine + peer + lease callbacks: send/bast/membership
  cb on DLM, msg/connect/disconnect cb on peer, expire cb on lease.
- `v5_dlm_send_cb_tcp` forwards DLM control messages via mxfs_peer_send.
- `v5_peer_msg_cb_tcp` parses incoming wire frames and routes to
  mxfs_dlm_process_remote_*; for inbound MXFS_MSG_LOCK_BAST it invokes
  the v5 inode/AG notify_fn directly (the master sends BAST to the
  current holder).
- `v5_bast_cb_tcp`: when DLM master fires BAST, forward to holder via
  peer_send (3 retries, 50ms backoff) or local-dispatch if owner==self.
- `v5_refresh_active_nodes`: pulls active set from lease (which already
  registers self at index 0) and calls mxfs_dlm_update_active_nodes.
  No append-self needed — initial implementation double-added; fixed.

## Bug found: phantom AG locks on single→multi transition
Symptom: 15×512 stress freezes at iter 1 with both nodes spinning on
`DLM AG lock failed: ag=0 rc=-110` / `ag=1 rc=-110` (60s ETIMEDOUTs).

Root cause:
1. T1 mounts alone in single-node mode.  active_nodes={T1}.
2. T1 acquires AG=0 EX as local master (mxfs_dlm_lock fast path,
   adds entry to local lock table).  XFS sets pag_dlm_cached=true.
3. T2 mounts.  Peers discover each other.
4. v5_discovery_peer_cb calls v5_refresh_active_nodes →
   mxfs_dlm_update_active_nodes({T1,T2}).
5. update_active_nodes detects membership change → purges all
   local lock-table entries (re-mastering invalidates them).
6. **But XFS perag still has pag_dlm_cached=true** for AG=0.
7. T1 wants AG=0 again → fast-path "already cached" hits.
   Eventually unlocks → next acquire goes slow-path → DLM has no
   entry, request goes to new master (T2).  T2 has no entry either.
   Grant succeeds for T1 but with no record on T2.
8. T2 wants AG=1 → goes to master T1, T1 has no record (purged), grant.
9. Each side now has phantom holds on the other's preferred AG.
   BAST ping-pong fails to release because the lock entry needed on
   the master to track the hold doesn't exist.  Result: ETIMEDOUT loop.

Fix (sess27 in v0.3.111):
**Why:** XFS's mxfs_dlm_peer_joined_flush already exists exactly for
this transition — it forces dirty data to disk AND drops
pag_dlm_cached for AGs with no active holders.  For CAW path it fires
when ctx->dlm_caw->single_node was true.  The TCP path was never
firing it because we only checked dlm_caw.

**How to apply:** In v5_discovery_peer_cb, when ctx->peer is set
(TCP), check `mxfs_dlm_is_single_node(ctx->dlm)` and if true, fire
ctx->peer_joined_notify_fn BEFORE the v5_refresh_active_nodes call
that triggers update_active_nodes' lock-table purge.  This forces
XFS to flush dirty + drop pag_dlm_cached so the post-purge state is
clean.

## Test results (sess27 end) — srcversion 4A96428BE8AF796387D23FB

Mode A surfaces intermittently (sess25 noted ~5-10% rate; sess27
re-confirmed it's still present).  Across multiple runs:

| Workload | Pass count | Notes |
|----------|-----------|-------|
| 5×256 fresh mkfs (3 consecutive) | 15/15 | clean run |
| 5×256 fresh mkfs (post-failure)  | 0/5  | Mode A iter 5 |
| 5×256 second run (after passing 5×256) | 5/5 | clean |
| 5×256 third run | 5/5 | clean |
| 15×256 fresh mkfs (single)     | 15/15 | clean |
| 15×256 after consecutive 5×256 | failed iter 2 | Mode A |
| 5×512 fresh mkfs               | hang iter 2 | AIL push deadlock |
| 15×512 fresh mkfs              | hang iter 2 | AIL push deadlock |

**Best-case TCP DLM**: 35/35 across 3×5×256 + 15×256 (one lucky run).
**Mode A frequency** (sess27 final samples, fresh mkfs each):
- 5×256: 3 PASS / 2 FAIL across 5 rounds = 60%
- 5×256: 7 PASS / 3 FAIL across 10 rounds = 70% (with diagnostic
  pr_warn calls — the slowdown may be slightly improving Mode A
  rate via timing change)
- 15×256: 1 PASS / 2 FAIL = 33% (still small sample)
- Sess25/26 CAW baseline at 5×256 was also ~50-60%.
**Mode A is roughly transport-invariant** — TCP DLM didn't fix it,
just confirmed it's pre-existing and architectural.
**5×512+**: 100% deadlock — separate architectural issue (AIL push).
- 15×512 with TCP: HANGS on iter 2 in `mxfs_dlm_ag_bast_work_fn` →
  `xfs_ail_push_all_sync`.  Hung-task printk after 122s.  ETIMEDOUT
  loops on AG=0 / AG=1 because the BAST work can't drain.
  This is a CROSS-NODE AIL PUSH DEADLOCK, not a TCP-specific bug.
  Both nodes call `xfs_ail_push_all_sync(mp->m_ail)` to drain the
  full AIL, but the AIL contains items needing locks the other
  node holds.  Mutual stall.  Same architectural issue likely
  affects CAW path at scale (sess26 saw 15×512 fail iter 7-8;
  may have been the same deadlock occasionally resolving).

## SESS27 P56-INSTR — Mode A localized to ip->i_disk_size lag

Built P56 in addition to P55 (srcversion `4D66098F7A3A4536A29B237`).
P56 captures `vfs_size = i_size_read(VFS_I(ip))` and
`disk_size = ip->i_disk_size` at bast_process entry.

**KEY FINDING** (5×256 fresh, iter 3 fail):

```
[91.205] P56 vfs_size=36 disk_size=21 i_dlm_state=3
[91.210] P55 disk_size=21
```

VFS sees 36 bytes (2 dir entries) but `ip->i_disk_size`=21
(1 entry).  After flush, disk shows 21.  **`ip->i_disk_size`
LAGS the actual VFS state**, and iflush serializes the lagging
value to disk, losing the second entry.

Full trace in `/tmp/sess27-p55-p56-trace.md`.

This **localizes Mode A to a synchronization bug between VFS
inode->i_size and XFS ip->i_disk_size during dir-entry
modifications**, NOT to the flush chain.  No matter how many
log_force/ail_push/flush cycles we add, iflush will write the
stale `ip->i_disk_size` value.

**Sess27 follow-up experiment**: added P58-INSTR to fire if
`if_format==LOCAL && disk_size != if_bytes`.  In a 5/5 PASSING
run (srcversion `2F26B87536D83AC4083DA0C`), P58 did NOT fire —
meaning **`if_bytes == disk_size`** in all observed cases.  But
P56 still shows `vfs_size > disk_size` (vfs=36, disk_size=21,
if_bytes=21).

So the divergence is between **VFS inode->i_size and XFS's
ip->i_disk_size + ip->i_df.if_bytes** (which are consistent with
each other).  XFS's view says "21 bytes inline = 1 entry", VFS
says "36 bytes".

This is even weirder — VFS i_size is INFLATED beyond what XFS
actually has stored.  Possible explanations:
1. VFS i_size was set during an earlier reload to a higher value
   that has since been overwritten by a different peer's smaller
   dir state, but VFS i_size wasn't re-synced.
2. A code path bumped VFS i_size without touching XFS state
   (would be a real XFS bug).
3. Compiler-reordering / lazy-update artifact.

Note: in this 5/5 PASS run, the divergence was observed BUT no
Mode A surfaced.  So the divergence is necessary-but-not-sufficient
for Mode A.  Sess28 to find the additional precondition.

**Sess28 priority**: trace `inode->i_size` updates AND
`ip->i_disk_size` updates separately around xfs_create, BAST,
and reload.  Find where they diverge and whether the divergence
correlates with Mode A.

## SESS27 P59-INSTR — AIL is EMPTY at bast_process time

srcversion `2B1D03CF39D4F3F3442684F` adds P59-INSTR which logs:
- `in_ail` — is the inode log item in AIL?
- `pinned` — is ip->i_pincount > 0 (transaction in flight)?
- `ili_fields` — pending log fields

Trace from a Mode A failure (round 2 fail iter 5):

```
[146.6] P56 vfs=6  disk_size=6  P59 in_ail=0 pinned=0 ili_fields=0x0
[146.6] P55 disk_size=6
[148.6] P56 vfs=21 disk_size=21 P59 in_ail=0 pinned=0 ili_fields=0x0
[148.6] P55 disk_size=21
[151.1] P56 vfs=6  disk_size=6  P59 in_ail=0 pinned=0 ili_fields=0x0
[151.1] P55 disk_size=6
[151.1] P56 vfs=6  disk_size=6  P59 in_ail=0 pinned=0 ili_fields=0x0  ← duplicate release
[151.1] P55 disk_size=6
[152.7] xfs_dir_removename rc=-2 ← FAILURE
[153.0] P56 vfs=21 disk_size=21 P59 in_ail=0 pinned=0 ili_fields=0x0
```

**At every bast_process release, in_ail=0**.  The AIL is genuinely
empty — no missing flush.  ip->i_disk_size matches memory matches
disk (P55 confirms).  By the time bast_process runs, xfsaild has
already iflushed any pending changes.

**This RULES OUT** the "incomplete flush at release" theory.

## What Mode A actually is (sess27 final theory)

Looking at the trace at 152.7 fail point:
- T1 attempts `rm perf_t1`.  dentry resolved name="perf_t1" → ip=131.
- xfs_dir_removename(dp=128, "perf_t1") returns -ENOENT.
- After failure (153.0), P56 shows vfs=21 disk_size=21 — dir has
  ONE entry but the lookup didn't find perf_t1.

Hypothesis: T1's i_df was reloaded between T1's `dd` create
(which added perf_t1) and T1's `rm` (which tried to remove it).
The reload replaced T1's i_df with disk content.  Disk had ONE
entry but it was peer's perf_t2 — T1's perf_t1 was never on disk
or was OVERWRITTEN by T2's later flush.

For T2 to overwrite T1's perf_t1, T2's i_df must have lacked
perf_t1 at T2's iflush time.  For that, T2's reload (after acquiring
from T1) must have read disk BEFORE T1's iflush of perf_t1
completed.

DLM is supposed to serialize: T1 flushes-then-releases, T2
acquires-then-reloads.  Window for T2 to read stale disk only
exists if T1's "flush" doesn't fully persist before T1's release.

P55 showed disk has T1's value AT release time (within the bast_process
view).  So T1's flush DID complete from T1's perspective.

But T2's reload via FUA bypasses kernel page cache and reads
from platter.  If the LIO target / qemu vhost-scsi has write-back
caching that delays platter commits despite blkdev_issue_flush,
T2's FUA read may see pre-T1 disk content.

This brings us back to the SAME class of bug as sess26 root
cause #2 (kernel SCSI persistence inconsistency under stress) —
just on the WRITE side instead of the CAW side.  Sess28 should:
- Verify with userspace SG_IO write+FUA-read tests under load.
- Compare LIO target's `emulate_write_cache` and `emulate_fua_*`
  flags' actual behavior.
- Consider whether qemu vhost-scsi caches writes inside the
  guest virtio layer.

## Additional sess27 P56 trace observation (10-round sample)

Long trace from a failing run shows:
```
[463.8] vfs=6  disk_size=6  → both empty (post-rm or init)
[465.8] vfs=21 disk_size=21 → 1 entry both (post-create)
[468.2] vfs=6  disk_size=21 → memory empty but XFS still tracks 21
[470.2] vfs=36 disk_size=21 → memory says 2 entries, XFS still 21
[472.6] vfs=6  disk_size=21
[474.7] vfs=36 disk_size=21
[477.2] vfs=6  disk_size=21
[479.3] vfs=36 disk_size=21
... (oscillates)
```

Memory's vfs_size oscillates 6/21/36 (empty/1/2 entries) but
`ip->i_disk_size` stays at 21 even when vfs says 6 (empty).  This
means our LOCAL `ip->i_disk_size` is NOT being updated by the
removename + commit cycle.  When peer reads disk, disk has 21
(1 entry).  When THIS node tries to look up entries, internal XFS
checks against `ip->i_disk_size`=21 — but the actual `i_df.if_data`
may be in an inconsistent state.

This is even more bizarre.  Sess28: trace every modification of
`ip->i_disk_size` and verify it's updated by xfs_dir2_sf_removename
(upstream line 580).  If updates are happening but reverted, find
the revert path.  If updates aren't happening, find the failing
transaction.

## Sess27 attempted fix for AIL push deadlock — REVERTED

Tried srcversion `96111F3F520006527DE8B74`: added
`xfs_ail_push_all_sync_timed` in `xfs/xfs_trans_ail.c` (bounded
variant returning -ETIME on timeout) and used it with 5s cap in
`mxfs_dlm_ag_bast_work_fn`.  Hypothesis: FUA hooks would mitigate
peer reads of partially-drained state.

**Result: 5×256 FAILED iter 3 with corruption** (xfs_dir_removename
returns ENOENT → trans_cancel → "Corruption of in-memory data 0x8" →
SHUTDOWN).  Mode A surface re-emerged because peer T2 read T1's
dir state from disk before T1's iflush completed — even with FUA,
the on-disk content was stale because xfsaild hadn't pushed the
cluster buffer yet.

**Conclusion**: AIL push must be unbounded for correctness.  The
deadlock is a real architectural bottleneck that needs a different
fix:
- Per-AG AIL filtering (only push items in this AG)
- Or ditch xfs_ail_push and rely on per-AG buflist drain alone
  (requires understanding what items actually need cross-node
  coherency vs which are safe to leave in AIL)
- Or break the deadlock at the lock layer (e.g., release AG=0
  before AIL push, then re-acquire after — but that needs full
  transaction redo on the other node's behalf)

**Sess27 final code state**: `xfs_ail_push_all_sync_timed` helper
remains in `xfs_trans_ail.c` (unused) for sess28 use.  Bast work
fn reverted to `xfs_ail_push_all_sync` (unbounded, deadlocks at
512MB but works at 256MB).  srcversion at sess27 end: post-revert
build (4A96428BE8AF796387D23FB or whatever rebuild produces).

## Mode A specific evidence (sess27 final trace)

```
[108.217994] DLM reload ino=128 disk_fmt=1 disk_size=21 ...
[108.218008] P6-INSTR reload-post ino=128 mem_entries=1 first_entry="perf_t2" mem_size=21
[108.218011] P41-INSTR ino=128 dcache drained
[108.218266] MX-INSTR remove dp=128 ip=131 name="perf_t1" xfs_dir_removename rc=-2
```

T1 just created perf_t1 (its own file, ino=131).  T1 tries to rm
perf_t1.  But T1's reload of dir 128 from disk shows ONLY perf_t2
(T2's file, mem_entries=1).  T1's create of perf_t1 was LOST from
the dir — meaning T2's flush of dir 128 (after adding perf_t2)
overwrote T1's perf_t1 entry.

Mechanism: T2 held dir 128 → T2 read from disk → T2 saw stale dir
(lacked perf_t1) → T2 added perf_t2 → T2 flushed (perf_t2 only) →
disk lost perf_t1.

For T2's read to be stale, T1's create commit was either (a) not
flushed to disk by T1's bast_process, or (b) flushed but read from
some cache that hadn't seen the write.

bast_process for inodes already does:
```c
xfs_log_force(mp, XFS_LOG_SYNC);
xfs_ail_push_all_sync(mp->m_ail);
blkdev_issue_flush(mp->m_ddev_targp->bt_bdev);
```

Plus xfs_buf_stale + xfs_imap_to_bp re-read + second blkdev_issue_flush.
This SHOULD be sufficient.  But Mode A still surfaces.

Sess28 trace points to add:
1. Snapshot dir 128 disk content INSIDE bast_process before release.
2. Snapshot dir 128 disk content on the next acquirer's reload-pre.
3. Compare.  If different → block-layer/target-side issue.
   If same → AIL push didn't persist what we thought.

## SESS27 P55-INSTR EVIDENCE (added at sess27 end)

Built srcversion `605DAD5BCDCEF002D717C1B` with P55-INSTR — a
post-`blkdev_issue_flush` snapshot of the dir inode's on-disk
size/nlink, taken inside `mxfs_dlm_bast_process` (xfs_mxfs_dlm.c
~line 135).  Pure diagnostic, no behavior change.

5×256 fresh mkfs run with this build — failed iter 4 (Mode A).
P55-INSTR trace from the failing run:

```
86.788  BAST-DISK ino=128 disk_size=21 nlink=2
88.171  BAST-DISK ino=128 disk_size=21 nlink=2
90.487  BAST-DISK ino=128 disk_size=21 nlink=2
92.426  BAST-DISK ino=128 disk_size=21 nlink=2
94.825  BAST-DISK ino=128 disk_size=6  nlink=2  ← EMPTY DIR ON DISK
97.036  BAST-DISK ino=128 disk_size=21 nlink=2
99.802  BAST-DISK ino=128 disk_size=6  nlink=2  ← EMPTY again
99.804  BAST-DISK ino=128 disk_size=6  nlink=2  ← back-to-back empty
```

dir 128 LOCAL fmt: size=6 = header-only (no entries); size=21 =
header + 1 entry.  At several release points, dir is being
released with an EMPTY on-disk view despite our local `xfs_create`
having added an entry just before.

**This proves**: the `xfs_log_force(SYNC) + xfs_ail_push_all_sync +
blkdev_issue_flush` chain in bast_process is NOT reliably
persisting recent dir modifications.  The committed-but-not-yet-on-disk
state is exposed when we release the lock.  Peer reads disk →
sees empty dir → adds peer's entry → writes (peer's entry only) →
disk now has only peer's entry.  Originator's entry is silently
lost.  Mode A symptom (rm finds ENOENT) follows.

Root cause must be one of:
1. xfs_log_force returning before items are in AIL (CIL→AIL window).
2. xfs_ail_push_all_sync racing with new commits (unlikely — bast
   fires when no holders, no concurrent modifies).
3. Block layer / LIO target / qemu host caching writes despite
   blkdev_issue_flush.
4. xfs_buf for inode cluster has flag interactions that prevent
   the actual disk write.

**Sess27 EXPERIMENT — CIL→AIL race FALSIFIED**:
Tested srcversion `CAD6E38659EB5B59574DF67`: added a second
`xfs_log_force(SYNC) + xfs_ail_push_all_sync + blkdev_issue_flush`
cycle after the first.  5×256 fresh-mkfs × 5 rounds: 2/5 PASS = 40%.
WORSE than the 3/5 = 60% baseline.  Hypothesis disproven.  By the
time the FIRST ail_push_all_sync returns, the AIL is genuinely
empty — adding a second cycle gains nothing and may even slow
things enough to surface other Mode A timing issues.

**Better sess28 hypotheses**:
1. **Cluster buffer write race**: dir 128 inode shares a cluster
   buffer with neighbors (e.g., inode 131 perf_t1).  xfsaild's
   iflush might submit the buffer with the snapshot of in-memory
   state at iflush time, not necessarily including all log-replayed
   modifications.  P55-INSTR shows disk_size=6 — the cluster buf
   write didn't carry our dir update.
2. **bast_process call ordering**: Maybe bast_process fires while
   the dd's xfs_create commit is mid-flight.  ilock_excl release
   should follow commit, but what if there's a path where they
   interleave with the BAST-arrival path?  Specifically, dd commits
   and proceeds to write 256MB; while writing, BAST arrives, dir
   ilock has dropped to NL but creates' buffer items might not be
   in AIL because the FIRST log_force happens later.
3. **Concrete sess28 instrumentation**:
   - Add P56-INSTR: snapshot in-memory dir 128 i_size + entry
     count IMMEDIATELY before log_force and after each call in
     the chain.
   - Add P57-INSTR: walk AIL and count items pertaining to inode
     128's cluster buf, before/after each step.
   - Compare: if memory says 21 entries but disk says 6, the chain
     failed to persist.  If memory also says 6, the dir mod was
     never properly committed before bast_process started.


## Open architectural issue (sess28 priority-0)

`xfs_ail_push_all_sync` in `mxfs_dlm_ag_bast_work_fn` is the
bottleneck.  Two possible fixes:

1. **Per-AG AIL push**: walk the AIL and push only items belonging
   to the AG being released.  Requires augmenting xfs_log_item with
   AG affinity tracking.  Most correct, most invasive.

2. **Non-blocking push**: use `xfs_ail_push` (non-sync) + short
   timeout.  Risk: if items haven't reached disk, peer reads may
   see stale state — but FUA hooks (sess22) ensure peer reads go
   to disk, so this may be acceptable.  Less invasive.

3. **Kill the push entirely**: phase 2's `pag_mxfs_alloc_buflist`
   drain + `blkdev_issue_flush` already covers AG-meta.  Inode
   data writeback should be handled by inode BAST chain (separate
   from AG BAST).  Need to verify no corner case relies on the
   sync push.

## What did NOT need changing for TCP
- `xfs/xfs_mxfs_dlm.c` — peer-joined flush, AG bast, inode reload
  paths all work unchanged because they go through the v5 abstraction.
- Wire-protocol structs (mxfs_dlm_msg_hdr, lock_req/resp/bast/release)
  — same as userspace.
- peer.c, dlm.c, discovery.c, lease.c — already in kernel build,
  no changes needed.

## Key files
- `/src/mxfs/dlm/v5_mount.c` — TCP transport branch, callbacks,
  dispatch wrappers, peer-joined ordering fix.
- `/src/mxfs/VERSION` — 0.3.111.

## What did NOT need changing for TCP
- `xfs/xfs_mxfs_dlm.c` — peer-joined flush, AG bast, inode reload
  paths all work unchanged because they go through the v5 abstraction.
- Wire-protocol structs (mxfs_dlm_msg_hdr, lock_req/resp/bast/release)
  — same as userspace.
- peer.c, dlm.c, discovery.c, lease.c — already in kernel build,
  no changes needed.
