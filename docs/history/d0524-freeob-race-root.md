<!-- sess465: chain-88 8/caw test1 fence ROOT = D-0524 lost-update race free_commit vs 'flushed' discharge (FREE_PENDING stuck -> P-FREEOB-REFUSED shutdow… -->
# sess465 — D-0524 root (chain 88 8/caw board, run 20260902T074512Z, 0.63.0 sv 6FBBCDF6)

## What happened (NOT a false death)
test1 (slot 0, node 2477736485) shut ITSELF down at 07:50:33 in dir_reuse round 4:
`P-FREEOB-REFUSED ag=39 path=bast-inline unpublished=1` -> `xfs_force_shutdown` at
`mxfs_ag_release_publish_gate` (xfs_mxfs_dlm.c:47838-47841) -> P-SESSION-POISON ->
P-WITHDRAW -> P163-WITHDRAW-STAMP slot=0. test8 (slot 3) saw P163-WITHDRAW-SEEN and fenced
(P236-FENCE-INTENT -> P-PR-FENCE EXCLUSION PROVED -> P236-FENCE-CERTIFIED); test5 (slot 1)
replayed slice 0 (complete 07:50:40, intents=0); all survivors P163-RECOVERED 07:50:41-42.
test1's P305-RESV-HEALTH SELF_GONE / P277 / P131-SELF-FENCE at 07:50:36 = it observing its own
fence. Zero heartbeat/lease anomalies on test1 before the shutdown. Fence = designed consequence.

## The defect (D-FREEOB-COMMIT-VS-FLUSHED-DISCHARGE-RACE-PENDING-STUCK-FAILCLOSED-SHUTDOWN-0524, critical)
ino 327155847 (AG 39, agino 0x87). Line order in kernlog_test1 (88094-88142):
- 88112 xfsaild copy-in of the UNLINK image (P240-COPYIN-ID, freeob==0) -> xfs_inode.c:8992 sets
  MXFS_IF_PUBOB_FLUSHED for that image; write submitted (88123-88129, same bp for slots 0-6).
- 88132-88139 completion (xfs_iflush_finish) walking the buffer's inodes (CLAIM-CLEAR durable for
  slots 0-6) INTERLEAVED with rm's ifree of slot 7: 88138 P150-FREE-IBT off=7 (freeob=1 already,
  xfs_inode.c:4286), 88142 P82-REM.
- completion reaches slot 7: xfs_inode_item.c:1154 -> mxfs_pubob_discharge('flushed') ->
  xfs_mxfs_dlm.c:37241 sees freeob==1 -> mxfs_pubob_free_pending (kind=FREE_PENDING, freeob=1).
- rm commit: xfs_inode.c:4349 reads freeob==1 -> mxfs_pubob_free_commit (kind=FREE, freeob=2).
Neither pair is atomic (freeob read/written OUTSIDE m_mxfs_pubob_lock, kind inside) -> lost
update: FREE overwritten by FREE_PENDING, freeob back to 1. End state observed: no P55C-FREE-FLUSH
ever, P88-PUBOB-RECLAIM-REFUSED clean=1 flushed=0 nlink=0 x9, gate 'P-FREEOB-PENDING ... ifree in
flight' every 2 s for the full 2+8x2 s budget -> refusal. Mirror ordering (commit's freeob=2 lands
first) -> discharge's 37245-37286 arm DROPS the committed FREE obligation silently = D-0351
exposure. Both orderings must be fixed.

## Fix plan (design consult sess465)
1. Decide on the STORE ENTRY kind under m_mxfs_pubob_lock in free_pending/free_commit/discharge;
   write i_mxfs_freeob under the lock. 'flushed' discharge of a pre-free image (staged with
   freeob==0) is a no-op once kind is FREE_PENDING/FREE (record the staged kind at copy-in
   xfs_inode.c:8992; compare at completion). FREE image completion (staged freeob==2 && mode==0)
   still discharges.
2. Gate self-heal + tripwire: FREE_PENDING with MXFS_IF_FREE_COMMITTED on the in-core inode ->
   P-FREEOB-PENDING-COMMITTED, promote to FREE under the current tenure epoch, continue.
3. Fault-injection knob widening the commit window (msleep between the freeob read and the
   write) to reproduce deterministically under dir_reuse_coherency 8/caw; then verify the fix.

## Harness note
run.sh (sess465) now writes the failure artifact to tests/evidence/run_<name>_<RUN_ID>/ with
gzipped kernlogs and prints THAT path (was: printed a deleted mktemp path, kept a raw copy in /tmp).
