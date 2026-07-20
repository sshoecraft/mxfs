---
name: sess47-DABUF-HOLE-healed-by-tenure-evict-next-wall-is-release-pipeline-wedge
description: sess47(ccloop): dir_tenure_evict=1 ELIMINATES reused-dir DABUF_HOLE shutdown. Next wall ROOT-FOUND = release vs xfs_end_io DEMOTING-state ILOCK deadl…
metadata:
  type: project
---

## sess47 (ccloop 4cb2d0a2) — DABUF_HOLE healed; next wall ROOT-FOUND

Build **E9D1B1CB** (two KEEP wedge fixes — see
[[sess47-FIXED-two-8tcp-wedges-relsafe-lock-and-ilockend-defer]]). 8/tcp dir_reuse,
reboot-clean + DRC_STREAM NFS capture.

### reused-dir DABUF_MAP_HOLE shutdown = sess20 stale-LEAF tear (PROVEN)
P14: `loaded_gen==dir_gen` (extent map FRESH); data blocks 1,2,3 are legal HOLES
(peer freed them); the **cached LEAF still references the freed blocks** → maps
bno=1,2,3 → hole → xfs_da_btree.c:2876 force_shutdown, CASCADES cluster-wide
(round 4). Served stale because `comm=dd dlm_mode=3` (EX) and the read-time leaf
re-read hook is disabled for owned_ex (dir_unpub_skip=1).

### HEAL: `dir_tenure_evict=1` (runtime modarg) → 0 holes, 0 shutdowns cluster-wide
Enables EX-side prior-tenure leaf revalidation (owned_ex-independent, epoch-gated,
NOT per-op slow). P23-TENURE-EVICT fired 18×. THE correctness fix for the leaf tear.
(dir_postread_reread=1 also heals but is too slow — per-op leaf re-read holds dir
VFS i_rwsem → openers block → timeout.)

### NEXT WALL — ROOT FOUND (RULE 4, full stacks captured): release vs xfs_end_io
DEMOTING-state ILOCK DEADLOCK on a data-file inode with pending unwritten-extent
conversion. With E9D1B1CB + dir_tenure_evict=1, rank6 wedged → timeout. The cycle:
- bast kworker (mxfs-ino-bast) releasing inode X:
  `mxfs_dlm_bast_process+0xf0a → filemap_write_and_wait_range → folio_wait_writeback
   → io_schedule` — WAITS for X's dirty-page writeback to complete.
- xfs-conv kworker completing that writeback:
  `xfs_end_io → xfs_end_ioend → xfs_iomap_write_unwritten → xfs_trans_alloc_inode →
   xfs_ilock → mxfs_dlm_ilock_begin` — BLOCKED. X is in DEMOTING state and xfs_end_io
   is a DIFFERENT thread than the demoter kworker, so it doesn't match
   `i_dlm_demoter==current` and goes into the DEMOTING wait.
- ∴ releaser waits for writeback that needs the ILOCK the releaser is holding →
  hard deadlock → node wedge → declared dead. `sync` also blocks.

This is a data-file release-ordering bug: a node releasing its OWN inode must let its
OWN in-flight I/O-completion unwritten-extent conversion finish (the EX grant is
STILL held until unlock — the conversion needs no new grant). Likely PRE-EXISTING
(postread_reread=1 hit a cluster_durable-area wedge too); exposed now that the leaf
corruption is healed so the test reaches data-heavy rounds. May be amplified by FIX-2
funneling releases through the bast wq — but the ILOCK cycle is the real root.

### NEXT SESSION (RULE 4 — strong lead):
The DEMOTING-state ILOCK wait (mxfs_dlm_ilock_begin) must admit the SAME-NODE
xfs_end_io unwritten-extent conversion while the grant is still held. Options:
(a) extend the demoter-skip so an I/O-completion conversion on a DEMOTING inode whose
    grant this node still holds proceeds (it modifies under the held EX, pre-unlock);
(b) bast_process must DRAIN pending unwritten-extent conversions (or do the page
    flush in a way that doesn't wait under a state that blocks the conversion) BEFORE
    filemap_write_and_wait / before unlock.
Keep E9D1B1CB + `dir_tenure_evict=1`. Repro: reboot-clean loop +
`MXFS_EXTRA_MODARGS="dir_tenure_evict=1" MXFS_TEST_ENV="DRC_STREAM=1" ./run.sh 8 tcp dir_reuse_coherency`.
See [[sess47-FIXED-two-8tcp-wedges-relsafe-lock-and-ilockend-defer]] [[sess20-PROVEN-dabuf-hole-is-stale-leaf-fixed-by-postread-leaf-only]].
</body>
