---
name: sess10-gemini-shared-epoch-lastwriter-fix-design
description: sess10 Gemini RULE-5 design #2: shared on-disk dir EPOCH + LAST_WRITER discriminator + synchronous publish kills the heartbeat-gen-lag stale-base dir…
metadata:
  type: project
---

## For the [[sess10-tcp-dlm-scaling-heartbeat-gen-lag-root]] lossy-heartbeat stale-base dir RMW. Gemini (2nd consult, native-timing evidence). RULE-5 justified.

## Core: replace the LOSSY async heartbeat gen with an AUTHORITATIVE shared ON-DISK dir epoch.
Add to the dir dinode (durably written every dir-EX commit), keep in-core `i_mxfs_loaded_epoch`:
- `di_mxfs_epoch` (u64 monotonic change counter)
- `di_mxfs_last_writer` (u32 node id of committer)
Do NOT reuse XFS `di_changecount` (it mutates in-core for VFS i_version outside cluster logic).

## Fast-path gate (at START of dir-EX modify, before touching in-core shortform fork; SHARED dirs only):
FUA-read the dinode -> d_epoch, d_writer.
```
if (d_epoch > i_mxfs_loaded_epoch) {
  if (d_writer == MY_NODE) {           // our OWN async publish caught up
      i_mxfs_loaded_epoch = d_epoch;   // advance, do NOT reload  <-- kills approach-B destage-race revert
  } else {                             // PEER durably wrote
      if (inode_has_item_in_ail(ip))   // HARD CONFLICT (we have un-destaged local mods)
          force_synchronous_publish_or_slowpath();  // see below — make unreachable
      else { reload_shortform_from_LUN(ip); i_mxfs_loaded_epoch = d_epoch; }  // wholesale reload SAFE
  }
}
```
Then modify in-core, `di_mxfs_epoch++`, `di_mxfs_last_writer=MY_NODE`, commit + log_force + bwrite + blkdev_issue_flush (publish-before-notify already does the durable half).

## The magic bullet: `d_writer == MY_NODE` distinguishes "disk ahead because MY last op's async flush finished" (don't reload) from "disk ahead because PEER wrote" (reload). This lets you DROP the buggy in-AIL gate without reverting your own change.

## Make the HARD-CONFLICT branch unreachable: for SHARED CACHED dirs, make the publish SYNCHRONOUS per VFS op (don't return until bwrite+flush done) so `inode_has_item_in_ail` is ALWAYS false at the next op start => wholesale reload always safe => no 3-way merge needed.

## REJECTED by Gemini: "flush-self-then-FUA-reload" WITHOUT the last_writer check = DANGEROUS: if you blindly flush your in-AIL add over a LUN that already has the peer's delete, you PHYSICALLY destroy the peer's delete on the block device. The last_writer discriminator + synchronous-publish is the safe path.

## Cost: FUA 512B dinode read per dir-EX MODIFY (not reads), SHARED dirs only, ~10-20us, does NOT drop the DLM lock => NOT the approach-A starvation (that dropped the lock => ms-scale BAST/ping-pong).

## Impl risk: on-disk dinode format fields (need free/padding space, XFS-compat envelope), FUA-read primitive (mxfs_pal_scsi_read_fua_bdev exists), reload integration (mxfs_dir_sf_refresh_if_disk_differs ~xfs_mxfs_dlm.c:6175). Validate vs RELIABLE repro: `./run.sh 2 tcp` full suite (tcp_dlm_scaling fails ~1/2 warm). Smaller first step to test: make publish synchronous-per-op + drop IN_AIL gate — but MUST pair (sess9 approach B alone regressed).
