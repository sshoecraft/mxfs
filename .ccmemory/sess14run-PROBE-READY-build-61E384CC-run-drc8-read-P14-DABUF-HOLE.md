---
name: sess14run-PROBE-READY-build-61E384CC-run-drc8-read-P14-DABUF-HOLE
description: sess14(ccloop) END: build 61E384CC has the P14-DABUF-HOLE smoking-gun probe at xfs_da_btree.c invalid_mapping. NEXT: clean all 8 nodes, run dir_reuse…
metadata:
  type: project
---

## sess14 (ccloop) END — probe-ready build for next session

Build **61E384CC** (= validated AA8C4934 runtime + inert dir_modify_extent_reload param + the new P14-DABUF-HOLE diagnostic probe; all additions are read-only/gated so runtime behavior == validated state for 1/2/4 tcp). NOT yet deployed/run.

### IMMEDIATE NEXT STEP (just do this)
1. Clean all 8 nodes: `for n in test1..test8; do ssh $n 'umount /mnt/shared; rmmod mxfs; dmesg -c'; done`. If a node shows WEDGED, `virsh -c qemu:///system destroy/start` it.
2. Reproduce the 8-node DABUF storm: easiest is the in-suite path — `TEST_TIMEOUT=600 ./run.sh 8 tcp` (dir_reuse fails after crash_consistency with the DABUF storm) OR run dir_reuse 8/tcp repeatedly. (Standalone dir_reuse 8/tcp at 600s PASSES, so the storm needs the in-suite contention/churn.)
3. `dmesg | grep P14-DABUF-HOLE` on the failing node (test4/test8 had hundreds). Read: ino, bno, fmt, nextents, **dir_gen vs loaded_gen**, evicted_incarn, reload_armed, comm.

### What it proves
- If `loaded_gen < dir_gen` at the hole → the extent map was NOT reloaded for the gen the leaf was refreshed to = decoupled async-evict-ring gen-bump vs extent-map-reload. ROOT PROVEN.
- `comm` tells the operation (ls=readdir, the file ops=create/lookup).
- Then FIX: ensure i_dlm_dir_gen advances ONLY together with an extent-map reload, OR arm MXFS_IF_DIR_RELOAD whenever the evict-ring bumps dir_gen so the next access reloads the inode (extent map) before xfs_da_read_buf re-fetches leaf/data blocks. (Reconciles sess68 "maps agree at MODIFY-prelock" — this hole is on readdir/lookup paths that have no modify-prelock extent reload.)

### Captured signature (build 1A0A8F9C, before this probe): `xfs_dabuf_map: bno 2 inode 537965` / `br_startoff 2 br_startblock -2 (HOLE) br_blockcount 1`, amid a P103-RELOAD-REUSE-ADOPT flood (ABA inode reuse, gen+1, adopting disk_size=0).

Criterion: 1/tcp ✅ 2/tcp ✅ 4/tcp ✅ 8/tcp ✗ (12/17). NOT met.
See [[sess14run-INSTRUMENTED-8node-DABUF-hole-signature-bno2-HOLE-plus-P103-reuse-adopt-flood]] [[sess14run-SESSION-SUMMARY-and-next-priority]].
