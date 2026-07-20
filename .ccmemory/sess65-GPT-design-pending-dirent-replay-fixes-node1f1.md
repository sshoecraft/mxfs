---
name: sess65-GPT-design-pending-dirent-replay-fixes-node1f1
description: sess65 GPT-5.5 design for node1_f1 double-block0 orphan: per-dir pending-positive-dirent list, replay missing ones into adopt via create's own tx. Re…
metadata:
  type: project
---

## sess65 — node1_f1 root NAILED + GPT-5.5 convergent fix design

### PROVEN ROOT (this session, byte-level, RULE 4)
dir_reuse_coherency 4/tcp loses exactly node1_f1 (rank1's FIRST file), readdir=399/400, **missing even on rank1 itself**. node1_f1 IS durably written to daddr=120 (AG0, rank1 affine) but the dir's winning logical-block0 on disk is a DIFFERENT physical block (e.g. daddr=33491656/2093296/4186520, high/peer AGs) that never held node1_f1. = dir logical-block0 DOUBLE-ALLOCATION from concurrent sf->block conversion. rank1 creates node1_f1 (shortform), converts -> block0@120; a peer converts its own stale shortform -> block0@high-AG (wins on disk); rank1's NEXT create (node1_f2) reload-ADOPTS the peer's block0 (lacks node1_f1), DROPPING node1_f1 from rank1's in-core. node1_f2..f50 added to peer block0 survive. The code's "post_release => disk is a strict SUPERSET of our entries" invariant is FALSE here — the peer's competing block0 orphaned ours.

### merge_ours GAP (the specific code hole)
reload_inode's sess14 `merge_ours` (xfs_mxfs_dlm.c ~8152) snapshots+re-applies our in-core entries across adopt ONLY when BOTH in-core AND disk are LOCAL (shortform). It does NOT fire for in-core->disk BLOCK adopt, so our entries (node1_f1) are dropped.

### REFUTED this session (do NOT repeat)
- **Epoch-driven adopt for in-core-LOCAL dirs** (set genuine_handoff when epoch>valid_epoch && fmt==LOCAL): REGRESSION — node1_f1 lost EVERY round (adopting the node1_f1-less peer block0 harder/faster). "Adopt harder" is exactly wrong.
- **mxfs_dir_adopt_block=1** (pre-lock FUA adopt): P61/P62-ADOPT fired 0x — at the racing converter's moment disk is still shortform (peer hasn't published its block conv yet); true concurrent race, pre-lock can't see a not-yet-done conversion.
- **Truncate-path staleness guard (P65-STALE-TRUNC in xfs_setattr_size)**: fired 0x even broadened to di_nextents/di_size mismatch. The intermittent bnobt double-free (do_truncate->xfs_itruncate_extents->xfs_free_ag_extent bno+len>gtbno) is a SAME-incarnation stale extent-map CONTENTS (bmbt records), header matches — a dinode-header FUA check can't catch it. Build E3DFE11C carries this inert guard (consider removing). SEPARATE intermittent bug from node1_f1; high run-to-run variance (0-38 shutdowns same binary).

### GPT-5.5 FIX DESIGN (option a+c, the convergent one)
1. **Epoch-gate sf->block conversion**: a node may NOT call xfs_dir2_sf_to_block (or log a dir data fork) if its in-core dir base epoch < current EX-grant epoch — must reconcile first. Prevents the 2nd block0.
2. **Generalize merge_ours** to all transitions (LOCAL->BLOCK, BLOCK->BLOCK diff block0).
3. **Per-dir PENDING POSITIVE-DIRENT list** (the key): append (name,child_ino,gen,ftype) on every successful LOCAL createname into the parent; remove/tombstone on local unlink/rename-out; CLEAR on dir incarnation change (di_gen bump). Filter by parent incarnation + child gen still valid.
4. **Reconcile-before-modify**: when epoch stale -> capture ours, FUA-read+adopt disk fork with a NO-FREE path (mxfs_install_disk_fork_nofree — do NOT xfs_bunmapi/free the stale in-core mapping = that's the bnobt double-free; let orphan leak for scrub), set base_epoch=grant_epoch, then REPLAY pending local dirents missing from adopted fork via xfs_dir_createname using THE CREATE'S OWN tp + already-held EX grant (NO extra DLM acquire — that deadlocks rc=-110). Bounded (1-4 per tx; rest stay queued for next create).
5. Replay idempotent: lookup name; skip if present w/ same ino; validate child di_gen; re-add dirent only (no new inode, no nlink double-bump).
6. Hook replay near mxfs_dir_merge_peer_into_tp (which already does disk->ours; add ours->disk via the pending list). For the reproducer rank1 loses only node1_f1, so node1_f2's create replays it.
7. Allocator affinity (preferred_ag=dir_ino_ag) is NOT a correctness fix — fork update still races. Don't.

### Build state: E3DFE11C = baseline + inert P65 truncate guard. node1_f1 fix NOT yet implemented. See [[sess64-DECISIVE-ROOT-node1f1-orphaned-in-double-allocated-block0]] [[sess64-FIX-PATH-enable-disk-block-adopt-prevents-block0-doublealloc]].</body>
