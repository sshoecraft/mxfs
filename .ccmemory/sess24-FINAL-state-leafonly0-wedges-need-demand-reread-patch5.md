---
name: sess24-FINAL-state-leafonly0-wedges-need-demand-reread-patch5
description: sess24 FINAL (CORRECTED): my DLM changes (asymmetric-MHT + fair-grant + queued_at) WEDGE nodes at >=4 (regressed 4/tcp 4/4->0/4 at DEFAULT params) ->…
metadata:
  type: project
---

## sess24 FINAL (CORRECTED) — tree REVERTED to keeper EF6000F0

### What I reverted and why
I added 3 DLM changes this session, all NOW REVERTED (tree rebuilds to srcversion **EF6000F0D53E6005E08F99D** == sess23 keeper, confirmed):
1. dlm/dlm.c queued_at-preserve across retry re-queue;
2. dlm/dlm.c FAIR-GRANT (queue a new request behind an older incompatible waiter) in both compat paths;
3. xfs/xfs_mxfs_dlm.c ASYMMETRIC MHT (`mxfs_dlm_mht_defer_bast(ip, requested_mode)` honoring PR-reader BAST immediately).
They PASS 2/tcp but **REGRESS 4/tcp dir_reuse 4/4 -> 0/4**: at DEFAULT params nodes 2-4 WEDGE (network-DOWN, hard kernel hang) + rc=-110, NO corruption (uf=0/hole=0). So my changes introduce a DEADLOCK/wedge that triggers at >=4 nodes. Prime suspect = asymmetric MHT (the MHT batching is load-bearing: it both masks the leaf/btree coherency bug AND prevents a release-timing deadlock; honoring PR BAST immediately breaks it). LESSON: GPT's "honor PR BAST immediately / fair-grant" is NOT safe to bolt onto this DLM as-is. Only prep_node.sh `blockdev --flushbufs` kept (harmless).

### CONFOUND CORRECTION (important)
The earlier conclusion "leaf_only=0 WEDGES nodes at 8" is UNRELIABLE — every leaf_only=0 run I did was on a build that ALSO carried my (wedge-causing) DLM changes. So the wedge may be from MY changes, not leaf_only=0. MUST re-test `dir_postread_reread=1 dir_postread_leaf_only=0` on the PRISTINE keeper EF6000F0 (now restored) to learn leaf_only=0's true effect (corruption-free? wedge? just slow/starved?).

### Solid, build-independent findings that STAND
- Storage is COHERENT (qemu cache=none/shareable/write-through) — data-block re-read is sound. [[sess24-BREAKTHROUGH-storage-coherent-datablock-reread-safe-residual-dlm-starvation]]
- On the keeper, 8/tcp dir_reuse dies of dir-block coherency corruption: stale-leaf DABUF-HOLE (EFSCORRUPTED) + xfs_dir2_data_use_free stale/torn-RMW-base corruption (xfs_dir2_data.c:1740). ~50% flaky fresh-boot.
- `leaf_only=0` (re-read data blocks on stale grant_gen) eliminated uf=0 AND hole=0 in the runs observed (corruption fix is real) — but those runs had my buggy DLM code, so the *downstream* failure (rc=-110/wedge) is not yet attributable.
- 1/tcp, 2/tcp pass on keeper; 4/tcp dir_reuse passes on keeper (4/4, sess23); 8/tcp is the lone blocker.

### NEXT STEPS (priority order)
1. **Re-test leaf_only=0 on PRISTINE keeper EF6000F0 at 8 nodes, clean boot** — check corruption AND network/wedge AND timing. Determines whether leaf_only=0 alone (no DLM changes) is viable.
2. If leaf_only=0 is corruption-free but only SLOW/starved (not wedged): implement Patch 5 (demand-driven RMW-only data re-read, keep leaf_only=1) to cut the per-handoff reload cost — template at xfs/libxfs/xfs_da_btree.c ~3796-3906, call site xfs/libxfs/xfs_dir2_node.c ~1959 (after xfs_dir3_data_read, before use_free). See [[sess24-gpt5.5-dlm-fairness-and-demand-reread-design]].
3. The PR-reader starvation (184s = exactly 60 retries × ACQUIRE_WAIT) needs a FAIRNESS fix — but NOT the asymmetric-MHT/fair-grant I tried (they wedge). Re-approach per GPT Patches 1-4 (persistent waiters, REAFFIRM barrier, local revoke_pending, no-shutdown-on-timeout) CAREFULLY with per-change 4/tcp regression validation BEFORE 8/tcp.
4. Diagnose the wedge: VMs use unlogged serial pty (`<serial type='pty'>` -> /dev/pts/N). To capture a kernel hang/panic stack, reconfigure to `<serial type='file' path=.../console.log>` (virsh edit + restart) or attach `cat /dev/pts/N` before the run. Without this the wedge stack is invisible.

### Methodology
ALWAYS `virsh destroy+start test1..N` for a CLEAN boot before a trusted run (single PASS != proof; ~50% flaky; 2nd consecutive run fails on stale bdev cache). Validate EVERY DLM change at 4/tcp (where the wedge first appears) BEFORE 8/tcp.
</body>
