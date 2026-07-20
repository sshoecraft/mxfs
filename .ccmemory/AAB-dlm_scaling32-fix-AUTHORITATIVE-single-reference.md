---
name: AAB-dlm_scaling32-fix-AUTHORITATIVE-single-reference
description: AUTHORITATIVE single reference for the dlm_scaling@32 fix (supersedes the 5 evolving memories). Root: resource_id lacks inode gen → reused inode inhe…
metadata:
  type: project
---

## dlm_scaling@32 FIX — AUTHORITATIVE single reference (ccloop 0d6e174d sess2, 2026-07-07, UNTESTED host-wedged)

Supersedes the evolution memories (read only for history): caw-HYPOTHESIS-…-slot-aliasing,
caw-FIX-DESIGN-…-resource-id-offset (REJECTED), caw-…-CONSTRAINT-mixed-ino-callers,
caw-…-BEST-approach-invalidate-…-dealloc, caw-…-REFINEMENT-piggyback-…-unlock. THIS is the current design.

### ROOT (code-confirmed): struct mxfs_resource_id (mxfs_common.h:60) = {volume, ino, offset, ag_number,
type} — NO inode generation. So a REUSED inode (same ino, new di_gen, possibly last owned by a DIFFERENT
node) byte-matches the prior incarnation's tombstone in caw_claim_inherit_epoch (dlm_caw.c:717) → inherits
the peer's last_ex_slot → on the new owner's EX, caw_grant_epoch_update (dlm_caw.c:669) sees last_ex_slot !=
my_slot → dir_epoch++ → i_dlm_dir_valid_epoch>0 → dir_priv_ex_skip gate (needs valid_epoch==0) DISENGAGES →
private-subdir FUA storm → dlm_scaling rate<50/s floor + node WEDGE. Pervasive at 32 (64k inode reuse/run),
rare at 16 (passes 16/16 alone). mkfs DOES zero CAW slots (disklock region) — the old cross-mkfs theory is
REFUTED; this is intra-run reuse.

### REJECTED approaches (do NOT use):
- "gen in resource_id.offset": FAIL-CORRUPT. It changes fnv1a_hash → slot INDEX depends on gen. But
  mxfs_v5_dlm_inode_lock has MIXED callers — some pass ip->i_ino (have gen), some pass raw ino
  (xfs_mxfs_dlm.c:318/19918/20154, no gen). If any can't supply a consistent gen, the SAME inode maps to
  DIFFERENT slots per path → within-node lock incoherence / lost mutual exclusion → corruption at scale
  (invisible at 1-2 nodes). Rejected.
- "sync CAW clear (find_slot FUA + CAS) at the free hook": SLOW (2000 frees/node × 2 FUA = defeats the fix)
  AND sess70 cascade risk (per-slot FUA on a sensitive thread blocked the heartbeat → fence → FS-shutdown
  cluster collapse — see mxfs_dlm_caw_purge_node header, dlm_caw.c:3501). Rejected.
- "pure-async (stage clear in eviction ring, apply later)": correctness WINDOW — a peer can realloc the
  freed ino before the async clear lands → stale inherit persists. Rejected alone.

### THE FIX (GFS2/OCFS2-validated: both bind inode generation into lock identity + invalidate at dealloc):
Clear the CAW slot's dir_epoch/last_ex_slot when the inode is FREED, by PIGGYBACKING on the unlock CAS that
already runs during the free — distinguish a FREE-release (write tombstone with dir_epoch=0/last_ex_slot=NONE)
from an IDLE-release (preserve them — load-bearing for genuine idle-gap cross-node coherence,
caw_tombstone_slot dlm_caw.c:694). ZERO extra I/O (reuses the unlock's CAS), synchronous-correct (the free's
inobt update, which gates realloc, is ordered after the release).
- Signal path: xfs_ifree already calls mxfs_dlm_note_inode_freed(mp, ip->i_ino, ip->i_generation)
  (xfs_inode.c:3994) → mxfs_v5_dlm_note_inode_freed(ctx, ino, gen) (v5_mount.c:1592, has {ino,gen,ctx}).
  Wire a "this ino is being freed" signal from there to the inode's unlock/tombstone path (an i_dlm flag,
  or mxfs_dlm_caw_mark_freeing(ctx->dlm_caw, ino) the next unlock consults).
- CAW ctx = ctx->dlm_caw. Model the slot clear+CAS on mxfs_dlm_caw_purge_dead_nodes (dlm_caw.c:3546, batched
  clear+CAS semantics). Param-gate `caw_epoch_free_reset` (default 0), FAIL-SAFE (default=115CCA8C behavior).
- OPEN detail for host-side tracing: the EXACT lock-release-vs-xfs_ifree ordering (is the inode's DLM lock
  still held at the free hook, or released earlier at inactivate/reclaim?) — trace it to place the clear at
  the right CAS. This is next-session step-1 work WITH the host.

### VALIDATE (with host): `scripts/dlm_scaling_diag.sh 32 "caw_epoch_free_reset=1"` → op-rate clears 50/s
floor + FUA read-IOPS drops (skip re-engaged); dmesg: private subdirs valid_epoch=0; no node wedge.
REGRESSION: dlm_scaling@16, cache_coherency@16/@32, dir_reuse — all rely on the idle-gap epoch inheritance
for GENUINE releases, which this fix must PRESERVE (only clear on FREE). Param default→1 after validation.
