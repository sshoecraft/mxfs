---
name: sess54-RESIDUAL-is-writeside-AIL-stale-flush-not-readside
description: sess54(ccloop) 8/tcp dir_reuse residual durable loss: read-side ALL clean (P28E/DOUBLEMAP/pcur0/KEEPGUARD/MEPZ=0) AND write-side tenure_reflush_skip=…
metadata:
  type: project
---

## sess54 — 8/tcp dir_reuse residual: NEITHER read-side stale-RMW NOR write-side reflush

### KEEPER build 8705E114 (net-positive, A/B PROVEN 2/4 vs baseline 1/4):
1. `mxfs_dir_addname_epoch_refresh = 1` (xfs_mxfs_dlm.c:5424) — safe data-block-only epoch
   consumption at the addname (xfs_dir2_node.c:2034).
2. FAIL-CLOSED on epoch regression (xfs_dir2_node.c:~2086): `mep==0 && b_epoch!=0` (dg_shadow
   slot evicted -> master epoch reset to 0) now treats the block STALE. ELIMINATED P54-MEPZERO.
Diagnostic probes added (capped, cheap): P54-KEEPGUARD, P54-MEPZERO, P54-DOUBLEMAP
(xfs_dir2_data.c:889 I/O-free in-core dir-block double-alloc detector), P28E cap 300->60000.

### RULE-4 RESIDUAL CHARACTERIZATION (drc_phantom_diag, many runs):
Durable single/contiguous dirent loss (LOOKUP_ENOENT REREAD_MISS on ALL 8 nodes = on-disk,
not enumeration-miss/transient). The lost dirent's BYTES are genuinely NOT in any durable
data block (readdir reads data blocks => short).  ALL read-side coherency probes CLEAN at the
addname: P28E diff=0 (in-core==platter every time, dir_addname_coherent=1 FUA ground-truth),
P28E pcur=0 (no extent-map divergence), P54-DOUBLEMAP=0 (no in-core dir-block double-alloc),
P54-KEEPGUARD=0, P54-MEPZERO=0.

### REFUTED write-side reflush this session (RULE-4): `dir_tenure_reflush_skip=1` (the
sess37 destaged-zombie in-AIL dir-DATA reflush skip, the most promising UNTESTED write-side
lever) → **3/3 FAIL** (round 1 1-loss, round 11 1-loss, round 18). Does NOT help. This
CONFIRMS sess50's refutation of dir_relepoch_skip ("loss occurs with 0 relepoch skips -> not
a pre-release reflush"). So the loss is NOT a stale in-core reflush either.

### THEREFORE (converges with [[sess50-NEXT-fix-dir_epoch-propagation-some-grant-path-delivers-0]]
and sess50 conclusion): the base is coherent at modify AND no stale image is reflushed ⇒ the
durable loss is a **DLM/transaction SERIALIZATION HOLE**, not a coherency-cache bug. Two
nodes' dir modifications are NOT being properly serialized so one durably erases the other's
dirent, despite DLM EX appearing exclusive (P42-STALEEX-SERVE=0, MX-DOUBLEGRANT=0 at the
master). Candidate holes to instrument NEXT:
- **ILOCK vs DLM-EX**: a node modifies the dir holding ILOCK while its DLM dir-EX was REVOKED
  mid-transaction (BAST during the create transaction) → a peer modifies concurrently. (See
  CLAUDE.md "ILOCK held across CAW poll" design tension.) Probe: log when a dir BAST/downgrade
  fires while a create transaction for that dir is IN-FLIGHT on this node.
- **Round-1 FRESH-dir growth** (the most reproducible MASS loss, 83 lost spread across nodes):
  shortform->block->leaf->node format conversions (P78 ~100/round) rewrite the whole dir; a
  node converting from a STALE in-core shortform/fork loses peer entries. Round-1 has NO prior
  tenure so tenure_reflush_skip/incarn-ABA can't apply. This is INODE-FORK reload staleness
  (P62-RELOAD-FORK-SHRINK family); epoch_adopt=1 would adopt the peer fork but is PROVEN
  shutdown (sess49) because it adopts a stale-SMALLER disk when WE are ahead.
- Decisive probe: at xfs_dir2_sf_to_block / da-format-conversion for ino<=256, FUA-compare the
  source (inode shortform or block) against the platter BEFORE converting; if in-core lags, the
  conversion is the clobber.

### High run-to-run variance (1 to 83 lost; rounds 1-23); slower runs (wall 449-531s) fail
more than faster (393-401s) = host-load/timing correlated. Marker NOT written (8/tcp dir_reuse
~50%). 1/2/4 tcp believed passing (sess48/sess58). See
[[sess54-FIX-addname-epoch-refresh-default-on-reduces-dirreuse-loss]].</body>
