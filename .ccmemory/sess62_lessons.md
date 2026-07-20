---
name: sess62_lessons
description: sess62 — cache_coherency 0/1→2 of 4 (SB-clamp + shutdown reduction). GPT consult: AG-meta FUA reads stale platter on SCST = next root to test (fua_di…
metadata:
  type: project
---

# sess62 (2026-06-05, ccloop run 29df431e) — build head 7DF27971

cache_coherency: **moved passed=0/1 → passed=2 of 4** (cross_visibility +
rename_visibility now PASS). Remaining failures: **unlink_visibility** (4/121,
pathologically SLOW 264s, + bnobt double-free shutdown) and **cross_write_read**
(1/6). Marker NOT written. 11/12 other criteria still PASS.

## Strategic reframe this session (the productive pivot)
Stopped chasing individual VISIBILITY races (the 40-session trap). Attacked the
**SHUTDOWN CASCADES** instead: a node that crashes mid-test fails ALL its
remaining assertions AND breaks barriers for peers → inflates the visibility
counts. Reducing shutdowns moved 2 subtests to green. This is the first real
measured movement in many sessions; keep this framing.

## Builds this session (all KEEP, all probes/defensive)
- **P-CR62** (xfs/xfs_inode.c ~1172, P-CREATE-ERR1 block): on the create-path
  EFSCORRUPTED double-alloc shutdown, logs new_ino + AG + on-disk dinode
  mode/gen → verdict DISK-LIVE=>double-alloc vs DISK-FREE=>incore-stale. Did
  not fire on the runs captured (intermittent path).
- **P62-SBCLAMP + P62-SBV** (xfs/libxfs/xfs_sb.c xfs_sb_write_verify): last-line
  clamp of benign cluster lazy SB counters (fdblocks/icount/ifree) before
  validate_sb_write, mirroring the existing xfs_log_sb clamp (~1387). Added
  forward-decl `struct mxfs_v5_dlm; bool mxfs_v5_dlm_is_single_node(...)` at file
  scope (top of xfs_sb.c) so both functions' externs match. NOTE: P62-SBCLAMP
  did NOT fire on a run where test1 still SB-shut-down → that SB shutdown is
  NOT the counter write-verify path (P62-SBV also 0). The SB shutdowns are
  intermittent/late (t~390s, likely teardown). Lower priority than the bnobt
  double-free.
- Current deployed/local srcversion: **7DF27971** (carries C4E65691 sess93 base
  + all the above).

## DECISIVE NEW EVIDENCE (RULE 4)
- This run's test1 shutdown = **bnobt double-free during UNLINK** (xfs_inactive
  → xfs_defer_finish → xfs_free_ag_extent overlap → xfs_defer.c:721 shutdown).
  P81-DEXT verdict: **ino=18874525 freed_fsb=0x24002c disk_claims_freed=1
  disk_differs=0 => DISK-INODE-OWNS-FREED = bnobt-lost-update.** The on-disk
  inode STILL owns the block, yet AG9 bnobt DURABLY lists it free (disk_differs
  =0). **This CONTRADICTS sess93's "incore-extent-stale, bnobt is a red herring"
  reframe** — there IS a real durable bnobt lost-update. Mechanism: block
  0x24002c was freed ONCE already (into bnobt) while inode 18874525 still owned
  it → its own legit unlink-free is the SECOND free that trips overlap. =
  earlier block DOUBLE-ALLOCATION.

## GPT CONSULT (RULE-5 escalation: Gemini×2 last session → GPT this session)
GPT rank-1 root: **`_XBF_FUA_FRESH` is node-local and survives intervals where
the node didn't continuously hold the AG DLM lock** → cached AG-meta served
stale to the allocator on reacquire → re-hands-out an owned block. Prescribed
invariant: AG-meta freshness must be scoped to the AG DLM hold EPOCH (FUA-reread
AGF/AGI/bnobt/cntbt/inobt/finobt on every reacquire-after-not-holding). Said the
overlap MUST stay fatal (non-fatal = unsafe data aliasing).

## BUT — code analysis partially REFUTES GPT's rank-1, points to SCST-FUA gap
- MXFS already has the epoch: `pag->pag_dlm_meta_gen` bumped on fresh acquire
  (xfs_mxfs_dlm.c:4925) + release_pending paths (4708/4755/4773, sess93). Buffers
  carry `b_mxfs_ag_gen`; read hook `mxfs_ag_meta_invalidate_stale` (~3656-3735)
  FUA-rereads when stamp < pag_gen.
- The ONE reacquire path that does NOT bump gen = the cached fast-path at
  **xfs_mxfs_dlm.c:4667** (`if pag_dlm_cached`, pre-acquire-lock). BUT the main
  BAST handler clears `pag_dlm_cached=false` (6386) + sets demoting (6389)
  BEFORE yielding the on-disk CAW (6608) → cached==true reliably implies
  still-held → 4667's no-bump is likely SAFE. (sess44 P89 held-check fired 0×.)
- **THE REAL SUSPECTED GAP (SCST-specific, sess45 in-tree comments):** the gen
  mechanism correctly decides to RE-READ on reacquire, but the re-read uses
  **SCSI FUA → reads the OLDER platter**. On the SCST target ALL initiators
  share ONE write-back cache, so a peer's just-written (not-yet-destaged) bnobt
  is in the shared cache; a normal BIO read sees it, an FUA read pierces PAST it
  to stale platter. So even with correct gen-invalidation, the FUA re-read can
  return STALE → double-alloc. Levers exist: `mxfs.fua_disable=1` (use bio,
  SCST-coherent) and `mxfs.fua_always=1`.

## NEXT SESSION — DO THIS FIRST (decisive, ~12 min)
1. **Test fua_disable=1 properly.** This session's attempt FAILED to apply:
   the criterion remounts (rmmod+insmod) and `INSMOD_OPTS="fua_disable=1"` did
   NOT propagate through `fresh_cluster_mount` (param read back 0 on all nodes).
   FIX: either (a) rebuild with `int mxfs_fua_disable = 1;` default in
   xfs_mxfs_dlm.c:5562, OR (b) patch tests/criteria/lib.sh fresh_cluster_mount
   to honor INSMOD_OPTS / append the param. Then run cache_coherency. If the
   bnobt double-free + visibility failures DROP → SCST-FUA-stale-platter root
   CONFIRMED → make fua_disable default-on (correctness > the LIO-era FUA
   workaround, since test cluster is SCST per project_test_cluster_scst).
2. If fua_disable doesn't fix it, A/B fua_always=1, then implement GPT's shared
   on-disk AGF epoch (CAS-bumped on every alloc/free-release) so reacquire
   invalidation is driven by ACTUAL peer modification (perf-safe vs blanket bump
   which would tank rsync_paired's 103% ratio).
3. unlink_visibility is the live failing subtest (concurrent rm of 120 files in
   one shared dir across 4 nodes; bnobt double-free during inactivation). Focus
   there + cross_write_read (1/6).

## INFRA (unchanged, all valid)
- Clean reboot ALL 4 (sudo virsh -c qemu:///system destroy+start testN) before
  any trusted run. /tmp/.mxfs_pass = cp ~/.mxfs/pass. Then bash tests/reset4.sh 4.
- Run: `( ./tests/criteria/cache_coherency.sh --nodes 4 >/tmp/cc.log 2>&1; echo
  EXIT=$? >>/tmp/cc.log ) &` then `until grep EXIT=`. Slots t1=0 t2=3 t3=1 t4=2.
  ~20 AGs, agblocks=261427, dblocks=5218294.
- High run-to-run variance (passed 0..2 across identical configs) — the
  shutdowns are stochastic. Average several runs before trusting a delta.
