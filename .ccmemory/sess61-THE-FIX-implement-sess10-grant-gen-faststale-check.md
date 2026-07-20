---
name: sess61-THE-FIX-implement-sess10-grant-gen-faststale-check
description: sess61 THE FIX to implement next: sess10's grant_gen fast-path staleness check (NEVER implemented). dir_reuse 4/tcp loss is case A (TCP double-grant…
metadata:
  type: project
---

## sess61 — THE FIX to implement (confirmed case A; sess10 plan, never built)

### A vs B RESOLVED → case A
sess10 established (traced in code) that the TCP DLM **double-grant is ALREADY
FIXED** (gen-token in dlm/dlm.c: `dlm_next_gen`, `lk->grant_gen` stamped on every
grant at dlm.c:624, delivered over the acked TCP protocol). So the dir_reuse
4/tcp durable loss is NOT a double-grant (B). It is case A: the dir-EX **FAST
PATH serves a STALE base** because the only staleness signal it trusts
(i_dlm_dir_gen) is bumped by the LOSSY async DIR_MODIFY eviction-ring
(note_dir_modified), which drops messages on TCP. My sess61 evidence corroborates:
the clobber buffer is dirty bufgen=0, content behind disk, kept by the dirty
guard — i.e. the node fast-pathed an EX serve onto a stale cached block0 and
dirtied it, never having reloaded the peer's grown block0.

### THE FIX (sess10 plan — verified NOT implemented this session)
Use the RELIABLE per-grant `grant_gen` as the "did the lock change hands" token
instead of the lossy eviction-ring. grant_gen infra EXISTS in dlm/dlm.c; the
XFS-layer query + fast-path check do NOT exist (grep: no mxfs_dlm_grant_gen / no
mxfs_v5_dlm_inode_grant_gen / no i_dlm_cached_grant_gen).

1. **dlm/dlm.c + dlm.h**: add `uint32_t mxfs_dlm_grant_gen(ctx, resource)` —
   model on `mxfs_dlm_held_mode` (dlm.c:2218): walk the bucket under
   table_rwlock, for lk->owner==local_node && state GRANTED/CONVERTING &&
   resource_equal, return the highest-mode entry's `lk->grant_gen` (0 if none).
2. **dlm/v5_mount.c + v5_mount.h**: add `uint32_t mxfs_v5_dlm_inode_grant_gen(
   ctx, ino)` — for ctx->dlm (TCP): make_inode_resource + mxfs_dlm_grant_gen.
   For CAW (ctx->dlm_caw): return 0 (CAW has atomic slot mutual-exclusion, no bug).
   Model on mxfs_v5_dlm_inode_ex_count (v5_mount.c:1134).
3. **xfs/xfs_inode.h**: add `uint32_t i_dlm_cached_grant_gen;` near i_dlm_dir_gen
   (line ~137). NOTE the EXISTING sess94 `i_dlm_dir_loaded_gen` is the same IDEA
   but keyed on the lossy i_dlm_dir_gen — the new field keys on the reliable
   grant_gen.
4. **xfs/xfs_mxfs_dlm.c**: 
   a. On SLOW-PATH acquire completion (where i_dlm_mode is set EX / grant
      published, near the gen bump at ~10161, and the post-grant publish region),
      set `ip->i_dlm_cached_grant_gen = mxfs_v5_dlm_inode_grant_gen(mp->m_mxfs_dlm,
      ip->i_ino);`.
   b. On the dir-EX **FAST-PATH serve** (the cache-hit gate in mxfs_dlm_ilock_begin
      — find the `dir_ex_verify_held` / cached-mode-EX serve region ~9600-9640 and
      the cached fast-path return): query `g = mxfs_v5_dlm_inode_grant_gen(...)`;
      if `g != ip->i_dlm_cached_grant_gen` (lock changed hands since we cached)
      → force the SLOW path: set i_dlm_stale, do mxfs_dlm_reload_inode (adopts
      disk, stales cached cluster buffer) AND bump i_dlm_dir_gen so the dir DATA
      blocks re-read, BEFORE serving the RMW. Then refresh i_dlm_cached_grant_gen.
   MHT preserved: within one continuous tenure grant_gen does NOT change → fast
   path keeps serving (no dlm_fairness starvation). It changes only when a peer
   actually got the lock → exactly once-per-tenure reload.

### WHY this beats everything tried (sess10 + sess61)
- di_changecount: per-node/collidable, UNSOUND.
- eviction-ring (i_dlm_dir_gen via note_dir_modified): LOSSY on TCP — the root.
- content-compare-while-holding / mxfs_dir_evict_data_blocks: skips dirty/in-AIL
  (sess61: the clobber buffer IS dirty bufgen=0 → kept → clobber).
- inode-FORK reload (my sess61 mxfs_dir_modify_adopt_disk_format): REFUTED, fork
  metadata never behind disk under EX.
- grant_gen is the AUTHORITATIVE already-existing "lock changed hands" token.

### VALIDATE
After implementing: `./run.sh 4 tcp dir_reuse_coherency` (probes OFF, build
should be representative ~2/24 baseline → target 0). Then FULL `./run.sh 2 tcp`
x3 (watch dlm_fairness no starvation got<50, no wedge) to ensure no regression,
then 1/4/8 tcp. Reset (virsh destroy+start) between full runs.

### CAVEAT to watch
The reload on the fast-path-grant-gen-mismatch must DRAIN/adopt safely: if the
buffer is this node's genuinely-uncheckpointed work (same tenure, grant_gen
UNCHANGED) it must NOT reload (sess36/sess50 resurrection). The grant_gen check
naturally gates this: same tenure → grant_gen same → no reload. Only a real
handoff (grant_gen changed, our work was drained at release per Invariant 1)
triggers reload. Also RULE-0: ~13s/round x24 ~ 312s vs 300s timeout — may need a
per-round cost cut even once coherent.

See [[sess10-FIX-PLAN-use-dlm-grant-gen-not-lossy-evictring]],
[[sess61-DECISIVE-dirty-bufgen0-divergent-block0-kept-by-dirty-guard]],
[[sess61-HANDOFF-state-and-next-steps]].</body>
