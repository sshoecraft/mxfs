---
name: caw-sess5-NEXT-correct-fix-mirror-iget-create-gate
description: sess5 NEXT-STEP: the correct read-storm fix = gate the DLM-grant reload_inode stale on create-authorship, MIRRORING xfs_icache.c:1005 which already e…
metadata:
  type: project
---

## sess5 NEXT-STEP — the correct read-storm fix (concrete, actionable)

### The precedent that shows the RIGHT gate
`xfs/xfs_icache.c:1005` — the multi-node inode-cluster invalidation (the sess38/sess19 stale at
~1445 that I read this session) is ALREADY gated `!(flags & (XFS_IGET_CREATE | XFS_IGET_INCORE))`.
So on the CREATE path the icache invalidation is correctly SUPPRESSED (a node authoring a fresh
inode must not stale+re-read the old on-disk image). The pattern EXISTS and is proven-safe.

### The storm is a DIFFERENT reload path that LACKS this gate
The 32-node storm stale comes from `mxfs_dlm_reload_inode` invoked by the **DLM grant callback**
(`mxfs_dlm_caw_lock → reload_inode`, dlm/dlm_caw.c side), NOT the icache iget path. Trigger gate is
the grant callback `if (VFS_I(ip)->i_mode==0 || ip->i_dlm_stale)` (xfs_mxfs_dlm.c:405) — the
`mode==0` freed-shell arm fires when a node re-creates/re-acquires its OWN just-freed reused inode
(dlm_scaling create/rm loop), adopting the pointless old freed image and staling the whole cluster
=> FUA storm. This path never sees XFS_IGET_CREATE, so it can't reuse the icache gate directly.

### CORRECT FIX (mirror the icache create-exclusion, per-inode authorship signal)
Gate the reload_inode cluster-stale (xfs_mxfs_dlm.c ~14406, the `reload_owned_skip` branch I added,
currently param-gated on the REFUTED grant_handoff check) on a **create/authorship** signal instead:
- Candidate: `ip->i_flags & XFS_INEW` (inode is being instantiated/created) — a fresh create sets
  INEW; a peer-data READ of an existing inode does not. OR thread a create flag from xfs_create/
  xfs_dialloc through to the ilock/grant so reload knows "we author this".
- The distinction MUST be authorship, NOT handoff history (grant_handoff gg==0 is ambiguous — it is
  also true on first-read-of-peer-data, which REFUTED the naive fix: cache_coherency@4=0/4, see
  [[caw-sess5-reload-skip-owned-REFUTED-grant-handoff-wrong-signal]]).
- Beware co-resident cluster false-sharing: on create we RMW one inode slot in a shared cluster;
  sess115 "write only owned inode sectors" (partial inode write) already protects co-residents, so
  suppressing the reload-read on create should be safe IF the partial-write path is engaged. VERIFY.

### SHARPEST SIGNAL (key refinement — avoids the sess5 refutation)
The storm reload fires specifically on the **`mode==0` arm** of the trigger `if (VFS_I(ip)->i_mode==0
|| i_dlm_stale)` (xfs_mxfs_dlm.c:405). A first-read of PEER-created data has **mode != 0** (iget read
it from disk before the grant callback), so it reaches reload via the *i_dlm_stale* arm, NOT mode==0.
=> An in-core **mode==0 shell = OUR OWN local free** (inactivation zeroed our mode); a peer's free
sets i_dlm_stale (evict-ring), it does NOT zero our in-core mode. THEREFORE: scope the skip to the
**mode==0 arm ONLY** and leave the i_dlm_stale/mode!=0 path (cache_coherency cross_write_read) fully
intact — that alone prevents the sess5 refutation.
BUT the mode==0 shell can still need a PEER's image in the cross-node dir_reuse case (we freed X, a
PEER re-created X, we now re-read X). Distinguish with the **prior-EX-owner slot stamped on our grant**
(reload_inode header @~14066: "the handoff bit the DLM master stamped on our current EX grant (prior EX
owner...)") — skip ONLY when prior-EX-owner == self (or none) since our free. This is DIFFERENT from
the refuted `mxfs_v5_dlm_inode_grant_handoff` GEN check (which returned gg==0 for first-read-of-peer).
Find/confirm the prior-owner-slot accessor in dlm/dlm_caw.c (the grant carries last-EX-owner; see
dlm_caw.c:382/547 "drop the last-EX record so every holder reloads"). Gate: mode==0 && prior_ex_owner
∈ {self, none} => skip stale (self-recycle, in-core-authoring). Validate dir_reuse@4 cross-node HARD.

### VALIDATION LOOP (fast, established this session)
Per fix iteration: `virsh destroy+start ALL 32` + `scripts/caw_preflight.sh 32`, then
`MXFS_EXTRA_MODARGS="<param>=1" ./run.sh 4 caw cache_coherency strong_consistency` — cache_coherency@4
MUST stay 4/4 (it dropped to 0/4 the instant the naive fix served stale peer data — a 1-run
unambiguous coherency oracle). Then dir_reuse@4 (cross-node reuse — the hardest coherency case for an
authorship gate). Only after @4+@16 coherency is GREEN, test the perf win: cache_coherency@32 (baseline
0/32 timeout -> must PASS <300s) and dlm_scaling@32 (baseline 28/32 fresh -> must hit 32/32).
Keep the fix PARAM-GATED default-off until @4/@16 coherency proven. IMPORTANT: a run.sh cache_coherency@4
FAIL OVERWRITES the recorded 4/caw PASS in criteria.json — always re-run it clean (param off) to restore
the cell before ending (I regressed+restored it this session).

### Build state: B366EA3C (deployed) has param `reload_skip_owned` (default 0, INERT/refuted-approach)
+ `read_attr_probe` (default 0, diagnostic). Repurpose the `reload_owned_skip` branch condition to the
authorship signal above. See [[caw-sess5-STALER-identified-reload-inode-and-levers-tried]].
