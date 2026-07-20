---
name: sess62-SURGICAL-leadP-SFMERGE-dead-no-same-incarnation-shortform-union
description: sess62 SURGICAL LEAD (updated): shortform 3-way union merge mxfs_dir_sf_merge_into fires 0x. GATE @ xfs_mxfs_dlm.c:8054 requires i_dlm_dir_sf_base!=N…
metadata:
  type: project
---

## sess62 SURGICAL LEAD — why the shortform union merge (the fix) never runs

Instr=1 guard census, failing dir ino=131, build F3342B5D:
- **P-SFMERGE: 0** — the 3-way shortform UNION merge NEVER runs. This merge (mxfs_dir_sf_merge_into, xfs_mxfs_dlm.c:6754; snapshot+adopt+re-apply at ~8054-8230) is base/ours/theirs: names WE changed keep ours, names we didn't touch follow disk (theirs) — so it would ADOPT a peer's node1_f1 (we never touched it) while keeping our own dirents. EXACTLY the fix. But it's gated off.
- P103-RELOAD-REUSE-ADOPT ~8000 (cross-incarnation gen-differs wholesale adopt — each round's first reload), P116-RELOAD-SELFCLOBBER-SKIP ~290 (return early), P33-FROMDISK-DIRSHRINK ~78 (return early), P95 ~78, P52/P58 0.

### THE GATE (xfs_mxfs_dlm.c:8054) — why P-SFMERGE=0
```
if (mxfs_sf_merge && S_ISDIR && ip->i_df.if_format==LOCAL && ip->i_df.if_data &&
    ip->i_df.if_bytes>0 && ip->i_dlm_dir_sf_base &&            // <-- (a) snapshot base must exist
    dip->di_format==XFS_DINODE_FMT_LOCAL &&                    // <-- (b) DISK must still be shortform
    be32_to_cpu(dip->di_nlink)==VFS_I(ip)->i_nlink)            // <-- (c) nlink match
```
Never all-true for the converter because:
- Most reloads are cross-incarnation (gen differs) -> handled by P103 reuse-adopt BEFORE/instead of this same-incarnation merge; the new incarnation has no i_dlm_dir_sf_base yet (gate (a) NULL).
- Same-incarnation reacquires that DO happen either hit P116/P33 early-return (keep stale in-core, never reach 8054) OR by then disk has converted to EXTENTS (gate (b) fails — merge is shortform<->shortform only).
- So the converter's stale shortform (missing node1_f1) is never reconciled with disk's shortform (with node1_f1) before xfs_dir2_sf_to_block freezes it.

i_dlm_dir_sf_base is set @ xfs_mxfs_dlm.c:8735 (after a coherent disk read/reload), freed @ xfs_icache.c:163 + 8733. Decl xfs_inode.h:140.

### FIX (next session, surgical + scoped)
Ensure the SAME-INCARNATION shortform reload reaches mxfs_dir_sf_merge_into for the converter on a post_release reacquire while BOTH sides are still shortform:
1. Confirm WHY gate fails for the converter: add a one-shot probe at 8054 logging which sub-condition is false (sf_base NULL? disk fmt? nlink?) for ino=131. Most likely sf_base==NULL (never snapshotted this incarnation) and/or P116/P33 returned before 8054.
2. If sf_base NULL: snapshot it on the round's first coherent adopt (P103) so subsequent same-incarnation reacquires have a merge base. 
3. If P116/P33 early-return bypasses the merge: for a SHORTFORM dir on post_release (NL->EX handoff) with disk-still-LOCAL same-gen, run the union merge INSTEAD of keep-in-core (post_release => Invariant-1 drained our prior tenure => disk superset => union adds peer node1_f1, re-applies our delta, NO delete-resurrection — the safe scoping vs the sess53 same-tenure regression).
4. The conversion race may also need: a node about to sf->block while disk is still shortform must first union disk's shortform (so the frozen block0 has everyone's entries). Consider invoking the merge at the convert call site (mxfs_dlm_dir_modify_reload_prelock / pre-create) for shortform same-gen post_release.
Verify: P-SFMERGE>0; node1_f1 survives; dir_reuse 4/tcp PASS x3; FULL ./run.sh 4 tcp no regression (esp. delete-heavy dlm_fairness/tcp_dlm_scaling — resurrection check); then 8/tcp (never run).

Build F3342B5D baseline-equivalent on disk; mxfs_sf_merge=1 default. See [[sess62-FINAL-content-level-stale-shortform-base-at-conversion]] [[sess62-PROVEN-ROOT-4way-logical-block0-split-divergent-extent-map]] [[sess62-HANDOFF-next-fix-is-namesetset-union-merge-epoch-scoped]].</body>
