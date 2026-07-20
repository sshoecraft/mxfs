---
name: sess8-FIX21-FIX22-dlm-fairness-PASS
description: sess8(a9a03929): dlm_fairness 8/tcp PASS 8/8 (run103, build B2787BC7). FIX-21 selective AG-grant migration at trans_dup (convoy dead). FIX-22 SF reba…
metadata:
  type: project
---

# sess8 (ccloop a9a03929) — FIX-21 + FIX-22 → first dlm_fairness 8/tcp PASS

Builds: 20CD7654 (sess7 head) → 489D551A (FIX-21) → 57FA2D86/460C8012 (tracers) → **B2787BC7 (FIX-21+FIX-22+tracers, run103 = dlm_fairness PASS 8/8, drained=0, P22 fired 25×)**.

## FIX-21 (PROVEN run98): selective AG-grant migration at xfs_trans_dup
- `mxfs_trans_migrate_ag_unlocks(tp, ntp)` (xfs_mxfs_dlm.c ~22900, called from xfs_trans.c:191 replacing the v0.3.106 unconditional splice): walks ntp->t_dfops pendings (extfree/agfl/rmap/refcount/bmap items carry xfs_group; XG_TYPE_AG only), migrates ONLY unlock-pendings for AGs still referenced by pending defer work; rest stay on old tp → release at its trans_free (right after sub-commit CIL insert). attr/exchmaps/unknown types with work items → retain-all (conservative). Preserves the sess26 EFI-coordinate guard exactly.
- Result: P1-AGWAIT trans_held_ags=[] everywhere (was [4],[2] dirty convoys), P1-AGDUP-DROP fires ~1/roll, dlm_fairness 3/8→7/8 in one step. rc=-110 defer-finish shutdowns gone.

## FIX-22 (PROVEN run102 trace, run103 verified): SF rebase-union resurrects own undestaged removes
- ROOT (name-level, t7 n7_r49): `mxfs_dir_rebase_shortform` (sess20/21, dir_sf_rebase=1 + dir_sf_rebase_merge=1, fired from modify_refresh at EVERY dir modify) does UNION(disk ∪ in-core-only) when own_work. Disk image was 2-ops STALE (own xfsaild mid-tenure flush landed pre-rename image at daddr level; all 8 nodes' xfsailds write the same cluster daddr uncoordinated). Union re-imported own just-renamed-away name (mv nX_rY → .done; union re-adds nX_rY from stale disk). rm then removes only .done → ghost committed → every peer adopt/flush propagates it → permanent 12-leftover ratchet ("df shared dir drained(exp=0 got=12)").
- FIX: filter the disk image through the per-tenure removed-set (sess34 infra: mxfs_dir_record_removed/mxfs_dir_was_removed) BEFORE any adopt/union in rebase. Gates: own_work && i8count==0 && remset valid+epoch-match. Recording gate widened (was drain_merge-only → now also when dir_sf_rebase_merge). P22-SFRB-ZOMBIE-SKIP (capped 2000, always-on) prints dropped zombies.
- Residual accepted risk: same-name+same-ino peer recreate within one epoch window post-release (astronomically rare; noted in code comment).

## Diagnostic infrastructure added (all gated mxfs.dir_relverify=1 except noted)
- P8-SFRM (xfs_dir2_sf_removename): every multi-node SF remove + post-remove name list.
- P8-SFIFLUSH (xfs_inode.c xfs_iflush after fork copy): platter ledger — exact SF name list each dinode cluster write, daddr+in_ail+comm.
- P8-SFADOPT (reload post-from_disk): adopted name list + post_release/handoff.
- P-SFREL-VERIFY ungated under dir_relverify (was dirwr/instr-only).
- P34F line extended: post_release/dgen/lgen/state.
- mxfs_sf_fmt_names() shared formatter (xfs_mxfs_dlm.c, decl in .h).
- Timeline technique: harvest all 8 dmesg, sort by realns → cross-node op/flush/adopt ledger (scratchpad timeline102.txt method).

## Key architecture facts learned
- The fairness dir stays SHORTFORM (~13 entries, 165-180B) and thrash-converts SF↔block ~40×/node/run at the boundary (P62-SF2BLK names=[] lists are gold: full in-core view per conversion).
- xfsaild inode-cluster writeback is UNCOORDINATED with DLM tenure: all 8 nodes write the same dinode daddr concurrently with divergent images. Release-side EX destage IS reliable (P-SFREL-VERIFY 78/79 DURABLE) — the staleness window is mid-tenure own-flush + cross-tenure late landings. FIX-22 kills the harmful consumer (union); the writeback disorder itself is untouched (watch for other consumers).
- 3-way SF merge (sess14) = dead code in this workload (0 P-SFM lines w/ sfm_dbg=1). P63-HANDOFF forced adopts DO run.
- MXFS_EXTRA_MODARGS insmod form: `dir_relverify=1` (NOT mxfs.-prefixed).
- Infra: after VM cycle, mount NFS: `mount -t nfs 192.168.1.4:/src /src -o rw,vers=4.1,hard,timeo=600,retrans=2,tcp` per node; run.sh needs /src.

## NEXT (criteria ladder)
1. Full 8/tcp suite clean-cycle (baseline 13/17 run94; fairness+scaling family should now converge; watch dir_reuse in-suite pace, soak, tcp_dlm_scaling).
2. Fix residue → repeat → 4/2/1 node suites.
- Reproducer: `./run.sh 8 tcp dlm_fairness` (~90s incl prep). Full suite: `./run.sh 8 tcp` (~25-40min).
- criteria.json = results store; jq '.categories[].tests[] | select(.name=="X") | .runs["8/tcp"]'.
