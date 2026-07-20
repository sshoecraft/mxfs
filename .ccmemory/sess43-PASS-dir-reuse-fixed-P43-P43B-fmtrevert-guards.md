---
name: sess43-PASS-dir-reuse-fixed-P43-P43B-fmtrevert-guards
description: sess43 PASS (build 226E02D6): dir_reuse_coherency 2/tcp FIXED via P43+P43B block→shortform format-revert guards in mxfs_dlm_reload_inode. ZERO double…
metadata:
  type: project
---

## sess43 — dir_reuse_coherency 2/tcp PASS (build 226E02D6D7392A9ED951A55), the multi-session blocker

### THE FIX (KEEP): two block→shortform format-revert guards in mxfs_dlm_reload_inode (xfs/xfs_mxfs_dlm.c)
The proven root (sess42): node1 ran `xfs_dir2_sf_to_block` TWICE for the SAME dir incarnation; the 2nd conversion's `xfs_dir3_data_init` re-zeroes block0 → node1_f1..f14 lost. The block→shortform in-core revert between the two conversions is a RELOAD adopting a shortform on-disk image. There are TWO revert sites in the same reload function:

1. **P43-DIR-FMTREVERT-SKIP** (~line 6718, after P33-DIRGROW-REVERT-SKIP): checks the LIVE `dip` cluster buffer BEFORE the down_write_trylock spin. Cleanup: `xfs_buf_relse(bp); ip->i_dlm_stale=false; return;` (no i_lock held yet).
2. **P43B-DIR-FMTREVERT-SNAP-SKIP** (~line 6996, right after `dip = snap`): checks the IMMUTABLE post-spin SNAPSHOT, before xfs_idestroy_fork. NEEDED because per sess87 a peer rewrites the SHARED cluster buffer DURING the spin, so early `dip` reads BLOCK (P43 passes) while `snap` captures SHORTFORM. Cleanup mirrors RELOAD-VERIFY-BAIL: `kfree(snap); xfs_buf_relse(bp); up_write(&ip->i_lock); ip->i_dlm_stale=false; return;`.

Both guards, same condition: `S_ISDIR && same S_IFMT && di_gen==in-core gen && ip->i_df.if_format != XFS_DINODE_FMT_LOCAL && dip->di_format == XFS_DINODE_FMT_LOCAL` → keep authoritative in-core BLOCK dir, refuse the stale shortform.

### EVIDENCE (drc_cap2, build 226E02D6, archived tests/_cap/PASS_226E02D6_test{1,2}.log):
- `PASS dir_reuse_coherency (nodes_pass=2/2)`, 24 rounds.
- **ZERO double-conversions** (no (ino,i_gen) with >1 P42-SFCONV). P42-SFCONV=24 (exactly 1/round baseline).
- **drc-FAIL=0, drc-RDMISS=0.** Leaf-hash holes (lookup_fail=9 in prior build 8E2F4890) GONE → confirmed downstream of double-conversion, NOT an independent bug.
- P43=1 + P43B=1, BOTH on the same incarnation gen=266719934 (round ~20): the revert was attempted at both sites and caught → no 2nd conversion → no loss. Direct mechanistic proof.

### PROGRESSION this session:
- build 8E2F4890 (P43 only): PARTIAL — 3 doubles still slipped via the P62-RELOAD-FORK-SHRINK snapshot path the early dip-check couldn't see. drc-FAIL>0.
- build 226E02D6 (P43+P43B): PASS.

### STILL TODO before writing criterion-met (criterion = "2 node dlm=tcp test 100% successful"):
1. CONFIRM STABILITY: bug is intermittent (only triggered round 20 this run). Need ≥3 consecutive dir_reuse PASSes.
2. RUN FULL SUITE: `./run.sh 2 tcp` (all criteria) — sess22 says criterion = full suite, dir_reuse was the holdout. Confirm 100%.
3. SLOWNESS (RULE 0): run took ~294s for 24 rounds (~12s/round) — the sess34 6s-handoff slowness (P138-BAST dur_us~6e6). Separate concern; assess if it blocks "successful".
[[sess43-two-reload-sites-revert-block-to-shortform-P43-P43B]] [[sess42-DECISIVE-double-sf-conversion-same-incarnation-proven]]
</body>
