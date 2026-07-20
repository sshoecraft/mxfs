---
name: sess59-zsl-residual-bmbt-leaf-disk-staleness
description: sess59 residual quantified: zsl P59-IREAD-MISMATCH loaded<if_nextents (e.g. 13<24) broot_lvl=1 → bmbt LEAF blocks on disk lag the dinode's di_nextent…
metadata:
  type: project
---

## sess59 residual — quantified the dinode↔bmbt-leaf on-disk inconsistency

Builds on [[sess59-zsl-bmbt-stale-child-root-and-residual]]. Current build
**B24B321B** = 75C0C6AE (bmbt-child evict) + a P59-IREAD-MISMATCH probe at
xfs/libxfs/xfs_bmap.c:1271 (pr_warn, fires only on the corruption).

### Measured (16-node storm, ino=131 shared dir, all on the dir DATA fork=0)
```
test1  loaded=13 if_nextents=24 broot_lvl=1
test2  loaded=13 if_nextents=16
test10 loaded=16 if_nextents=18
test12 loaded=14 if_nextents=21
test13 loaded=16 if_nextents=21
test15 loaded=13 if_nextents=16
test16 loaded=14 if_nextents=16
```
silent loss this run = 270 (varies 105–270 run-to-run; was 1600 before the
bmbt-child evict fix). EXIT=1.

### Interpretation (RULE 4)
`loaded` = extent records found walking the (cold-read) bmbt LEAF blocks
that the if_broot ROOT points to. `if_nextents` = di_nextents from the SAME
dinode. Reload reads the dinode atomically, so root + di_nextents are
mutually consistent. **loaded < if_nextents ALWAYS** ⇒ the bmbt LEAF blocks
on disk hold FEWER records than the dinode (di_nextents + root) expects: the
releasing writer persisted the dinode (inode-cluster buffer) but NOT the
latest content of one or more bmbt leaf blocks the root points to. broot_lvl=1
= 2-level tree (root in dinode + level-0 leaves in AG blocks).

### Why this is the blocker now
My bmbt-child EVICT fix (mxfs_dir_evict_bmbt_blocks) correctly forces a cold
re-read of the leaves, which EXPOSES the stale on-disk leaf (previously
masked by serving the stale cache). The remaining bug is WRITER-SIDE: the
BAST release drain (xfs_mxfs_dlm.c ~2723-2809) gates on `!in_ail` (dinode)
&& `data_durable` (= mxfs_dir_data_durable incl mxfs_dir_bmbt_scan(false)),
and flushes via mxfs_dir_flush_data_blocks (→ mxfs_dir_bmbt_scan(true)).
That SHOULD land the leaves — yet disk leaves lag. Candidates to probe next:
1. mxfs_dir_bmbt_scan misses a leaf (clean-in-cache but stale-on-disk, or
   the AG-walk owner-match skips it, or MXFS_BMBT_SCAN_MAX=64 cap).
2. AG free-space DOUBLE-ALLOCATION: the bmbt leaf daddr is shared/reused so
   its write is clobbered (sess39/42/43 family — "dir block shares daddr
   with inode cluster").
3. surgical_inode_write / inode-cluster flush writing di_nextents without
   the matching leaf, or a torn inode-cluster vs leaf ordering.

### NEXT
Run with INSMOD_OPTS="dirwr=1" (module param, 0644) → enables P133-BMBT-RELFLUSH
+ P134 dinode/bmbt-revert write-side probes (low rate). Correlate: does the
releaser flush ino=131's bmbt leaves at release? Does P134 show a revert?
Also consider a writer-side release probe that re-reads di_nextents + sums
the on-disk bmbt leaves just before unlock and logs any mismatch (catches
the writer releasing an inconsistent set directly).

KEEP fixes so far: mxfs_dir_evict_bmbt_blocks + the disk_superset
peer_modified_since_load bypass (1600→~100-270) + the verify-phase robustness
in scripts/sess88_workload_a_modeN_baseline.sh.
</body>
