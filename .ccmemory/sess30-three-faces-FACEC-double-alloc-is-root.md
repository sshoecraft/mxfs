---
name: sess30-three-faces-FACEC-double-alloc-is-root
description: sess30 KEY: dir_reuse 2/tcp has 3 intermittent faces; severest=FACE C AG double-alloc (urandom file data over inode cluster @daddr 0xc00 → shutdown),…
metadata:
  type: project
---

## sess30 (ccloop 8ddb16a2) — dir_reuse_coherency 2/tcp: THREE intermittent faces, FACE C is the deepest

Build at relay = **AB435ACC** (baseline restored; all sess30 acquire-side experiments REVERTED). The criterion = `./run.sh 2 tcp` 100%; ONLY dir_reuse_coherency fails (16/17 pass).

### THE THREE FACES (all intermittent, run-to-run variance, ALL in baseline AB435ACC):
- **FACE A (DATA)**: readdir<200 (e.g. 185/186) — a contiguous create-order range (=1 dir DATA block) durably missing from readdir, both nodes. lookup_fail=0.
- **FACE B (LEAF)**: readdir=200 but lookup_fail=N (5–11) — names in data blocks but leaf hashval gone → stat ENOENT. P26-DSCAN-MISS shows the datascan under-reads (scanned=117/200).
- **FACE C (INODE-CLUSTER CORRUPTION → SHUTDOWN, severest)**: "Structure needs cleaning" (EFSCORRUPTED -117). `xfs_inode_buf_verify` fails at inode block **daddr 0xc00**. The corrupt buffer's first 128 bytes are **RANDOM DATA** (e4 89 fa 25 b0 c1 5d 82…), NOT dir magic (XDD3/XDB3) and NOT inode magic (IN). The test fills files via `dd if=/dev/urandom`, so **a FILE DATA BLOCK was allocated at the same daddr as an inode cluster** = **AG FREE-SPACE DOUBLE-ALLOCATION**. `P26-IGET-FAIL dp=131 name=node1_f46.md5 inum=3072 err=-117`: dirent points to inum 3072 whose cluster (0xc00) is overwritten by urandom file data. This is the **sess39–47 bnobt/AGF double-alloc** root (NOT dir-block coherency). It pre-exists (baseline 080025Z had 44 needs-cleaning lines on test1). The original criteria "no-result" = the test SHUTS DOWN mid-run (~round 16-17) and never prints RESULT.

### IMPLICATION (reframes the whole problem):
FACE C (AG double-alloc) shuts the FS down → the test can never pass while it fires. It is likely the PRIORITY and may be independent of (or upstream of) the dir-block faces A/B. dir_reuse stresses daddr/inode REUSE (rm-rf+recreate same dir each round), which is exactly the ABA/double-alloc stressor. The deepest face is AG-allocation coherency across nodes (a node allocates a block as a file data extent; the peer, with stale AG free-space metadata/bnobt/AGF, allocates the SAME block as an inode cluster — or vice versa).

### sess30 REFUTED fix attempts (do NOT repeat — all reverted):
1. **Acquire-side pin-drain EXTENSION** (mxfs_dir_drain_evict_data_blocks loop 50→2000 iters + periodic log_force): REGRESSED to readdir=0/200 + xfs_dir3_block_verify corruption (aggressive evict forced cold-reads of block 0 while the READER's extent-map was stale block-format vs disk leaf-format → XDD3-read-as-XDB3). Lesson: must reload extent-map BEFORE cold-reading.
2. **NL-side pin-drain** (new fn at the pre-DLM-request NL point in mxfs_dlm_ilock_begin @~8412: log_force+wait dir-buffer pins, NO evict): did NOT fix A/B; FACE C corruption still fired (PROVED pre-existing, not caused by it). Reverted (adds acquire-path cost, no benefit).
3. **Write-side SET-SUPERSET discard** at xfsaild chokepoint: GPT-5.5 REFUTED (legit-remove resurrection; discard pulls BLI from AIL → crash-loss). See [[sess30-GPT-NL-refresh-design-and-superset-refuted]].
4. (prior) merge-while-EX → DLM -110 timeout.

### Established facts:
- Target = LIO fileio write-through → plain cold-reads COHERENT (FUA rejected/unneeded). See [[sess30-LIO-coherent-and-acq-pin-drain-fix]].
- publish-before-notify in place; release drain thorough.
- mxfs_dlm_ilock_begin is called BEFORE xfs_ilock takes i_rwsem (so the NL pre-request point holds no local ILOCK — confirmed safe for the NL-refresh, but the NL-refresh alone doesn't fix A/B/C).
- LESSON: adding log_force / eviction / pin-manipulation to the dir ACQUIRE path is hazardous (perturbs flush ordering; 2 attempts regressed or were neutral).

### NEXT SESSION (recommended priority): attack FACE C = AG free-space double-allocation.
Diagnose WHY a file data block and an inode cluster get the same daddr (0xc00) under concurrent create + reuse. Reuse prior AG-meta detectors (sess33 P33 dual-AG-alloc, sess81 P81-DEXT, sess42 b_mxfs_ag_gen, sess43 in-AIL-AG-meta-discard-guard). Likely a stale AG free-space (bnobt/cntbt/AGF) cache at AG-DLM re-acquire under reuse → two allocators hand out 0xc00. The dir-block faces A/B (stale dir DATA/LEAF base RMW + xfsaild flush) are SECONDARY — fix C first (it shuts down the test). Tools: scripts/drc_parse.sh (per-round A/B/C summary), tests/suite/dir_reuse_coherency.sh. Reboot/clean cluster before runs. See [[sess29-PROVEN-root-xfsaild-stale-dirblock-flush-at-EX]], [[sess42_lessons]], [[sess47_lessons]].
