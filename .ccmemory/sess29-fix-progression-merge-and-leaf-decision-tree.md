---
name: sess29-fix-progression-merge-and-leaf-decision-tree
description: sess29 fix progression for dir_reuse 2/tcp: dir_merge=1 FIXES data face (readdir 187→200) but DLM-timeout shutdown; leaf face = lookup-path bug; stag…
metadata:
  type: project
---

## sess29 (ccloop 8ddb16a2) — dir_reuse_coherency 2/tcp fix attempts + decision tree

### Confirmed this session (RULE 4, builds run on 2-node TCP, cluster reboot-stable now)
1. **`dir_merge=1` (mxfs_dir_merge_peer_into_tp, additive union-merge in xfs_create) FIXES the DATA face**: readdir 187→**200** (re-adds peer's durable dirents before each create RMW so xfsaild flushes a union). PROOF the data face is a write-side stale-base RMW.
2. **BUT `dir_merge=1` causes a `rc=-110` DLM-timeout shutdown** at `mxfs_dlm_ilock_begin:8534` (peer's PR readdir times out 120s) — the per-create full-dir plain-bio read slows create processing → delays BAST handling → peer starves. Same class sess18 hit with merge variants. The merge is EX-hold-extending.
3. **LEAF face = lookup/read-path bug** (sess27-FINAL confirmed earlier): the dirent is DURABLY present in the data block (readdir lists it) but `xfs_dir2_leaf_lookup` ENOENTs and the `mxfs_dir2_datascan_lookup` fallback MISSES it. My run: `P26-DSCAN-MISS ndb=1 scanned=128` = UNDER-SCAN (extent-map walk gave ndb=1 while dir has ~200/2 blocks) AND/OR the `cmpresult` skip.

### Fixes written this session (in tree)
- **Merge once-per-tenure** (xfs_mxfs_dlm.c, end of mxfs_dir_merge_peer_into_tp): advance `i_dlm_dir_evicted_gen/incarn` after a COMPLETE merge (`nent<MAX_ENT && added==missing`) so subsequent same-tenure creates skip (peer can't modify while we hold EX) → cuts per-create cost → should reduce DLM timeout. RISK: short tenures (frequent handoff in the storm) → still many merges.
- **datascan cmpresult reset** (xfs_dir2_leaf.c top of mxfs_dir2_datascan_lookup): `args->cmpresult = XFS_CMP_DIFFERENT` — a failed leaf-lookup leaves cmpresult=EXACT, making the scan's `cmp != args->cmpresult` gate SKIP an exact match (sess27-FINAL prime suspect).
- **P29-DATAWRITE detector** (pal/linux/xfs_buf.c, helper mxfs_dir3_data_fingerprint) — proved the xfsaild stale-flush root. NOTE false-positives on rm-rf removals (buf<disk is also a removal).

### Build progression
0270D870 (sess28 baseline) → 75FD71CC (+P29 detector) → 5760A5E2 (+merge once-per-tenure) → **AB435ACC (+datascan cmpresult reset)** = current built .ko (NOT yet test-run; the in-flight run used 5760A5E2).

### DECISION TREE (next)
- If `dir_merge=1 dir_leaf_rebuild=1` (5760A5E2) PASSES → re-test on AB435ACC, then full `./run.sh 2 tcp` ×3 for regressions (merge runs on ALL multinode creates — watch cache_coherency/crash_consistency/rsync_paired + DLM timeouts).
- If merge STILL times out → ABANDON merge (EX-hold-extending, sess18+sess29 both timeout). Pivot to NO-EX-HOLD path:
  - DATA face: write-side stale-subset SKIP at bio chokepoint (skip xfsaild dir-DATA write when coherent disk is a content-SUPERSET of the buffer), gated by a per-inode "no-remove-this-tenure" flag for safety (create waves are additive; removals persist via release-drain). OR `partial_iwrite=0` (sess27 — but that fixes extent-map staleness, may NOT fix my content-clobber data face).
  - LEAF face: datascan fixes (cmpresult done; investigate why ndb=1 under-scan — extent map short at lookup) + `dir_leaf_rebuild=1`.
- Marker only on verified full-suite 100%.

### Infra reminders
Reboot cluster (`tests/reboot_cluster.sh 2`) before EVERY run — a shutdown leaves /dev/sda busy → "PREP FAIL (mkfs): device is busy". dnsmasq reservations keep test1=.186/test2=.182. FUA is DEAD (LIO target). See [[sess29-PROVEN-root-xfsaild-stale-dirblock-flush-at-EX]], [[env-test1-dhcp-reservation-fix-sess29]].
