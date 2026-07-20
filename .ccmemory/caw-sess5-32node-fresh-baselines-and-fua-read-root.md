---
name: caw-sess5-32node-fresh-baselines-and-fua-read-root
description: sess5: FRESH-substrate 32/caw baselines (dlm_scaling=28/32, cache_coherency=0/32 timeout) prove the read-storm is FUNDAMENTAL not degradation. Storm…
metadata:
  type: project
---

## sess5 (ccloop 12e0d157) — 32/caw fresh baselines + FUA-read storm root

### KEY REFRAME: substrate freshness dominates; earlier 6-13/32 numbers were DEGRADED
- run.sh prep **re-mkfs's every run** (tests/setup/prep_fs.sh → FS_PREP_OK) + rmmod/insmod fresh module. So
  degradation is **transport-level (SCST/iSCSI/PR)**, NOT on-disk FS.
- **Substrate degrades HARD run-to-run**: fresh dlm_scaling@32=27-28/32, 2nd run same-substrate=3/32,
  storm 1760 AG0 reads/8s. Full `virsh destroy+start ALL 32` + preflight resets the transport → fresh.
- **criteria.json records each TEST independently** (showstat reads `.tests[].runs[N/dlm]`) → CAN run
  each failing test on its OWN fresh substrate and bank the pass; don't need all 17 in one run.sh.

### FRESH-SUBSTRATE 32/caw baselines (all 32 virsh-rebooted + preflight, build 6C6D5274/15062487)
- **dlm_scaling@32 = 28/32** (genuine 4-node tail even fresh — NOT just degradation).
- **cache_coherency@32 = 0/32 TIMEOUT** (>300s budget, killed). FUNDAMENTAL: 32 nodes × cross-node
  coherent reads (1024×1MB md5 + 640 rename + 960 unlink verifies) saturate the ONE iSCSI target.
- So the 32-node coherency slowness is REAL on fresh substrate, confirming the read-storm root.

### STORM MECHANISM (RULE-4 proven this session)
- Storm = COLD re-reads of **regular-file inode clusters in AG0** (dd confirmed magic 0x494e/mode 0644;
  fsblk~24645 = ino~197160), test1's OWN files (slot0→AG0 affinity). ~0.3/op peers-idle → ~6/op at load.
- **NOT** peer AG-lock ping-pong (`ag: acq=1 rel=0 nest=4258` = AG0 held EX continuously).
- **NOT** any counted mxfs coherency path: igstale=0 (icache stale, xfs_icache.c:1409 gate is
  `mxfs_dinode_cached_allocated` NOT AG-ownership, engages for allocated inodes → no re-stale);
  evict-ring `mxfs_dlm_evict_inode_cb` only SETS FLAGS (no reads) + references peer AGs not AG0;
  `mxfs_dlm_ag_drain_inode_buffers` only FLUSHES dirty (doesn't stale clean). ALL ruled out.
- **The storm reads BYPASS `xfs_buf_submit_bio`** (my read_attr_probe there counted ~0). They go through
  the **mxfs FUA read path** `mxfs_buf_read_fua` (pal/linux/xfs_buf.c:4851) via `mxfs_pal_scsi_read_fua_bdev`.
- FUA gate (xfs_buf.c:6711): `XBF_READ && !fua_disable && (fua_always||!_XBF_FUA_FRESH) && multi-node &&
  mxfs_buf_needs_fua_read(bp)`. `mxfs_buf_needs_fua_read` (dlm.c:27238) = TRUE for ALL inode/dir/bmbt bufs.
- `_XBF_FUA_FRESH` set by mxfs_buf_read_fua, CLEARED by `xfs_buf_stale` (xfs_buf.c:131). So storm =
  inode clusters STALED (removed from cache) then cold-FUA-re-read. **The staler is still unidentified**
  (NOT the mxfs coherency paths above; candidate = XFS-core reclaim/binval — needs a probe at xfs_buf_stale).
- **sess79 already tried "skip FUA when AG owned" → WEDGED** (ILOCK hung-task: served a pre-EX-acquire
  stale cached buffer). The `!_XBF_FUA_FRESH` gate already handles acquire-time correctly; the storm is
  from FUA_FRESH being cleared too often (stale churn), not the gate being wrong.

### NEXT-SESSION PLAN
1. Probe `xfs_buf_stale` (pal/linux/xfs_buf.c:73): count+attribute (caller comm/stack) stales of INODE
   buffers during dlm_scaling@32 → identify the exact staler. Build has read_attr_probe already (param
   `read_attr_probe`, counters mxfs_rd_*; it's at the wrong path — storm is FUA not submit_bio).
2. Fix = stop the unnecessary stale (GFS2: keep the cluster cached+FUA_FRESH while AG held EX, no BAST),
   OR make the post-stale re-read plain (page-cache amortized) when AG held continuously — carefully, to
   avoid the sess79 wedge (only safe when FUA-read/written during CURRENT EX tenure).
3. Methodology: `virsh destroy+start ALL 32` + `scripts/caw_preflight.sh 32` before EACH measured run
   (substrate degrades in 1 run). DON'T pkill concurrent op-loops mid-DLM-op (wedges a DLM resource →
   360s timeout → shutdown cascade; killed 10 nodes this way this session).
See [[caw-32node-dlm_scaling-ROOT-shared-AG0-reread]] [[AAA-sess4-HANDOFF-caw-criteria-unified-readstorm-root]].
