---
name: sess22-SESSION-SUMMARY-net-progress
description: sess22(ccloop) SESSION SUMMARY: keeper EFBB9861. 3 banked fixes (reorder-remove kills shutdown cascade; node-format datascan heal kills dir_reuse loo…
metadata:
  type: project
---

## sess22 (ccloop) — SESSION NET PROGRESS. Keeper EFBB9861B5CB420552AB864.

### THREE banked fixes (all KEEP, all xfs/libxfs/):
1. **Reorder xfs_dir_remove_child non-dir path** (xfs_dir2.c): removename FIRST while trans clean → eliminates remove-path dirty-cancel SHUTDOWN. Turned sess21's 8/tcp shutdown-CASCADE into NO-shutdown isolated fails.
2. **Node-format datascan leaf-hash-hole READ heal** (xfs_dir2_leaf.c + xfs_dir2_node.c + xfs_dir2_priv.h): mxfs_dir2_datascan_lookup now handles BTREE/node-format dirs + wired into xfs_dir2_node_lookup → ELIMINATES dir_reuse `leaf-hash lookup_fail`.
3. **Leaf rebuild holeskip + bail-not-shutdown** (xfs_dir2_leaf.c): dormant when leaf_rebuild OFF (default). leaf_rebuild=1 PROVEN HARMFUL (bnobt double-free shutdowns) — keep OFF.

### MEASURED state on keeper:
- **Full ./run.sh 8 tcp = 13 PASS / 4 FAIL, ZERO shutdowns on all 8 nodes, NO cascade** (was sess21 11/17 with shutdown cascade). crash_consistency + tcp_dlm_scaling now PASS 8/8.
- **8/tcp FAILs (4, all pure-coherency no-shutdown):** cache_coherency (cwr: cross-write-read stale file-data md5, 763/765), zero_silent_loss (0/8 data loss), dir_reuse_coherency (single readdir=799 face, flaky ~PASS 1/3), fault_netpartition (7/8).
- **2/tcp:** 12/12 pre-dir_reuse PASS; dir_reuse flaky (3× standalone PASS; full-suite hit a flaky AGI-CRC shutdown — [[sess22-AGI-crc-shutdown-ifree-fua-write-no-crc]]).

### dir_reuse residual NARROWED to ONE face: `readdir count exp=800 got=799` = durable SINGLE-ENTRY data-block lost-update (RMW-on-stale-base create-miss). NOT the acquire-side LOCKED-SKIP (P-DE-BLK LOCKED-SKIP / LOCKED-WAIT / P36-EVICT-LOCKED all fired 0×). = the sess11 "lost dirent committed rval=0 vanishes from in-core cached data block within ~250us" deepest race.

### CRITERIA (1/2/4/8 tcp 100%) NOT MET. Remaining deep bugs (130-sess core), prioritized for next session:
1. **dir_reuse readdir=799** data-block single-entry lost-update (sess11 addname→commit window race) — the last dir_reuse face.
2. **cache_coherency cwr** — cross-write-read stale FILE-DATA (FUA-read coherency; different facet from dir).
3. **zero_silent_loss** 0/8 data loss.
4. **AGI CRC** flaky in-full-suite shutdown.
5. **fault_netpartition** 7/8.
Links: [[sess22-FINAL-keeper-DFDBAAFE-and-remaining-deep-bugs]] [[sess22-8tcp-full-suite-landscape-13of17-noshutdown]] [[sess22-FIX-remove-reorder-eliminates-dirty-cancel-shutdown]] [[sess22-FIX-node-format-datascan-leafhash-heal]].
