---
name: sess122-ccloop-RESUME-p110-readside-regression
description: sess122 RESUME: current build (1F7AF33C/C01185FA) REGRESSED to 2/4 from sess23's 3/4. Fix = disable read-side P110 interlock like sess23 did write-si…
metadata:
  type: project
---

## sess122 (ccloop run 4eef1f39) — RESUME HERE (dev suspended ~few days, user over weekly budget)

### Where we are (CLEAN-cluster, RULE-4 verified this session)
- **High-water mark = sess23 (ccloop), build `2C16B9C9` = cache_coherency 3/4**
  (cross_visibility, rename_visibility, unlink_visibility PASS; only cross_write_read FAIL).
  sess23 root: P122/P93 **write-side** suppression (`mxfs_suppress_stale_agwrite`) was the
  CORRUPTOR — it mis-classifies legit COALESCING frees (numrecs legitimately decreases) as
  stale reverts. Disabling it (now `=false`, void-casts at xfs_buf.c:2221) → 0/4→3/4. See
  [[sess23-ccloop-suppression-was-corruptor-3of4]].
- **Current tree builds `1F7AF33C` (+ my instr = `C01185FA`) and is REGRESSED to 2/4.**
  cross_visibility + rename_visibility PASS; **unlink_visibility now FAILs**; cross_write_read FAIL.
  The sess23 write-side fix is STILL in the tree (verified `mxfs_suppress_stale_agwrite=false`),
  so the regression came from the later ccloop "session 24" W2/inobt-detector work.

### PROVEN regression mechanism (RULE 4, direct dmesg)
unlink_visibility shuts a node down via the **read-side sibling interlock P110-BIO-OVER-LOGGED**
(pal/linux/xfs_buf.c:2785-2805). It refuses a PLAIN-BIO READ of an AG-meta buffer when
`mxfs_buf_is_ag_metadata(bp) && mxfs_buf_has_uncheckpointed_mods(bp)`, keeping the in-core
image. Observed: `P110-BIO-OVER-LOGGED daddr=4174642 ops=xfs_agi comm=rm` during `rm` →
then `Metadata I/O Error (0x1) at xfs_inactive_ifree (xfs/xfs_inode.c:2093) → SHUTDOWN`.
P110 has the **EXACT SAME flawed premise sess23 disproved for the write side** — "in-core is
always authoritative" is FALSE for a legit AGI update during ifree. (Other stochastic
manifestations same run: inode-lock DIVERGENCE livelock → `P-CAWEXH ... all CAS counters 0`
= caw_lock divergence path ~dlm_caw.c:1387-1468 spins because in-core i_dlm_mode re-adds the
EX bit; and xfs_defer_finish_noroll corruption xfs_defer.c:721 — all in the two-EX-holder window.)

### THE FIX TO TRY FIRST (next session, RULE 4)
Make read-side **P110 LOG-ONLY** (mirror sess23's write-side disable): in pal/linux/xfs_buf.c
~2785, keep the pr_warn but DELETE the `bp->b_error=0; bp->b_flags|=XBF_DONE; xfs_buf_ioend(bp);
return;` action so the plain-bio read proceeds normally (under fua_disable=1 the plain read hits
the COHERENT SCST write-back cache, NOT a stale platter — so it can't serve stale; sess23 proved
the acquire-invalidation + release-drain fences are tight: P79/P14/P47/P126 = 0). Rebuild,
power-cycle+reset4, re-run unlink_visibility (MXFS_NODE_OFFSET=0). Expect: no P110 shutdown,
unlink_visibility PASS → back to 3/4. If the divergence-livelock (P-CAWEXH) still shuts a node
down, that's the next target (inode-lock mutual-exclusion: two nodes EX on same dir inode).

### Then: cross_write_read (the sole fail at sess23's 3/4 ceiling)
Per [[sess23-ccloop-suppression-was-corruptor-3of4]]: node1 missing from peers' OK lists =
likely reg-file writer-durability / reader-staleness (DIFFERENT path from AG-meta; see
sess79/sess85/sess45 reg-file BAST-release flush + di_size). Only after 3/4 restored.

### Iteration rules (BINDING)
- ALWAYS power-cycle ALL 4 (`sudo virsh -c qemu:///system destroy+start`) + `bash tests/reset4.sh 4`
  + set `fua_disable=1, instr=0` + `dmesg -C` before any trusted run. The first run on a
  stale/old-build mount gives FALSE failures (burned 2 runs on this).
- Inner loop healthy now: `bash tests/repro_rename_concurrent.sh "test1 test2 test3 test4" 20`
  AND `100` → TOTAL_FAILS=0 ×4. Subtests: `MXFS_NODE_OFFSET=0 MXFS_TESTS_DIR=/src/mxfs/tests
  bash tests/run_tests.sh --nodes 4 --phase cluster --test test_unlink_visibility
  --pass-file /tmp/.mxfs_pass --device /dev/sda --mount-point /mnt/shared`.
- cache_coherency.sh hardcodes MXFS_NODE_OFFSET=16 (test17-32) — our cluster is test1-4, so
  run subtests with OFFSET=0, or override.
- Cluster currently left mounted on build C01185FA (P-CAWEXH instr, KEEP as regression gate).

### Marker NOT written — ship gate RED (cache_coherency 2/4; 11/12 other criteria PASS).
Related: [[sess23-ccloop-suppression-was-corruptor-3of4]] [[sess122-ccloop-unlink-3failmodes-agfence-gap]]
[[cache-coherency-rearch-provenance-and-gap]] [[sess19b-shared-epoch-design]].</body>
