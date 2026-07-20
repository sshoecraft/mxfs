---
name: sess59-drc-readdir-miss-stale-disksize-gen-equal
description: sess59 RULE4: dir_reuse readdir-miss root candidate = reader in-core dir i_disk_size lags on-disk (8192<12288) while i_dlm_dir_gen MATCHES → reload s…
metadata:
  type: project
---

## sess59 — dir_reuse_coherency readdir-miss: instrumented root candidate

### Fast reliable reproducer (KEEP): tests/tcp/drc4_repro.sh
N-node standalone, NO MQTT. Key: all nodes cold-read (drop_caches+readdir)
**CONCURRENTLY** (parallel ssh), matching the suite coord_barrier release.
- Sequential reads (v1) = 20 rounds CLEAN (race masked, settles in <1s).
- Concurrent reads = FAIL round 9 (`node4_f45.md5` missing from readdir on
  ALL 4 nodes, lookup_fail=0). So the miss is a TRANSIENT visibility gap at
  concurrent barrier-release that self-heals in ~1s — still a FAIL by
  [[feedback_timing_is_failure]] (coherency must be prompt ~ms).
Usage: `bash tests/tcp/drc4_repro.sh 4 50 24` (cluster mounted on test1-4).

### Smoking-gun probe (P62-RELOAD-FORK-SHRINK on a missing node, test1):
`incore_fmt=2 incore_nx=3 incore_size=8192 disk_fmt=2 disk_nx=3 disk_size=12288
 incore_gen=2844007164 disk_gen=2844007164 shrink=0 post_release=1`
- On-disk dir = 12288 (3 data blocks); in-core = 8192 (2 blocks). The 3rd
  block holds node4_f45.md5's dirent.
- **incore_gen == disk_gen** despite size divergence → the gen-gated reload
  treats the inode as up-to-date and does NOT adopt the larger disk size.
- readdir enumerates by the stale (smaller) i_disk_size → misses entries in
  the newly-added trailing data block. lookup uses the size-independent
  da-btree hash → still resolves them (lookup_fail=0). Matches symptom exactly.

### HYPOTHESIS (falsifiable, not yet code-proven):
The dir-modify generation counter (i_dlm_dir_gen — what EVICT-RING-DIRMOD
bumps and P62 compares) is NOT bumped on the dir-GROWTH path that extends
i_disk_size / adds a new dir data block. A peer at the old size sees
gen-equal, skips the FUA-reload, readdir short. OR: the reload fires but
only refreshes extents+gen, not i_disk_size (incomplete apply). OR: a
shrink-revert guard (P43/sess49 family) wrongly blocks a legit GROW.

### NEXT (RULE 4): localize in xfs/xfs_mxfs_dlm.c —
(a) where i_dlm_dir_gen is bumped vs the dir size-extend/data-block-add path;
(b) whether the reload applies disk i_disk_size on a grow;
(c) is the P62 "shrink" guard gating grows too.
No corruption/shutdown. Transport-independent → fix carries to CAW.
See [[sess59-4node-tcp-16of17-dir-reuse-coherency-fails]].
