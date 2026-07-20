---
name: sess69-REFUTED-dataclobber-enforce-makes-it-catastrophic
description: sess69 REFUTED: mxfs.dataclobber=2 (write-side enforce skip) makes 4/tcp dir_reuse CATASTROPHICALLY worse (readdir=0/400 empty dir). Write-side suppr…
metadata:
  type: project
---

## sess69 REFUTED — write-side write-suppression (mxfs.dataclobber=2 enforce) is HARMFUL

Tested `MXFS_EXTRA_MODARGS='dataclobber=2'` (enforce the sess41 write-side clobber guard: plain-read on-disk dir block, skip the xfsaild write if disk has strictly MORE live dirents than the buffer + dc_stale prior-tenure).

Result: round 2 → **readdir=0/400 on ALL nodes** (the directory went EMPTY — catastrophic, vs the baseline's single-dirent loss at round 8-19). P-DATACLOBBER-SKIP fired (≥1×). So the enforce skip SUPPRESSED LEGITIMATE writes and destroyed the dir.

This matches the project's repeated lesson — write-side *suppression* mis-classifies legit writes and becomes the corruptor:
- [[sess23-ccloop-suppression-was-corruptor-3of4]] (P122/P93 suppression mis-classified legit coalescing-frees)
- mxfs.dirskip enforce "refuted sess17" (xfs_mxfs_dlm.c:15430 comment)
- mxfs.dataclobber default 0 (detect-only) for this reason.

**DO NOT retry dataclobber>=2 or dirskip=1 as the fix.** Reverted to defaults (both 0). Cluster reloaded clean (module rmmod'd on all 4 nodes for next-session prep to insmod with defaults).

### Implication for the root
The loss is NOT fixable by suppressing the "wrong" write — because the writes are individually LEGITIMATE (each node holds EX, fresh base — sess69 P-TDS-RMW stale_base=0, P-DOUBLEGRANT=0). The dirent loss emerges from the LEGAL interleaving of legitimate per-node RMWs across the rm-rf+recreate reuse churn, not from any single detectably-stale or illegitimate operation. This is why 68 sessions of "detect the bad operation and suppress/reload it" have failed — there is no single bad operation to catch.

### Reframed next direction
Stop hunting a detectable bad op. Instead either:
1. Add a per-dir-block CONTENT FINGERPRINT probe (entry-count + name-hash) at create-time AND at every write-submit, correlate across node streams by daddr+realns to reconstruct the EXACT interleaving that drops one entry — to see the precise lost-update sequence (which two operations, on which nodes, in which order). Only then is a targeted ordering fix possible.
2. OR accept that the coherency is correct per-op and the gap is a missing SERIALIZATION the test exposes — e.g. the rm-rf+recreate reuse means the dir inode/blocks are freed and reallocated while peers still have them cached; consider whether the dir inode REUSE needs a cluster-wide barrier (drain all peers' caches of the freed inode's blocks before reallocation), which is an allocation/free-side fence, not a dir-modify fence.

See [[sess69-DECISIVE-loss-invisible-to-detectors-double-grant-remaster]] (all coherency detectors refuted), [[sess69-REFUTATIONS-and-gpt-design-dirreuse-4tcp]].</body>
