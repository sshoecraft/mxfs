---
name: sess-tcp-FIX-noncaw-slot-claim-unique-ags
description: FIX (build A3E2842C): non-CAW verified disklock slot claim → nodes get unique slots 0,1 → distinct preferred AGs → eliminated the AG0 inobt-collision…
metadata:
  type: project
---

## Build A3E2842CCEF45CB87CF67FD (was F22321→C44D5CF3→A3E2842C)

### Problem chain
2-node tcp: disklock slot-claim uses SCSI COMPARE_AND_WRITE (0x89). This SCST LUN REJECTS it
with ILLEGAL REQUEST / INVALID FIELD IN CDB (sense 0x5/0x24) regardless of caw_path 0|1 or
SCSI-PR registration (added PR to TCP path in C44D5CF3 — did NOT make CAW succeed). sess130
had switched the claim from a racy plain-write to CAW precisely because parallel mounts
collided; but CAW is dead on this target, so claim returned -EIO and node_slot defaulted to 0
on EVERY node → AG affinity (node_slot % maxagi) sent all nodes to AG0 → concurrent same-AG
inode alloc/free corrupted AG0 inobt freemask → EFSCORRUPTED FS shutdown (dlm_fairness wedge).

### FIX (dlm/disklock.c): mxfs_disklock_claim_slot_noncaw()
claim_slot now falls back to a VERIFIED non-CAW claim when CAW fails: FUA-scan (read_prio) for
own/free slot → FUA-write our record (unique timestamp) → sleep 30ms → FUA-read-back; accept
only if node_id AND timestamp survived. A racing peer's later write wins the read-back; the
loser rescans. Closes the sess130 race the old blind plain-write had. Harness mounts
sequentially so common path is uncontended. Result: test1=slot0 (AG0), test2=slot1 (AG1) —
verified in dmesg. Also kept (defense-in-depth): v5_mount.c TCP path registers SCSI PR + a
node_id%64 slot fallback if claim still returns <0 (now only on real disk failure).

### Effect: AG0 inobt-collision FS-shutdown wedge ELIMINATED. dlm_fairness no longer dual-node
shuts down. Remaining (under test): occasional `df shared dir drained got=1/2` stale-readdir
(dir-DATA coherency on the shared dir, NOT the corruption) and possible single-node wedge from
shared-dir-block cross-AG contention (shared dir lives in one node's AG; peer dirent-adds may
allocate dir blocks there). Next: re-measure dlm_fairness 15×; if got=N persists, fix
readdir-time dir-block refresh. Then port 8 PENDING tests. See
[[sess-tcp-ROOT-dlmfairness-both-nodes-slot0-no-scsipr]].
