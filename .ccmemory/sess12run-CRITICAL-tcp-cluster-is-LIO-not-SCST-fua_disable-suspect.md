---
name: sess12run-CRITICAL-tcp-cluster-is-LIO-not-SCST-fua_disable-suspect
description: sess12(ccloop) CRITICAL: TCP cluster test1-4 /dev/sda is LIO-ORG (NOT SCST). fua_disable=1 assumes coherent SCST cache — WRONG for LIO. Testing fua_d…
metadata:
  type: project
---

## sess12 (ccloop) CRITICAL — the TCP test cluster storage is LIO, not SCST; fua_disable=1 may be the dir_reuse root

### Discovery
`/sys/block/sda/device/{vendor,model}` on test1 = **`LIO-ORG  mxfs`**. The TCP cluster (test1-4/8) is backed by a **LIO** iSCSI target, NOT SCST. The CLAUDE.md memory `project_test_cluster_scst` ("SCST not LIO — CAW works") applies to the CAW/v5 cluster, NOT this TCP run.

### Why this matters
Running param `fua_disable=1` (sess45 "SCST shared cache" perf lever). The whole mxfs read-coherency design under `fua_disable=1` ASSUMES the storage write-back cache is **coherent / peer-visible**, so it skips FUA and uses plain-bio reads (`pal/linux/xfs_buf.c` ~L4294: gate `!mxfs_fua_disable`). But:
- CLAUDE.md design tension: **"LIO target drops SCSI FUA bit."**
- ccmemory sess26: **"LIO target CAW reports CAS-success without persisting (cross-node only)."**
So on LIO, a node's plain-bio read after evicting a stale dir block returns the **stale LIO per-initiator cache image, NOT the peer's durable write** → the exact "cold-read returns stale" sess11 documented → cross-node stale-base RMW → durable dir-entry loss (dir_reuse) and the fence_during_write corruption-0x8.

### Caveat / open question
2/tcp passes 17/17 (incl cache_coherency) on this same LIO cluster WITH fua_disable=1, so fua_disable=1 is not categorically broken — but the 4-node heavier contention may expose the gap. DECISIVE TEST IN PROGRESS: re-run `drc4_capture` with `MXFS_EXTRA_MODARGS='dirwr=2 fua_disable=0'` (forces FUA SCSI READ(16) that pierces the LIO cache). If the 9-entry durable loss disappears → root confirmed = fua_disable on LIO. NOTE: fua_disable=0 makes every meta read a FUA roundtrip → SLOW (RULE 0 perf concern); if it fixes correctness, need a scoped FUA (dir-meta only / on-modify only) to stay performant.

### Repro harness note
`drc4_capture.sh` does its own `virsh destroy+start` reset. Do NOT run multiple copies concurrently — they collide on the cluster and wedge prep (module never loads). Run ONE at a time. Use Bash tool `timeout` param ≥ 480000ms (script needs boot ~50s + prep + 24 rounds; default 120s tool timeout is too short and orphans the run).

See [[sess12run-DECISIVE-dir-block-doublealloc-with-AG-btree-block-PROVEN]] (CORRECTION: daddr=27211984 was the dir LEAF block, magic 0x3df1@off8 — NOT a btree double-alloc; the real signature is cross-node stale-base dir RMW revert) [[sess12run-CLEAN-BUILD-4tcp-baseline-two-real-bugs]].
</body>
