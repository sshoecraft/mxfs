---
name: ccloop-c7ee71c6-sess40-END-open-tracking-shipped-and-claim-exhaustion-found
description: sess40 END: AGI root proven + per-slot buckets + open-tracking/deferred-reap all shipped &amp; verified (0.11.331-335); NEW claim-retry-exhaustion de…
metadata:
  type: project
---

# sess40 (ccloop session 22) END — three increments shipped+verified, one new defect isolated

## Builds 0.11.331 → 335 (all verified at 32/caw)
1. **331 tombstone semantics**: MXFS_IF_FREE_COMMITTED (1U<<27, set only at committed ifree) gates the two free-aware DLM release sites. "Inactivation skipped != inode freed" (GPT).
2. **332 per-slot AGI buckets** (mxfs.iunlink_slot_buckets=1): the structural fix for D-AGI-UNLINKED. Same-build A/B on tests/agi_bucket_repro.sh — knob=1 pair+chain CLEAN, knob=0 reproduces -117 + withdrawal.
3. **333/334/335 open tracking + deferred reap** — closes D-CROSSNODE-OPEN-UNLINK-DATA-LOSS (peer's unlink was truncating+freeing a file another node held open; live fd read 20 bytes of zeros).

## Open-tracking design AS BUILT (two measured redesigns — do not regress these)
- `open_holders` uint64 bitmap in the CAW slot's reserved area (slot stays 512B). Tombstones preserve it; same-resource claims inherit it; fencing strips dead nodes' bits; unlock_free zeroes it; slots with open bits do not tombstone.
- **PUBLISH ON THE BAST-RELEASE CAS, NOT PER open()**. Per-open CASes bumped generations on hot slots and starved real acquires: 32 nodes × ~20k opens (zsl) → `ea_claim=100 → rc=-110 → SHUTDOWN_CORRUPT_INCORE`, 234/644 zsl checks lost. BAST release is the ONLY moment a peer's destructive path can be imminent (it must BAST every holder off to take EX), so publishing there is both sufficient and rare.
- **CLEARS MUST BE GATED ON i_mxfs_open_pub**. Ungated, evict + unlinked-exit ran a full slot probe (SCSI reads) for every inode → zsl 440/644. With the gate: 644/644. Only what we set gets cleared.
- `i_mxfs_open_n` (atomic, xfs_file_open/release) + `mapping_mapped()` = protected activity.
- B6 OPEN-DEFER guard at the HEAD of destructive inactivation (before truncate), under the EX it already holds: peer bits ⇒ defer truncate+ifree; zombie stays durable on our bucket; per-mount deferred-reap list + 30s worker (iget+irele re-drives the guard).
- **Reap entries MUST carry the defer-time authority snapshot** (MXFS_IF_LOCAL_UNLINK + i_unlinked_bucket) and restore it after the generation match — a fresh iget has neither, and the B4 no-authority guard then blocks the owner's own reap forever (measured: retried at 30s cadence indefinitely).
- Verified lifecycle: P87-OPEN-DEFER (open_holders=0x3) → P88-REAP-RETRY (0x3→0x1 as the closer's bit clears) → P145-FREE + P89-REAP-DONE within one 30s cycle of last close. Probe: tests/openunlink_probe.sh (PASS; pre-fix FAIL with zeros).
- **mxfs.open_tracking knob (default 1)** = same-build A/B control. Use it before blaming this work for anything.

## NEW DEFECT: D-CAW-CLAIM-RETRY-EXHAUSTION-SHUTDOWN (critical, in ledger)
Cold-read PR acquire loses the claim-empty CAS 100× (MXFS_CAW_MAX_RETRIES, no liveness extension, unlike the wait/unlock paths) → rc=-110 → ilock_begin escalates to SHUTDOWN_CORRUPT_INCORE → cluster cascade (10-32 nodes). All retries ea_claim; requester never registers as a waiter; on-disk census of a stuck resource: slot LIVE gm=5 hex=1 waiters=0.
**RULED OUT by measurement**: table exhaustion (556-1845 live of 65536), pre-mkfs ghosts (one volume id), host storage (fsync p90 6.5ms), and MY OWN WORK (open_tracking=0 control arm reproduces identically; 332 was intermittent too).
**Next measurement**: print target empty_idx + resource hash base + slot content at the last miscompare + full-probe re-check → distinguishes 32-way claim contention vs broken probe chain vs stale compare image. Independently: a claim timeout must never shut the FS down (use the shipped unlock-path wall-clock-deadline pattern).

## Board state on 335 @32/caw
PASS: fio_perf, cache_coherency 654/654, strong_consistency, zero_silent_loss 644/644, scaling_curve, precond_readiness, posix_multi, mmap_coherency, dlm_fairness, dlm_membership, dlm_scaling, dirent_durability (30r loss=0), dirent_publish_integrity, fence_during_write, fault_netpartition, soak, openunlink_probe, agi_bucket_repro.
INTERMITTENT/RED: crash_consistency + dir_reuse_coherency — both now attributed to the claim-exhaustion defect above, NOT to budget.

## Rig notes
- Native XFS same-LUN reference: `MXFS_DEV=/dev/mapper/mpatha MXFS_FORCE_PREP=1 ./run.sh 1 xfs prep_cluster` (umount all 32 first), then tests/native_xfs_ref.sh: create p50 0.07ms; cold stat 0.16 / open 0.13 / getdents 0.12 / rmdir 0.29ms. mxfs peer-cached equivalents: 23 / 24 / 73 / 99ms.
- Slot-table census one-liner: O_DIRECT read /home/steve/disk.img @67149824, 65536×512; magic@+0 (LIVE 0x4D584357, TOMB 0x4D58444C), volume@+8, ino@+16, holders_ex@+40, open_holders@+152.
- 9 OPEN defects.
