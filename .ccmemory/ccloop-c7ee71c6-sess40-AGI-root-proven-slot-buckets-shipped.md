---
name: ccloop-c7ee71c6-sess40-AGI-root-proven-slot-buckets-shipped
description: sess40: AGI cross-node zombie ROOT PROVEN (deterministic 2-node repro ~40s); per-slot buckets SHIPPED 331/332 + verified A/B; NEW open-unlink data-lo…
metadata:
  type: project
---

# sess40 (ccloop session 22) — AGI-unlinked family: root proven, structural fix shipped

## Deterministic reproducer (THE session tool): tests/agi_bucket_repro.sh
- pair|chain phases, test1/test2, ~40s. Held-open unlinked fds = persistent zombies; congruent inos (same AG, ino≡mod 64) force cross-node bucket adjacency ON DEMAND. agshift=21 on this fs (agno = ino>>21).
- Key discovery en route: mxfs shards inode ALLOCATION per node across AGs — cohabitation comes from UNLINKING PEER-CREATED files (any shared-tree rm), not concurrent creates. Pool must be created by ONE node.
- First run reproduced the sess38 shutdown shape byte-exact: B's insert faults A's live zombie in (P83-UNL-RELOAD) + BASTs A off its own open-unlinked EX; A's close → head-mismatch with stale self-view (prev=NULLAGINO "I am head") → xfs_iunlink_lookup(NULLAGINO)=NULL → -EFSCORRUPTED at libxfs/xfs_inode_util.c:778-781 → shutdown → withdrawal.
- ROOT (design-level): i_prev_unlinked is IN-CORE-ONLY state mirroring a cluster-shared on-disk list; the peer that mutates the list updates it only in ITS icache. Upstream premises (all members in-core; not-in-core ⇒ abandoned orphan to free) both false cross-node.

## Shipped
- 0.11.331 increment 1: MXFS_IF_FREE_COMMITTED (1U<<27, set only at committed ifree) gates both free-aware DLM release sites (xfs_inactive exit + mxfs_dlm_evict ~30516). "Skip ≠ freed" (GPT). Verified: P144 only on true free.
- 0.11.332 (2069AD0467906282A95EA7F) increment 2a: per-slot AGI buckets. mxfs.iunlink_slot_buckets=1 (cluster-uniform ONLY); xfs_iunlink_pick_bucket + xfs_iunlink_member_bucket in libxfs/xfs_inode_util.c; i_unlinked_bucket int16 stamped at insert/recovery/reload walks, USED by remove, reset at remove+skip+alloc; P84 unset-warn, P85 foreign-reload gate, P86 recovery-scope skip; mount recovery multi-node = own bucket only (single-node = all 64 legacy sweep); scrub gated (not compiled).
- A/B same-build: knob=1 pair+chain CLEAN (0 reloads, 0 corruption); knob=0 REPRODUCES (-117+withdraw). 32/caw: cc 654/654, dirent 30r/0loss, fence PASS, netpartition PASS, crash PASS 19s re-run (first pass 90s budget FAIL = pace-tail coupling, md5 sidecar phase 43s = 1600 shared-dir creates; correctness failed=0).
- KEY COLLAPSE: slice index == disklock slot ⇒ adopted slice's dead-owner bucket == claimant's own bucket ⇒ already swept by scoped mount recovery.

## NEW DEFECT (ledger): D-CROSSNODE-OPEN-UNLINK-DATA-LOSS (critical)
- tests/openunlink_probe.sh (~15s): B's unlink of a file A holds open runs B's FULL destructive inactivation (truncate frees A's extents!) — A's live fd reads 20×\0. No open tracking exists (no iopen equivalent). posix_multi has ZERO unlink coverage (board honest but blind).

## Fix design (GPT-approved, 2 consults in transcript): open_holders bitmap in slot reserved bytes
SET piggybacked on acquire CAS; LAZY CLEAR (evict CAS or on-demand revalidate incl. mappings/DIO/writeback); defer guard at HEAD of destructive inactivation under EX (before truncate!); deferred-reap list + periodic worker + reap-nudge; fencing strips open bits; TEN acceptance invariants in ledger AGI entry; survivor sweep of dead/unowned buckets MANDATORY (unbounded liveness defect otherwise); slot-format feature bit for mixed-version rejection (rig = re-mkfs interim).

## Rig/other state
- 8 OPEN defects (7+1 new). Fleet on 332 uniform, fresh fs (FORCE_PREP after native window).
- NATIVE XFS same-LUN reference (tests/native_xfs_ref.sh via `MXFS_DEV=/dev/mapper/mpatha MXFS_FORCE_PREP=1 ./run.sh 1 xfs prep_cluster`; needs all-32 umount first): create p50 0.07ms mean 0.10; cold stat 0.16 / open 0.13 / getdents 0.12 / rmdir 0.29ms.
- Pace re-baselines @32 on 330, host-fresh (fsync p90 25.1ms): shared create mean 196ms p50 7 p95 1932; PRIVATE no longer flat (mean 118, tail-driven); peer-cached per-op stat 23 / open 24 / getdents 73 / rmdir 99ms (uniform ~23ms first-touch revocation + readdir ~50 on top). Ratios vs native: readdir ~600x, create ~2000x mean. Both pace defects unambiguous OPEN; tail anatomy is the next lever.
- P82-ADD print still displays HASH bucket (cosmetic; fix in next build).
- crash_consistency first-pass-after-fresh-prep can burst over 90s from the pace tail (known coupling; re-run passed 19s).
