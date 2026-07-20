---
name: AAA-ccloop8ba7-sess3-repro-iter1b-CATASTROPHIC-inode-cluster-clobber
description: iter1b (build 4462813A+probes): cc PASS but posix_multi 0/32 — urandom over live inode cluster (AG40 agbno16, ino~83886208). P130/P131/P75-cil ALL SI…
metadata:
  type: project
tags: [ccloop-8ba7ae5c, repro, double-alloc, inode-cluster-clobber, iter1b]
---

# sess3 repro iter_1b (2026-07-16 19:57-20:01) — CATASTROPHIC reproduction, new build 4462813A

## Setup
Build 0.10.109 srcversion 4462813A73DD5D2C880777F = 5DA487D4 + P130-FALSE-FRESH (lineage cert,
xfs_mxfs_dlm.c fresh-acquire ~26240 + lineage_open cleared at 4 unlock sites + single→multi reset) +
P131-INVAL-DISCARD (invalidate_ag_meta locked branch superset) + P75 cil_resident extension +
P-DBLALLOC disk_owner + P-DBLALLOC-AGF discriminator (xfs_alloc.c). Probe param dblalloc_probe=1 via
MXFS_EXTRA_MODARGS. Harness: scripts/dblalloc_repro.sh <iter> (prep fresh + precond+cache_coherency,
then strong_consistency+posix_multi; pulls per-node probe journals to tests/logs/dblalloc_repro/iter_*/;
static uv/pm fork-overlap check vs /home/steve/disk.img).

## Results iter_1b
- prep OK (one earlier prep attempt failed convergence: test5 stuck active_count=31 — retry worked).
- cache_coherency PASS 32/32 (3021 checks). strong_consistency PASS.
- **posix_multi FAIL 0/32 NO_TERMINAL_RECORD** — cluster-wide collapse at ~20:00:38: 85×
  "Metadata corruption detected at xfs_inode_buf_verify, xfs_inode block 0x4fd9ac0" (test18 + others);
  hexdump = PURE URANDOM → **file data written over a live-mapped inode cluster** (AG40 agbno16,
  chunk base ino 83886208). Reads → EIO cluster-wide, no shutdown.
- **P130-FALSE-FRESH: 0 hits. P131-INVAL-DISCARD: 0. P75 cil_resident: 0. P121/P117-coldread: 0.**
  → acquire-side discard + release-left-dirty + false-fresh ALL REFUTED again on a live catastrophic repro.
- P-DBLALLOC: 574 hits (148 dir-block / 16 dir-leaf / 410 holds=inode) BUT content-check has a
  FALSE-POSITIVE gap: freed chunks/dirs leave stale live-looking content (mode!=0 dinodes persist if
  ifree's cluster zeroing only logged, or legit reuse) — hit count ≠ double-alloc count.
- P-DBLALLOC-AGF: 570/574 differ=1 BUT direction analysis shows in-core freeblks LOWER than disk by
  exactly the in-flight tx allocs = NORMAL mid-tenure lag; verdict string misleading. 4× differ=0.
  KEY sample: test13 kworker (cwr writeback) tenure=1 (FIRST-ever AG9 acquire, FUA-cold) allocating
  AG9 agbno296-300 (data) whose content = mode-0644 dinodes; disk AGF freeblks=261357 constant.
- test9 was NOT the AG9 carver in-window; carver unknown (icreate sweep inconclusive; P102-ACQ is
  dirwr-gated OFF so fresh-acquire events invisible — consider ungating for next iter).

## Next steps (decisive)
1. Unmount all 32 → static FULL cross-reference on /home/steve/disk.img: walk inobt chunks (root
   agbno3 per AG, AGI at agstart sector 2) + ALL allocated inodes' data forks; report any block
   claimed by BOTH a chunk and a fork extent (or two forks). Two live owners = double-alloc PROVEN
   per-block, no write-history needed. (uv-vs-posix method generalized.)
2. If proven at AG40/16: identify the data-extent owner file → its writer node → that node's AG40
   acquire/alloc history vs the chunk carver's — the handoff that lost the alloc.
3. Fix detector FP gap if needed: holds=inode hits are only DBLALLOC-certain when inobt ALSO still
   owns the chunk (post-hoc static check per hit, not in-kernel).
4. posix_multi 0/32 NO_TERMINAL_RECORD despite budget 30s: [30s/30s] — nodes all EIO'd/hung on the
   corrupt cluster; run.sh leftover-killer fired. This IS the reproduced failure, budget red herring.
5. Journald rotation: pull per-iter (harness does). P102-ACQ + P10-INSTR are mxfs_dirwr/instr gated —
   next build consider ungating P102-ACQ (fresh-acquire visibility) — cheap, rare event.

## Iteration cost
~5.5 min/iter healthy (prep 90-150s, cc ~100s, sc+pm ~40-70s, sweeps ~60s). Prep convergence flake
~1/2 tries (test-N stuck at 31 members — just retry).
