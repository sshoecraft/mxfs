---
name: ccloop8ba7-sess7-july14-idle-repro-verified-fixed
description: The July-14 2/caw sticky-ENOENT bug (full suite → 600s idle → dir_reuse FAIL 121/145, 7 failed fix attempts, session 19ba9b24) verified FIXED on 0.10…
metadata:
  type: project
tags: [ccloop-8ba7ae5c, sess7, dir-reuse, verification]
---

# July-14 idle-gap dir_reuse bug — verified fixed (2026-07-17, build 0.10.120/F2443A0C)

## The original bug (session transcript 19ba9b24-5959-4857-ba1d-bf9a38771dbd.jsonl, 07-14→07-15)
2/caw: full 19-test suite → idle 600s (reproducing a natural ~9min gap) → dir_reuse_coherency FAILED deterministically (145 checks, 121 passed, 24 failed), STICKY until reform. Idle-after-fresh-reform alone passed — needed full-suite-then-idle. Signature: rank2 statx ENOENT on /mnt/shared/.dir_reuse_coherency itself (rank1's created dir invisible); root ino=128 reloaded byte-identical stale content 707×; coordinated lookups 490× still ENOENT. Seven fix attempts across 4 layers (dentry cache / DLM lock modes incl. the PR-fast-path-ignores-i_dlm_stale fix / buffer eviction / mxfs_dlm_reload_inode) all failed identically; most reverted; evidence chain in /src/mxfs/state.md of that date. Final UNVERIFIED theory: write-side durability gap on rank1.

## Verification now
Exact reproducer re-run on 0.10.120: FORCE_PREP 2/caw → full suite (all 20 PASS) → sleep 600 → dir_reuse_coherency: **PASS 2/2, 145/145 (260s)**. Second consecutive cycle (another 600s idle → retest, no reform between): **PASS 2/2, 145/145 (265s)**. The formerly-deterministic failure does not reproduce.

## Attribution (plausible, not separately proven)
The write-side theory matches the sess7-proven P150 read-clobber family: rank1's root-dinode update (shortform dirent add) iflushed into the cluster buffer, clobbered by a cold read, stale image written back → durably lost → peers FUA-read stale root forever (sticky ENOENT, "reload 707× byte-identical"). P150 READ-PRESERVE closes exactly that path. Intermediate ccloop-run fixes (P133 raw-FUA init, igrab/P142 guards) may also contribute.
