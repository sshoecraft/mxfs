---
name: reference_mxfs1_sess74_results
description: mxfs.1 v0.14.0 sess74 (2026-05-07) resurrection results on same hardware as v5. PARTIAL WIN on dd/fio/metadata-storm; SINGLE-NODE CORRUPTION on rsync-of-deep-source-tree (element-web). Architecture decision is NOT settled. Read sess74_lessons.md in mxfs.1's memory project AND the rsync-bench update below.
type: reference
originSessionId: 7229d9d0-b519-4889-a60f-2f0fe50bd187
---

## ⚠️ UPDATE 2026-05-07 (post-rsync-bench, supersedes morning headline)

The morning's "mxfs.1 is in better correctness shape than v5" headline
was based on dd / fio / metadata-storm only.  An rsync-bench run later
the same day exposed a single-node correctness bug that the morning
sweep missed.

**Single-node corruption on rsync of element-web** (4,385 files /
971 dirs, JS-app deep nesting):
  - Bug location: `libmxfs/dir_cache.c::flush_*_dir` — dir format
    transition (likely SF→block→leaf) corrupts dir blocks during
    writeback.
  - Symptom: dmesg fills with `dir_cache: block dir ino N:
    unexpected magic 0xNNNNNNNN, attempting parse anyway`.  The
    recovery branch produces binary-junk filenames and bogus inode
    numbers (in the trillions).
  - User-visible: rsync silently drops ~84% of the tree, exits 23.

**Single-node perf degradation on rsync of open-gpu** (no corruption
triggered, but journal saturates faster than it drains):
  - Iter 1: 13s, Iter 2: 88s, Iter 3: 116s.

**XFS native baseline on same hardware:** 2.5-3.7s on both trees,
full md5 integrity.

**Implication for v5 vs mxfs.1 decision:**
  - mxfs.1's morning numbers (1.00x XFS fio, 100% pass on 2-node dd
    stress) are real for those workloads, but they do NOT generalize
    to realistic create-heavy nested workloads.
  - mxfs.1 has a SINGLE-NODE corruption bug that v5 does not have.
    v5's bugs are cross-node.  Different bug surface, not strictly
    "mxfs.1 better."
  - Neither version is currently production-ready on this hardware.
    The decision is harder, not easier.

---

## Original sess74 morning section (kept for context — note caveat above)

mxfs.1 (the first-attempt MXFS at `~/src/mxfs.1/`) was resurrected and
validated in session 74 on 2026-05-07, on the same hardware that v5 is
tested on (test1 + test2 on clyde, kernel 6.8.0-101, Samsung 870 EVO
via tcm_loop+iblock CAW).

## Headline numbers (use these when comparing v5 to mxfs.1)

| Workload | mxfs.1 v0.14.0 | v5 sess30 (v0.3.128) |
|---|---|---|
| fio seq write 1m single-node | 505 MiB/s = 1.00x XFS | ~99% XFS |
| fio rand write 4k single-node | 261 MiB/s = 1.03x XFS | ~91-96% XFS |
| 5×256 cross-node × 5 samples | 25/25 = 100% | 20/25 = 80% |
| 15×256 × 3 samples | 45/45 = 100% | mixed: 4/15, 1/15, 15/15 |
| 15×512 × 3 samples | 45/45 = 100% | mixed: 6/15, 8/15, 7/15 |
| Metadata stress 10 min | PASS, no corruption | not measured |

## Where the data actually lives

- `/home/steve/src/mxfs.1/state.md` — sess74 section at top, dated 2026-05-07.
- `/home/steve/src/mxfs.1/bench.json` — `sess74_resurrect_v0140_fio`
  entry (canonical fio sweep), `sess74_resurrect_v0140_dd` (paired
  XFS / mxfs.1 dd numbers).
- `~/.claude/projects/-src-mxfs-1/memory/sess74_lessons.md` —
  **project-scoped to mxfs.1, will NOT auto-load in /src/mxfs sessions.**
  If working on cross-version comparisons, read it explicitly.

## Real open issues in mxfs.1 (not a free win)

1. CAW disk-lock table is hard-capped at 4096 entries
   (`libmxfs/disklock.c`). Saturates at OS-install scale (~10K-100K
   files). Produces 120s timeouts. Needs dynamic sizing or aggressive
   LRU eviction before mxfs.1 is production-grade for full-tree workloads.

2. Cross-node visibility window without writer-sync — test2 writes,
   test1 reads without intervening sync, sees `init_special_inode:
   bogus i_mode (0)`. Same "Mode A" class as v5 has been chasing.
   Workaround: writer fsync. Real fix: BAST flush dirty inodes before
   granting.

3. Allocator self-heal dmesg events (`cntbt/bnobt desync`, `chunk
   not found in inobt`, `stale sb`) — appear during normal operation,
   self-correct, KERN_NOTICE level. Same bug family v5 has been
   chasing reactively; mxfs.1 reconciles silently.

## How to apply

- **Don't claim v5's perf advantage over mxfs.1 without re-measuring
  on the same hardware in the same session.** Sess30 was implicitly
  comparing v5 (99% XFS measured) against mxfs.1's stale v0.13.0
  rsync number (24% XFS) — the freshly-measured fio numbers in
  sess74 invalidate that framing.
- **Don't assume v5's manual-bio CAW fix is needed for mxfs.1.**
  Sess74 confirmed mxfs.1's PAL also calls scsi_execute_cmd and
  passes 100% at 2-node. The bio-aliasing hypothesis behind v5's
  fix doesn't appear to bite mxfs.1 at 2 nodes. Don't port v5's
  fix to mxfs.1 prophylactically.
- **Storage-side facts (FUA-on-write semantics, Samsung 870 EVO
  bdev_fua=0, LIO emulate_write_cache=0) are real and apply to BOTH
  v5 and mxfs.1.** Sess30 documented these for v5; sess74 reconfirmed
  them for mxfs.1. They are environmental, not version-specific.
