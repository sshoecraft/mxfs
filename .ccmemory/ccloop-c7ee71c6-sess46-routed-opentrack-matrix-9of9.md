---
name: ccloop-c7ee71c6-sess46-routed-opentrack-matrix-9of9
description: sess46: routed open-unlink protection built per GPT C9-ordering (363→369), matrix 9/9 at knob=1+tracking; 5 kernel defects rooted on the way; refusal…
metadata:
  type: project
tags: [ccloop, sess46, iclus, open-unlink, matrix]
---

# sess46 — ICLUSTER open-tracking port: design → 5 roots → matrix 9/9

## What shipped (0.11.363-369, all builds same-day)
GPT design ruling (full text in session transcript, task ky7033o2v) applied:
- `mxfs_dlm_caw_open_set` — durable standalone SET, allocate-on-set live
  bit-only slot, claim discipline verbatim from lock claim, dup-merge to
  canonical (`caw_open_set_dedup`) since concurrent fresh claims can dup
  and a knob=0 reboot would inherit sess47 two-EX corruption.
- `mxfs_dlm_caw_open_probe` — claim-less B6 read; classes: bits-found
  (union over live+tombstone+dup records), AUTHORITATIVE_ABSENT (clean
  walk to zero terminator), error/garbage/cap → defer. Per-slot fresh
  reads, no span.
- `mxfs_iclus_disk_release` — single choke point (normal, bast_notify,
  selfclear) gating on `mxfs_iclus_publish_open_bits` sweep.
- Admission gate `mxfs_iclus_open_admit` + slow-path conversion in
  `mxfs_dlm_open_protect` (P95-OPEN-CLUSTER-CONVERT).
- `i_mxfs_open_setting` closes close-during-SETTING (C4 defers to setter).
- Retention: `caw_repair_slot` preserves open_holders (WAS WIPING — live
  hole in shipped per-inode tracking); claim inherit restores tombstone
  bits; bit-carrying foreign tombstone resurrection (P-OPENBITS-TOMB-*).
- open_clear = chain walk over ALL same-resource records.
- xfs_super refusal LIFTED; icluster default-ON later must bump
  MXFS_PROTO_GEN (C7 vergate enforces).

## The five roots (each RULE-4 evidence-first)
1. **P90 intent poisoning** (364): per-inode publish set pub=true for
   routed inodes; sweep believed it durable, skipped SET. Evidence: P90
   fired + zero P-ICLUS-OPENSET + defer=0.
2. **Sticky-vs-config gate** (365): fresh create's grant is mode-0-era
   per-inode; sticky bit lands NEXT acquire; gate must be
   mxfs_dlm_iclus_covered.
3. **Tombstone-serving open** (366): ilock-ride adoption of peer-freed
   image (P116) completed the open, read ''. Now -ESTALE → re-walk →
   ENOENT. All configs. (matrix hold_fd also fixed: pidfile-wait.)
4. **Split-brain** (367): covered inode on LOCAL grant vs peer's routed rm
   through unheld CLUSTER resource — free with no BAST/sweep/bit
   (P19-B3DEC will_skip=0, zero opener interaction). Fix: admit refuses
   !ic; slow path forces conversion. Matrix 9/9 from here.
5. **cwr empty-md5** (368): LOCAL-grant dirty 33-byte .md5 invisible to
   iclus release (fan_out/covered_active were sticky-gated) → cluster
   handed off pre-drain → 31 readers read empty exp, consistent data
   file. Widened both to config predicate (dirs excluded — dir-131
   EDEADLK family). Pre-existing at knob=1 since Phase A.
   → 369: widening starved -EDEADLK SELFCLEAR (spinner's own ILOCKed
   local grant uncounted-demotable) → 2× 0x8 shutdown under load-63.
   Selfclear covered_active now skips the acquiring ino. 369 rode out a
   load-79 burst 32/32 mounted.

## Verification state (369, knob=1+open_tracking=1)
- openunlink_matrix 9/9 ×2 (368, 369). trunc_legal/partial coherent.
- Board rows green earlier this session at knob=1 (362: 12 rows; 367-368:
  fairness/strong/posix/mmap/membership/cc/zsl/fence/dd chunks — cc had
  ONE 1-of-654 cwr flake → root #5).
- PENDING: full board at 369 knob=1; knob=0 ship-config regression board
  (shared primitives touched: repair/claim/open_clear/P95-ESTALE);
  crash_consistency + dir_reuse at 369; rsync lap continuation.

## Watch items
- P95-OPEN-STALE-INCARNATION ×2 back-to-back seen once (VFS retry also
  ESTALEd) — userspace can see ESTALE where local fs gives ENOENT; legal
  (NFS semantics) but a wart; alias-retirement should kill the dentry.
- P-ICLUS-OPENSET with opens=0 print = post-SET recheck clearing (benign,
  by design).
- Slot-table capacity: bit-only slots unreclaimable while set (GPT
  liveness note) — telemetry not yet shipped (occupancy high-water).
- GPT fault-arm list (20 items) not yet run as dedicated tests; matrix
  covers ~8 semantically.

## Rig discipline
Game-server bursts hit load 63→88 today; two NO_TERMINAL all-32 events
excluded (load-79, load-63). ALWAYS gate laps on 1-min load <30 — but the
check must be INSIDE the same shell &&-chain immediately before run.sh
(lap 1 raced a burst that started mid-run; unavoidable, excluded).
