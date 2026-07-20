---
name: sess36-lessons-ship-gate-5-fixes-mode-a-re-diagnosis-magic-0x0-was-an-artifact
description: "2026-05-29. Fixed 5 ship-gate criteria (slow mount root-caused, dkms packaging, resize, dkms timeout). Core Mode A bug re-diagnosed on SCST as a lost-update; CRITICAL — sess34/35's magic=0x0 was an instrumentation offset bug, NOT a disk-zeros/durability problem."
metadata: 
  node_type: memory
  type: project
  originSessionId: a39db758-41a1-4798-b2ca-2990df902d49
---

# sess36 lessons (2026-05-29)

Autonomous ccloop session toward SUCCESS_CRITERIA / verify_ship.sh. Cluster is v5 =
test1..test16 on SCST (CAW works); coordinator runs on host `clyde` with full virsh.

## Ship-gate criteria fixed + verified PASS this session
- **slow first-mount (~16-18s)** broke cluster_ops_timing, chk_clean, online_membership.
  Root cause = two avoidable delays in CAW DLM mount init:
  1. `mxfs_disklock_get_stale_slot_mask` (dlm/disklock.c) slept a fixed 10s
     (HB_INTERVAL*5) even with no active peers. FIX: poll-with-early-exit (live peer
     HB advances in ~1 interval) + skip entirely when snapshot empty. Correctness
     identical (stale only declared after full window).
  2. `mxfs_dlm_caw_purge_dead_nodes` (dlm/dlm_caw.c) did 65536 single-slot reads (~5s)
     every mount. FIX: batch-read the table in 32-slot/16KB kzalloc chunks for the
     find phase; per-candidate CAS/repair unchanged.
  → first mount ~2.8s, join ~5.5s. 3 criteria PASS.
- **dkms_install**: packaging/common.sh was wired for old mxfs.1 layout (libmxfs/,
  frontend/, mxfs_common.h → version "0.0.0"). FIX: mxfs_version reads VERSION file;
  mxfs_stage_kmod_source rsyncs the v5 tree (compat include xfs dlm pal mxfs_clayer +
  Kbuild/Makefile/VERSION). Also bumped the criterion's per-call SSH timeout to 300s
  (the on-node DKMS build of the full XFS fork takes ~76s > default 60s). PASS.
- **online_resize**: criterion's `set -e` + `insmod 2>/dev/null` aborted when a prior
  aborted run left the module loaded / loop mounted. FIX (tests/criteria/online_resize.sh):
  idempotent leftover cleanup + `lsmod|grep -q '^mxfs ' || insmod`. PASS.
- Already green: mkfs_timing, wedged_unmount, dmesg_clean, cache_caps.

## The core bug (Mode A / cache_coherency) — re-diagnosed, NOT yet fixed
- Reliable reproducer added: **`tests/repro_modea.sh [iters] [n1] [n2]`** — concurrent
  `mkdir SAMEPATH; touch nodeN; sync` from both nodes, each then lists. **19-20/20 fail**:
  both nodes' dir gets a DIFFERENT inode (lost update / duplicate-create).
- Proven NOT the bug: sequential cross-node visibility (works), concurrent add of
  DISTINCT names to a pre-existing dir (works), storage durability (SCST write-through,
  backing file verified to hold valid XDB3 dir blocks).
- **CRITICAL CORRECTION**: the `magic=0x0` "disk reads zeros" signal that drove
  sess34/35 is an **INSTRUMENTATION ARTIFACT**. P-H16 (xfs/xfs_mxfs_dlm.c) read the raw
  XFS daddr via SCSI without adding `bt_sector_offset` (=196688 sectors, the MXFS
  envelope), so it read the journal region (zeros). Production reads (mxfs_buf_read_fua,
  xfs_buf bio path, xfs_log) all add bt_sector_offset and are correct. FIXED P-H16 in
  v0.4.5. **Re-evaluate sess34/35 "durability cliff" conclusions — likely a phantom.**
- DLM serializes correctly (timeline capture: peer holds root EX → defers our BAST →
  releases → we acquire after). So the real bug = the acquiring node's RMW base for the
  parent dir block lacks the peer's just-committed entry → **incomplete acquire-side
  cache invalidation for dir DATA blocks** (candidate sites: reload H18 stale walk that
  skips locked bufs; the `_XBF_FUA_FRESH`/`mxfs_buf_in_fua_window` gate).
- Two fix attempts DISPROVEN + reverted: (1) bounded wait+stale of skip_locked dir buf
  in BAST-DIR-STALE (staling discards, doesn't write; 20/20 still fail); (2) hold dp
  ILOCK across xfs_dialloc (local ILOCK doesn't serialize across nodes; 17/20).
- sess37 decisive next step: with FIXED P-H16, capture whether the peer's entry is on
  disk at the acquiring node's read time. YES → stale-cache bug, fix = force dir-buf
  re-read on acquire. NO → release-before-write, fix = ensure home write before DLM
  release. See `/src/mxfs/notes/sess36_shipgate.md` for full detail.

## Build state
srcversion E06DB7064C93254CF9EA50A (VERSION 0.4.5) = the 5 ship-gate fixes + corrected
P-H16, NO coherency-logic change. test1+test2 left mounted. Full session-36 instrumentation
(sess20-35 P-* printks) still present; not stripped (dmesg_clean passes, console_loglevel=4
keeps them off serial console). Task "strip instrumentation" deferred (not gating).
