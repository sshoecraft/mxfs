---
name: sess31-STATUS-8tcp-residual-is-clean-single-dirent-loss-only
description: sess31 STATUS: 1/2/4 tcp = 100% PASS (IQN fix). 8/tcp passes 2/3 (runs A,B 17/17; run C failed ONLY on rare clean 799/800 single-dirent loss).
metadata:
  type: project
---

## sess31 STATUS after the duplicate-IQN infra fix [[sess31-BREAKTHROUGH-duplicate-iscsi-iqn-was-the-8node-flakiness]]

### Current standing (build 37A37B10, deployed)
- **1/tcp = 16/16 PASS** (dkms_install fixed by node /var/log cleanup — was ENOSPC).
- **2/tcp = 17/17 PASS** (full suite, clean).
- **4/tcp = 17/17 PASS** (full suite — was 13/17 cascade before the IQN fix).
- **8/tcp = 17/17 on runs A & B; run C = 14/17.** Run C's ONLY root failure was `dir_reuse_coherency` round 24 = the classic **clean single-dirent loss `readdir 799/800, lookup_fail=0`** (then it cascaded to fault_netpartition/tcp_dlm_scaling). No shutdown, no infra. This is the genuine sess20-30 dir-data lost-update — the SOLE remaining blocker.

### The residual (sole remaining bug for 100%)
The durable single-dirent loss in dir_reuse_coherency at 8 nodes. Rare (~1 per 3 full runs / ~1 per 70 dir_reuse-rounds). Mechanism PROVEN sess28 [[sess28-SMOKINGGUN-EXholder-destages-stale-inAIL-base-bgen0-mergeneeded]]: an EX-holder destages a stale in-AIL dir-DATA block (in_ail=1, bgen=0, incore_extra=1 disk_extra>=1) — our add A on a base missing peer's B → clobbers B. Root: at T1 release, A was NOT landed on disk (release-drain coverage gap), so the in_ail block survives to T2' reacquire where the acquire-evict can't invalidate it (clearing DONE on in-AIL corrupts) → xfsaild destages stale → loses B.

### REFUTED this session (do not retry)
- **`dir_write_merge=1`** (write-side 3-way graft): CAUSES a **bnobt double-free SHUTDOWN** (`ltbno+ltlen>bno` xfs_alloc.c:2254 → xfs_free_ag_extent) at ~round 7, plus leaf-hash lookup_fail=1. Strictly worse than default. Confirms the sess30 refutation via a harder symptom.

### Tooling added
- `tests/tcp/drc_repro_loop.sh [ITERS] [MODARGS]` — reboots 8 nodes (so MODARGS apply via fresh insmod — run.sh alone REUSES the mount and does NOT re-insmod), then loops 8/tcp dir_reuse_coherency until a fail round, DRC_STREAM on. NOTE: modargs are insmod-style (`dir_write_merge=1`, NO `mxfs.` prefix). steve cannot write /root, so the loop logs HIT to stdout (poll the log, not a /root marker). Launch with `setsid ... < /dev/null &` (plain nohup got reaped).

### Next
Capture a clean-loss with `dir_relverify=1` (enables P25-RELVERIFY-MISMATCH: incore!=disk at EX release) + DRC_STREAM to confirm whether T1 release leaves A in_ail-undestaged, then fix the release-drain coverage gap (land A before EX handoff = Invariant 1). The release fence is xfs_mxfs_dlm.c:7488 (mxfs_dir_data_durable gate → mxfs_dir_flush_data_blocks_relsafe).
</body>
