---
name: sess54-ROOT-coresident-cluster-flush-stale-buffer-resurrection
description: sess54 PROVEN ROOT of tcp_dlm_scaling/dlm_fairness durable dirent leak: cluster-granular iflush + per-inode EX authority mismatch. NOT the merge. Bui…
metadata:
  type: project
---

## sess54 — PROVEN ROOT (RULE 4, instrumented) of the durable dirent leak. Criterion (2/tcp 17/17) NOT met. Build 99A4E4905 carries fixes, UNTESTED at relay.

### THE LEAK (reproduced this session, PLAIN full suite ~1/5 fail)
`tcp_dlm_scaling`/`dlm_fairness`: node does create→mv→rm of `n${R}_r${i}` in ONE shared dir; node1 asserts dir empty at end. FAILS: a leftover dirent (e.g. `n2_r55`, `n2_r57.done`) survives ON DISK, seen by BOTH nodes, survives drop_caches both = durable on LUN. Always one node's OWN removal (by rm or mv-source) lost. The OTHER 16 tests pass; leak hits the LAST hot-dir test (tcp_dlm_scaling, run 17th).

### RULED OUT: the 3-way SF merge. With sfm_dbg=1, **P-SFM-READD=0 P-SFMERGE=0** on both nodes during the failure. The sess53 EX-gate+clean-adopt DID suppress merges. The residual is NOT merge resurrection.

### PROVEN ROOT (captured kernel stack + markers): **cluster-granular flush vs per-inode EX authority MISMATCH.**
`mxfs_inode_cluster_durable(dp)` → `xfs_iflush_cluster(bp)` flushes the WHOLE 4KB inode cluster buffer (ALL co-resident dirty inodes), then `xfs_bwrite` writes the whole buffer. The P119 guard (xfs_inode.c ~4636, sess119 Gemini) makes a non-EX dirty inode `error=0; goto flush_out` = marks it CLEAN without copying in-core → the cached buffer's STALE bytes (pre-removal) get written back → durable RESURRECTION. Captured: `P119-NONEX-FLUSH-SKIP ino=8390722 i_dlm_mode=3(PR) incore_mode=disk_mode=040755 incore_gen==disk_gen exh=0 prh=0 in_ail=1 comm=rm`, stack `xfs_iflush←xfs_iflush_cluster←mxfs_inode_cluster_durable←mxfs_dlm_dir_inode_durable←xfs_remove`. The discarded ino (8390722) is a LIVE same-incarnation dir and is a CO-RESIDENT of the dir being flushed (≠ the dir whose op ran) — so a per-op fix on the target dir cannot fix it. GPT-5.5 (RULE-5 consult ON FILE, see below) confirmed: authority granularity (per-inode EX) ≠ write granularity (4KB cluster) is the architectural root.

### CONSTRAINT: xfs_iflush MUST return 0. `xfs_iflush_cluster`: `error=xfs_iflush(); if(error) break;` → `xfs_force_shutdown(CORRUPT_INCORE)`. So a guard in xfs_iflush can only mark-clean(discard) or flush(write); cannot "leave dirty / -EAGAIN".

### FIXES IN BUILD 99A4E4905 (all KEEP unless disproven; UNTESTED at relay):
1. **mxfs_dlm_dir_hold_ex()** (xfs_mxfs_dlm.c, new EXPORT) + wired into **xfs_remove** + **xfs_rename**: bump an extra ex_holder while still holding ILOCK_EXCL so bast_process (needs holders==0) can't demote during the ILOCK-dropped durable flush → keeps i_dlm_mode==EX so P119 doesn't discard the OP'S OWN dir. VERIFIED PARTIAL: P119 comm=rm 3→0, comm=mv 2→1, leftover got=2→1. Helps the target dir; does NOT fix co-residents.
2. **Localized fresh-RMW** in mxfs_inode_cluster_durable (xfs_mxfs_dlm.c ~1697): SCSI-FUA re-read the cluster into r_bp->b_addr BEFORE xfs_iflush_cluster (guarded: multi-node, skip XFS_BLI_INODE_ALLOC_BUF). So co-resident inodes written back carry CURRENT platter image, not stale cached → no resurrection. iflush_cluster re-overlays the authoritative (dirty+EX) inodes so our own change isn't lost. THIS is the intended co-resident fix. UNTESTED.

### REVERTED (DEAD END — caused worse failure): the "leave-dirty in xfs_iflush_cluster" co-resident skip (P54-CORESIDENT-LEAVE-DIRTY). It WEDGED the AIL: left ino 25700290 dirty 50×, never re-acquired EX → **P113-DRAIN-WEDGE** (stuck in_ail forever) → suite timeout 13/17. Confirms GPT's discard-vs-wedge warning: never leave a non-EX dirty inode dirty without a flush mechanism.

### ALSO FOUND: **SLOWNESS root = dir_reuse_coherency takes 285s** (per-test timing: everything else 10-30s; dir_reuse +173s→+458s). The full suite is ~545s almost entirely due to dir_reuse. This is the sess34 6s-dir-handoff (MXFS_LOCK_ACQUIRE_WAIT_MS=6000 deferred-BAST) slowness — separate RULE-0 blocker; fix the deferred-dir-BAST-honor so handoffs aren't ~6s.

### NEXT SESSION:
1. TEST build 99A4E4905: reboot clean, `MXFS_EXTRA_MODARGS="sfm_dbg=1" ./run.sh 2 tcp` (full suite ~545s, run via direct `> log` redirect — NOT awk-piped, awk buffers & loses output on SIGTERM). Check tcp_dlm_scaling/dlm_fairness pass + P119 count + NO P113-DRAIN-WEDGE + NO new shutdown. Repeat 3-5× clean reboots for reliability.
2. If fresh-RMW fixed it → also fix dir_reuse 285s slowness (sess34 deferred-BAST) → then 17/17 reliably → marker.
3. If co-resident leak persists → GPT's full fix: ICLUSTER DLM lock + fresh-RMW (read disk under cluster-write lock, overlay ONLY authoritative inodes) OR target-only sub-buffer 512B write of just dp's dinode (if isize>=512, one inode/sector). See [[sess54-gpt-coresident-cluster-flush-design]].
Repro harness: tests/tcp/fg_one_run.sh (reboots+full suite). Diagnostics in build: P119 has exh/prh/in_ail + one-shot dump_stack for dirs; P-ICD/P-SFREL-VERIFY have exh/prh/state (gated dirwr/instr). Related: [[sess53-FINAL-residual-is-release-durability-race-with-churn]] (superseded: it's NOT a release-side churn race, it's cluster co-flush of stale buffer).
