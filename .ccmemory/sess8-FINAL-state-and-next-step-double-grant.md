---
name: sess8-FINAL-state-and-next-step-double-grant
description: sess8 FINAL: 2/tcp reliably 15/16 (rename guard killed shutdown cascade, build DA703FD6 deployed). Remaining = double-grant lost-update; next = lock-…
metadata:
  type: project
---

## CURRENT STATE (head sess8). DEPLOYED build = DA703FD6DF02BDDC48491FD on BOTH nodes.
2/tcp = reliably 15/16 with NO shutdown cascade. The single failure ROTATES across the
concurrent-shared-dir tests {dlm_fairness, tcp_dlm_scaling, crash_consistency, cache_coherency},
always the SAME root (shortform-dir lost-update), always BENIGN (`shared dir drained got=1` /
cc `got=98`, both nodes stay mounted). Marker NOT written (criterion = 16/16 not met).

## KEEP (build DA703FD6) — two fixes this session:
1. **xfs_rename pre-dirty source revalidate** (xfs_inode.c ~3869, after the
   `mxfs_dlm_dir_modify_refresh` calls): mirrors the xfs_remove guard (~3481). ELIMINATED the
   `xfs_trans_cancel at xfs_rename+0x90b — Corruption of in-memory data` FS-SHUTDOWN that
   CASCADE-failed every test after dlm_fairness (made the suite look like 6/16). Now the source-gone
   rename degrades to a clean -ENOENT (`RENAME-REVALIDATE-MISS`). THE big win. See
   [[sess8-rename-guard-fix-and-shortform-lostupdate-root]].
2. **P-SFREL probe** (xfs_mxfs_dlm.c bast_process release path, ~line 3051, dirwr/instr-gated):
   plain-bio reads the inode cluster back at release and logs shortform count+names. Diagnostic only.

## REVERTED this session (do NOT redo): removing the 1000ms throttle on the P106/P108 stale-EX
slot-verify in mxfs_dlm_ilock_begin (~line 6289). Tested: **P108-REACQUIRE fired ZERO times** at a
lost-update → the holder NEVER lost its on-disk slot → the lost-update is NOT the lost-slot stale-EX
condition. Throttle-removal only added per-acquire slot-read latency (perturbation/masking), so it
was reverted. (~1/6→~1/20 was timing noise, not a fix.)

## PROVEN DIAGNOSIS of the remaining blocker (RULE 4, dirwr=1 repro ~1/16 standalone via
`./run.sh 2 tcp dlm_fairness` loop, reboot first):
- The shared test dir is SHORTFORM (dirents inline in the dinode; ALL dir-DATA-block coherency
  machinery — modify_refresh evict, durable_signal, release-drain dir-flush — is a NO-OP for it).
- **Write durability is CORRECT**: every P-SFREL shows the releasing node's entries DURABLE on the
  LUN before release (invariant #1 holds: bast_process does log_force(SYNC) + wait pin==0 +
  log_force + mxfs_ail_drain_inode_sync + blkdev_issue_flush before unlock).
- **NOT lost-slot stale-EX** (P108 never fires).
- THEREFORE: a node RMWs the shortform dir from a STALE in-core fork that lacks a peer's
  ALREADY-DURABLE entry, then commits+releases durably → clobbers it. Since EX is supposed to
  serialize and reads use the write-cache coherence point, the only explanation is a **DOUBLE-GRANT**
  (both nodes hold a valid EX concurrently — the proven tcp_dlm_scaling heisenbug,
  [[sess-tcp-tcp-dlm-scaling-DOUBLE-GRANT-proven]]) that the gen-token fix
  ([[sess-tcp-DLM-double-grant-FIXED-gen-token]]) reduced but did NOT fully close, OR a transient
  read-staleness at the drain-check readdir. (Some leftovers durable {n1_r1,n1_r4} both-nodes-agree;
  some transient = empty after run. Both observed.)

## NEXT STEP (fresh session, RULE 4): the double-grant is a HEISENBUG — printk/per-op tracing
(mxfs.lockwr=1) SUPPRESSES it (timing). Build a **lock-free per-CPU event ring** in dlm/dlm.c that
records {ts, node, resource, op=GRANT/RELEASE/REAFFIRM/REMOVE, gen, mode} with NO printk in the hot
path, dumped ONLY when a leftover/lost-update is detected (or at unmount). Correlate BOTH nodes'
rings (realns timestamps, both UTC) to catch the window where two nodes' EX-hold intervals overlap on
the dir resource. Then fix the protocol path that lets a holder's master entry go absent / a second
EX be granted. Ruled-out paths: purge_stale_for_resource (DEAD code, no callers);
process_remote_release stale-gen guard (correct); request-path re-affirm (correct). Suspect: the
-ETIMEDOUT 6s retry race (MXFS_LOCK_ACQUIRE_WAIT_MS, dlm.c ~897/1208) and/or membership purge_node
(dlm.c 1627) removing a live holder. Fallback builds: E143DF7B (rename guard, no probe), E8BF16B2
(pre-rename-guard, 15/16 WITH shutdown cascade — worse), 404BC55C (double-grant gen-token).
</body>
