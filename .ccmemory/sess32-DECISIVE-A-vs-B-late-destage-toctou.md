---
name: sess32-DECISIVE-A-vs-B-late-destage-toctou
description: sess32 CONFIRMED on losing iter: P-POSTRMW stale-base=0 on all 8 nodes while P-WMERGE fires 3-6x. RMW base always fresh; block goes stale post-releas…
metadata:
  type: project
---

## sess32 — CONFIRMED: the loss is the async-destage-AFTER-RELEASE TOCTOU (not a stale RMW base)

### Decisive evidence (build 6056E587, dir_postrmw_probe=1, on a LOSING iter: round 22 readdir 799/800 all 8 nodes)
- **P-POSTRMW STALE-RMW-BASE = 0 on ALL 8 nodes** (zero events the whole iter). The in-core dir block is ALWAYS a SUPERSET of disk right after our addname (disk_extra=0 post-RMW) → our RMW base is NEVER stale.
- **P-WMERGE MERGE-NEEDED = 3-6 per node** at the later bio destage (disk_extra>0 AND incore_extra>0).
=> The block is CORRECT when built; it goes stale AFTER we release EX, and xfsaild re-flushes the now-stale b_addr → reverts a peer's add. Mutual: incore_extra>0 too (our add reverted by the peer's flush), so two nodes' late re-flushes ping-pong and whichever flushes last wins; the other's dirent is the durable loss.

### What this RULES OUT (do not pursue)
- Read-side / acquire-side staleness refresh (base already fresh at RMW — refresh is a no-op for this bug). 
- EX-side epoch reval (sess32: made it 798 via keep-guard bypass). 
- create-time reconcile / dir_merge (base already a superset). 
- ALL param tuning (full proven config still loses). 
- destage byte-graft (bnobt corruption).

### THE FIX (write/release side — GPT-5.5 ×2)
xfs_bwrite at EX release does NOT retire the buffer-log-item from the AIL; the BLI lingers (dirty=0,in_ail=1). xfsaild later re-flushes that buffer AFTER a peer superseded the on-disk block → revert. FIX: at EX RELEASE (publish-before-notify path, xfs_mxfs_dlm.c — search mxfs_dlm_dir_durable_signal / P97 / publish-before-notify), after log_force+bwrite+flush, PUSH+WAIT the AIL until every dir data/leaf/free BLI for the inode has LEFT the AIL (retired), THEN DLM unlock. So no stale dir buffer can be re-flushed post-release. DEADLOCK CAUTION (RULE 2): push AIL NOT holding buffer locks / not in txn / not holding ILOCK; drain local ops first; use targeted per-buffer wait or xfs_ail_push_all_sync. Gate default-off; validate then default.
ALT (cheaper, riskier): at the xfsaild dir-DATA write chokepoint, suppress a re-flush when the buffer is NOT pinned/dirty by an ACTIVE local txn (a pure post-release reflush) and disk diverged — but must re-read after to not strand our own un-durable add; the release-retire is cleaner.

### Probe build 6056E587 (dir_postrmw_probe default-off, keeper-safe). Cluster: reboot to clear. CRITERIA NOT MET. [[sess32-HEAD-handoff]] [[sess32-DECISIVE-A-vs-B-late-destage-toctou]]
</body>
