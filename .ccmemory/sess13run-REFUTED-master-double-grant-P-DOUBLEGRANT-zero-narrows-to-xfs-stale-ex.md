---
name: sess13run-REFUTED-master-double-grant-P-DOUBLEGRANT-zero-narrows-to-xfs-stale-ex
description: sess13(ccloop) REFUTED master-side double-grant: always-on P-DOUBLEGRANT=0 + P-STALEMASTER-GRANT=0 for ino 131 across all nodes. DLM master never con…
metadata:
  type: project
---

## sess13 (ccloop) — master double-grant REFUTED by always-on detectors

### Evidence (last dir_reuse 4/tcp run, build D7F1FC0B, ino 131)
- `P-DOUBLEGRANT` (dlm.c dg_grant_ex: fires when a DIFFERENT node holds an ACTIVE EX in the master's shadow table at a new EX grant) = **0** on all 4 nodes.
- `P-STALEMASTER-GRANT` (mastership-flap probe) = **0** on all 4 nodes.
⇒ The DLM master does NOT grant dir-EX to two nodes concurrently, and mastership does not flip. promote_waiters' lock_compat gate holds: a waiter EX is granted only after the prior holder's lock leaves the master table (its RELEASE processed).

### So the residual 1/400 durable double-PLACEMENT is NOT a master double-grant. Remaining candidates:
1. **XFS-layer cached i_dlm_mode==EX is STALE vs a real DLM handoff** (sess49 root, NOT master-visible): the master correctly single-grants, but a node's XFS-layer i_dlm_mode/i_dlm_state still says CACHED+EX after the DLM moved the grant (a BAST not yet processed / a fast-path serve that didn't re-check the grant), so its addname fast-paths onto a stale base. mxfs_v5_dlm_inode_held is a NO-OP on TCP (returns 1) so the XFS layer CANNOT verify it still holds EX before the RMW. NEXT: instrument the dir addname fast-path to compare XFS i_dlm_mode/cached_grant_gen against the DLM's CURRENT grant_gen for ino 131 at the moment of placement; if they diverge on the loser → CONFIRMED. Fix = on EVERY dir modify (incl cached-EX fast path) re-check mxfs_v5_dlm_inode_grant_gen vs i_dlm_cached_grant_gen (sess61 plan, the fields EXIST) and force a coherent re-read/slow-reacquire if advanced — i.e. make the cached-EX serve epoch-checked, not just the slow path.
2. Write-durability ordering (peer add not on platter at FUA-read) — less likely given the sess97 fence + H26 blkdev_issue_flush precede the unlock, but verify the H26 flush covers the loser's specific block before the release message.

### Candidate 1 is the strongest and matches sess49's "TCP stale cached-EX double-RMW, not converged" + sess61's never-fully-wired grant_gen fast-path check. The i_dlm_cached_grant_gen field exists (xfs_inode.h:138) — verify it is (a) set on every grant and (b) CHECKED on the dir-EX fast-path serve in mxfs_dlm_ilock_begin (~line 10712, the `ip->i_dlm_ex_holders++` cached fast-path). If the check is missing or only on slow-path, ADD it to the fast-path.
Build D7F1FC0B (off-by-default levers, non-regressing). Criterion NOT met. See [[sess13run-CONCLUSION-readside-buffer-fixes-exhausted-residual-is-write-placement]] [[sess61-THE-FIX-implement-sess10-grant-gen-faststale-check]] [[sess49-residual-tcp-doublegrant-dir-resurrection-complete-diagnosis]].</body>
</invoke>
