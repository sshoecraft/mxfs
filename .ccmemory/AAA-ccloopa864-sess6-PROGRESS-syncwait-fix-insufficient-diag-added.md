---
name: AAA-ccloopa864-sess6-PROGRESS-syncwait-fix-insufficient-diag-added
description: sess6 PROGRESS: v0.10.52 sync_wait completion-routing fix did NOT fix wedge#2a (override fired 0x; bmbt-scan sync bwrite still hangs). Diag added in…
metadata:
  type: project
---

## sess6 (ccloop a864) PROGRESS — wedge#2a fix attempt #1 insufficient; diagnostic added

### What happened
- **Baseline (0349484E)**: dir_reuse@32/caw wedged at **r3** — owner_scan `xfs_dir3_leafn` sync bwrite lost-wakeup (P-IOWAIT-STUCK flags=ASYNC|DONE done=0). Confirmed FAIL.
- **Fix attempt #1 (v0.10.52 / 7647E2C4)**: added `b_mxfs_sync_wait` (snapshot `!(XBF_ASYNC)` at xfs_buf_submit) + routed xfs_buf_ioend(1698)/xfs_buf_bio_end_io(1829) on it (complete instead of relse/queue_work when ASYNC spuriously set on a sync submit). **RESULT: FAILED — wedged at r1** (~3 min, FASTER repro). `P-SYNCWAIT-OVERRIDE` fired **0×**. Stuck now on `ops=xfs_bmbt` via `mxfs_dir_bmbt_scan → xfs_bwrite → xfs_buf_iowait` (durable_signal, same class, different arm). Same P-IOWAIT-STUCK signature: flags=0x30 (ASYNC|DONE), done=0, wr_counted=0, dir_inflight=0, rd=0 wr=0, comm=rm.

### What the override=0 rules out (RULE 4)
The completion is NOT reaching my routers with (XBF_ASYNC && b_mxfs_sync_wait). `__xfs_buf_ioend` clears XBF_READ|WRITE + sets XBF_DONE (matches stuck flags) and returns true — so a completion DID run, then the router saw XBF_ASYNC and took the **relse/async branch with sync_wait=FALSE** (else my override would have fired). So **sync_wait was FALSE at the completion** despite rm's xfs_bwrite clearing ASYNC at submit (should be true).

### Leading hypothesis (unconfirmed): b_hold-window async steal
owner_scan (xfs_mxfs_dlm.c:1102) + bmbt_scan (same pattern, ~L821) hold candidate buffers by **refcount (b_hold++) during the RCU walk, NOT b_sema**; only later take b_sema (xfs_buf_lock) + recheck + xfs_bwrite. In the b_hold-only window xfsaild (delwri_submit_nowait, xfs_buf.c:8097 sets XBF_ASYNC → sync_wait=FALSE) can async-submit the same buffer. If the completion routing / b_iowait pairing gets crossed there, rm's later sync bwrite waits on a b_iowait an async completion already consumed via relse. NOT yet proven.

### Diagnostic build v0.10.53 (in flight at handoff)
Added to P-IOWAIT-STUCK probe (xfs_buf.c:5020): `sync_wait=%d ioend_seen=%u relse_seen=%u`. New u8 fields b_mxfs_ioend_seen (completions run) + b_mxfs_relse_seen (completions that took the async relse branch), reset at xfs_buf_submit, incremented in xfs_buf_ioend + xfs_buf_bio_end_io. **NEXT: rerun dir_reuse@32/caw, grep P-IOWAIT-STUCK on the stuck rm node. Decode: sync_wait=0 ⇒ async-steal confirmed (fix at the b_hold window OR force sync_wait); ioend_seen=0 ⇒ NO completion ran (write bio never completed — different bug); relse_seen>0 ⇒ wrongful async-relse of the sync buffer confirmed.** Then apply the exact fix.

### Repro is FAST now (r1, ~3 min) — cheap to iterate. Test cmd: `MXFS_DEV=/dev/mapper/mpatha ./run.sh 32 caw dir_reuse_coherency` (nohup, timeout 4600). Prep re-mkfs's + power-cycles all 32, asserts srcversion. The sync_wait routing fix (v0.10.52) is KEPT (correct for the ASYNC-flip case even if not this wedge; inert here).
</body>
