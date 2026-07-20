---
name: sess16run-release-invalidate-REFUTED-points-to-DLM-grant-drain-ordering
description: sess16(ccloop) CRITICAL: dir_release_invalidate=1 (GPT part-1 drain-then-invalidate, forces next acquirer to COLD-READ durable image) ALSO FAILS at m…
metadata:
  type: project
---

## sess16 (ccloop) — release-invalidate REFUTED → the root is DLM serialization, not buffer coherency

### The decisive refutation
mht=50 + `dir_release_invalidate=1` (sess13run's "publish-durable-then-discard": after the synchronous release bwrite lands each dir block durable, xfs_buf_stale + clear XBF_DONE so the NEXT acquirer COLD-READS the coherent shared image — this IS GPT-5.5 design part 1, the "correct form" that addressed sess96's resurrection refutation): dir_reuse STILL FAILS 0/8, SAME loss (node1_f1, node5_f40).

### Complete refutation table (every buffer-coherency mechanism fails at mht=50)
| Mechanism | Layer | Result |
|---|---|---|
| force_coherent=1 | read: FUA re-read every block, no cache hit | FAIL |
| dir_postread_reread=1 | read: reliable grant-gen re-read before RMW | FAIL |
| b_mxfs_dir_epoch trigger (42178C17) | read: tenure-epoch re-read, override undestaged | FAIL |
| dir_release_fua_write=1 | write: release block to PLATTER (FUA write) | FAIL |
| dir_release_invalidate=1 | release: drain-then-invalidate → next acquirer cold-reads | FAIL |

### What this PROVES (narrows the root massively)
The clobbering node writes block0 (daddr=120) from a base MISSING node1_f1, and NO amount of forcing fresh reads — even forcing the next acquirer to COLD-READ the durable on-disk image after a drain+invalidate — prevents it. So the writer is NOT using a stale CACHED buffer that better invalidation would fix. Either:
1. **Overlapping EX (broken serialization)**: two nodes hold/use EX on ino=131 in overlapping windows → both RMW block0 from their own concurrently-current bases → one clobbers. The master's lock_compat[][] check (dlm/dlm.c:617) should prevent two GRANTED EX, BUT the grant→drain→regrant ordering may release the grant to the peer BEFORE the prior holder's drain+invalidate completes, OR a direct PR→EX upgrade / REAFFIRM path (dlm/dlm.c:512-527, sess35) grants without serializing against the prior holder's in-flight modify. [[sess51-ROOT-tcp-dlm-scaling-is-symmetric-PR-EX-dir-upgrade-livelock]] documents the PR→EX upgrade path on this exact dir.
2. **Conversion/addname logic drop**: shortform↔block↔leaf conversion or xfs_dir2_leaf_addname drops f1 even from a correct base. (Less likely — f1 IS written durably 286× by owner then clobbered, per [[sess16run-RESOLVED-f1-written-then-clobbered-on-hot-block0]].)

### NEXT SESSION — decisive experiment (do FIRST, before any more buffer fixes)
Instrument OVERLAPPING EX on ino=131: at each dir-block modify/write, log (node, i_dlm_mode, i_dlm_ex_acquire_ns, grant_gen). Cross-node-merge: do two nodes' EX tenures on ino=131 OVERLAP in wall time? OR add a master-side detector in dlm/dlm.c promote_waiters / the direct-grant paths: when granting EX to node X, assert no other node has a GRANTED conflicting mode that hasn't completed its BAST-release+drain. If overlap exists → the fix is in dlm/ (grant ordering: do NOT grant EX to a peer until the prior holder's bast_process drain+invalidate fully completes AND acks). This is GPT design part 2's REVOKING fence applied at the GRANT/protocol layer, not the buffer layer. STOP testing read-side/buffer params — all 5 are refuted.

### Build state
42178C17 (= baseline + inert P32F fence + inert b_mxfs_dir_epoch trigger, both gated off at default). Cluster left failed (will reboot next run). Default-config (mht=300) dir_reuse PASS unregressed (all new logic gated off). Criterion NOT met — marker not written.</body>
