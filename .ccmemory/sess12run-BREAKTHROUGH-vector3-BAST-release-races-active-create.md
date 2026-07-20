---
name: sess12run-BREAKTHROUGH-vector3-BAST-release-races-active-create
description: sess12(ccloop) BREAKTHROUGH vector-3 root PROVEN: dir BAST release-drain+EX-demote runs CONCURRENTLY with an active create (no ILOCK serialization) →…
metadata:
  type: project
---

## sess12 (ccloop) BREAKTHROUGH — vector-3 (intra-create single-dirent revert) ROOT PROVEN

### Decisive trace (build 40AC2A0C, dirwr=2, drc4_repro round 10, test1, lost = node1_f15.md5)
- 433.578685 P11-FLUSH-CLEANSKIP daddr=112 names=[node1_f7..f14]  (a dir RELEASE drain in progress)
- 433.578886 P16-RELEASE-UNDESTAGED daddr=112  (release path)
- 433.579289 / 433.579748 **P11-FLUSH-UNCACHED daddr=112 comm=kworker**  (release drain, block uncached, SKIPPED)
- 433.580905 **P11-DATALOG daddr=112 off=2136 name=[node1_f15.md5] comm=bash**  (the create writes the entry)
- 433.580913 P-CRNAME-DONE rval=0  (create succeeds)
- 433.580971 P11-POSTADD PRELOGF daddr=112 names=[node1_f7..f14...]  (durable_signal: 112 LACKS node1_f15.md5)
- node1_f15.md5 in ZERO PRELOGF lines clusterwide → durably lost.

### ROOT (PROVEN): the dir BAST RELEASE (kworker, drain + EX demote) runs CONCURRENTLY with the bash CREATE on the SAME dir, because the release path takes NO inode ILOCK
`mxfs_dir_data_durable` / `mxfs_dlm_dir_inode_durable` / `mxfs_dir_flush_data_blocks` operate on buffers directly (xfs_buf_incore + buffer lock) and do NOT acquire dp ILOCK — by design (the "ILOCK held across CAW poll" deadlock tension, CLAUDE.md). So while bash's create holds dp ILOCK_EXCL and is mid-transaction, a kworker BAST handler drains the dir and DEMOTES the dir DLM EX to a peer. The create's just-committed dirent (f15.md5 → daddr 112), added AFTER the kworker already snapshotted/uncached 112, is lost: the peer takes EX with 112 = the pre-f15.md5 image, and the create's entry never becomes durable/peer-visible. This is NOT a reload-under-ILOCK (impossible) — it's a CONCURRENT release+demote with no serialization against the active writer. Matches GPT-5.5's vector-3 prediction exactly ("a BAST during an active writer must DEFER, not demote").

### FIX (GPT design, concrete): serialize EX handoff against active dir modifies WITHOUT taking ILOCK (avoids the CAW-poll deadlock)
1. Per dir inode: a `writer_active` flag/atomic count. The create/rename/remove path sets it AFTER acquiring ILOCK_EXCL + dir EX and the modify_refresh, and clears it AFTER durable_signal (end of the modify section).
2. The dir BAST handler (bast_work_fn → mxfs_dlm_dir_inode_durable / the demote): if `writer_active`, set `revoke_pending` and RETURN WITHOUT demoting (do not drain+release mid-create).
3. end-of-modify: if `revoke_pending`, kick the deferred BAST (re-queue the drain+demote) so the peer is served promptly (avoid sess18 DLM rc=-110 timeout — the defer window is one create, ~µs, not unbounded).
CAUTION: must not deadlock — the create must not block on the peer while holding the deferred BAST (the AG→dir ABBA, CLAUDE.md sess58). The defer is non-blocking (flag only), so the create proceeds to commit, then releases. Verify the peer's EX acquire wait tolerates the brief defer.

### Status: vector-3 root PROVEN this session; fix NOT yet implemented. This is the DOMINANT dir_reuse failure mode (single-dirent loss). The sess12 write-side guards (dir_ex_write_guard, dir_sf_rebase) are backstops only. See [[sess12run-VECTOR3-precise-BAST-site-14430-defer-during-create]] [[sess12run-GPT-DESIGN-tenure-rebase-dir-coherency-unified]] [[sess12run-RESULT-vector1-2-fixes-sound-but-inert-vector3-dominant]].
</body>
