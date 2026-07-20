---
name: sess31-merge-gate-once-per-tenure-is-why-dir_merge-ineffective
description: sess31: dir_merge ineffective because it's ONCE-PER-TENURE (perf gate evicted_gen==dir_gen). Merge snapshot (P18 added=0) misses the peer add that la…
metadata:
  type: project
---

## sess31 — WHY dir_merge is ineffective (instrumented, RULE 4)

### Evidence
Ran the round-1 repro with `dir_merge=1 dir_force_block=0 dirwr=1` (enables P18-MERGE-TP + P-WMERGE). Result: **P18-MERGE-TP added=0 on all 8 nodes for the storm dir (ino=131)** — the union-merge re-added NOTHING. The run also hit a **DLM lock timeout shutdown** (`DLM inode lock unrecoverable: ino=131 mode=5 rc=-110`, mxfs_dlm_ilock_begin:12916) — the per-tenure full-dir FUA snapshot + dirwr overhead slowed BAST handling enough that a peer's PR-acquire timed out (the sess29 perf-doomed-merge failure).

### Root of dir_merge's ineffectiveness
`mxfs_dir_merge_peer_into_tp` (xfs_mxfs_dlm.c:5291) has a perf gate (~5331): returns early unless `dir_gen != evicted_gen`, and after a complete merge it ADVANCES evicted_gen=dir_gen → so it runs **ONCE PER TENURE** (first create after acquire), then every subsequent create THIS tenure skips it. P18 added=0 ⇒ at that one snapshot the merge's FUA read did NOT see the lost entry as missing (in-core already matched the disk image it read). So node1_f4.md5 became visible to this node's destage-relevant base AFTER the once-per-tenure merge snapshot. Re-running the merge per-create closes the window but → DLM timeout shutdown (perf). Classic correctness-vs-perf wall.

### Confirms the architectural conclusion
The merge MUST re-validate at the LAST possible point (the async destage / TOCTOU), not once-per-tenure at create. All create/read-time merges snapshot too early. See [[sess31-KEY-loss-is-async-destage-TOCTOU-create-and-read-merges-ineffective]].

### Untried, most-promising fix for next session
At the dir-DATA-block destage chokepoint (pal/linux/xfs_buf.c, where the writeprobe already computes disk_extra via FUA read): when disk_extra>0 (this write WOULD revert a peer add), DEFER the write (re-queue the buffer, do NOT ioend-success) and bounce to a worker that, holding the dir EX, runs the transactional union-merge (mxfs_dir_merge_peer_blocks) to fold the peer's entries into the in-core block(s); xfsaild then re-pushes the now-coherent block. Gate default-off. The hard parts: safely deferring the bio write without faking ioend, and igetting dp from the buffer owner ino in a writeback context. Risk: a bug here wedges ALL writeback — validate carefully against the round-1 repro.

### Standing: 1/2/4 tcp = 100%; 8/tcp = ~2/3 (this loss). Cluster clean default, build 37A37B10. CRITERIA NOT MET. [[sess31-HEAD-handoff]]
</body>
