---
name: sess13run-three-residual-faces-triage-705FDC6E
description: sess13 triage: fence 0/10 on FIX-C; residuals = ds got=0 (own dirent swallow), fairness EUCLEAN (chunk over stale platter, init not destaged), drc sw…
metadata:
  type: project
---

# sess13 — FIX-C holds; three residual faces triaged (build 705FDC6E)

## FIX-C status (entry-locks-before-AG-grants)
Fence/netpartition/tds family: **0 failures in 10 full-suite 4/tcp iters**
(pre-FIX-C rate ~1-in-4). P13-CLEANRETRY=0, P12-HOLDERTASK=0, no -110s.
Side effect: P71-UNDERFLOW prints (125/run, test-node-local, benign-by-design:
`xfs_lock_two_inodes` in-AIL path nowait-locks the FILE child without DLM
begin; END prints. More frequent because rm's reach trans_alloc_dir faster,
dir stays in-AIL more).

## Residual face profile (~10 iters): drc 2/10, dlm_scaling 2/10, dlm_fairness 1/10
All three = shared-dir concurrent-modify staleness family:

1. **dlm_scaling got=0**: node's OWN subdir dirent vanishes from shared parent
   `.dlm_scaling` right after the 4-way racing `mkdir -p` (3 nodes EEXIST-race
   the parent + 4 child mkdirs in fresh shortform parent). ZERO P12-IGETMISS
   in latest hit → NOT an iget miss; the DIRENT is gone from the parent view
   (stale-base RMW swallow). Instrumented dlm_scaling.sh: POSTMKDIR-INVISIBLE
   + FIRSTFAIL probes + parent dirdump at first fail → /root/drc_blkdump_dsc_*.

2. **dlm_fairness EUCLEAN** (run_dlm_fairness_20260704T062706Z): node2 first
   create in shared dir → -117. Sequence: (a) 06:28:27 dinode-verify fail ino
   18874496 (=node2's mkdir target), P-SFV disk_differs=0, RECOVERED via
   reload (IOPS-REWIRE → dir 0755); (b) 06:28:41 xfs_inode_buf_verify EUCLEAN
   ino 8394176 (".dlm_fairness" per root lookup) daddr 0x7fd860 — the cluster
   read returns an **XDB3 dir data block** (entries d1,d10 = dead
   rsync_paired/soak dir). Diagnosis: fresh inode CHUNK allocated over
   freed dir blocks; the chunk-INIT write never destaged (fresh cluster bufs
   queue on pag_mxfs_alloc_buflist for Phase-2 AG-release drain) but the
   .dlm_fairness DIRENT already published in root → peer cold-iget reads the
   stale platter → EUCLEAN. ALSO: two inos for one name (18874496 on node2 vs
   8394176 durable) = the mkdir -p race double-created .dlm_fairness (root-dir
   swallow, same family as #1).

3. **drc readdir-miss** (2 hits): all-4-nodes-agree readdir=394/400 or 397/400,
   lookup_fail=0, missing = f1(/f2) of nodes 2,3,4 (first REMOTE adds).
   = sess12-r7 "unused/prior-entry header swallowed followers" walk-vs-lookup
   divergence. Standalone drc (3×) + ds+drc pair (1×) PASS — needs mid-suite
   state. Forensics kept dying: bins in /root wiped by VM recycle + journald
   rotates in ~85s under P71 firehose.

## Harness fixes landed (kernel UNCHANGED = 705FDC6E)
- run.sh FAIL capture: pulls /root/drc_blkdump_* (tar|base64 over ssh_node).
- drc script: dmesg tail → $drc_bd/dmesg_at_rdmiss.txt at RDMISS.
- dlm_scaling.sh: mkdir-rc + visibility + FIRSTFAIL parent-dump probes.
- run.sh prep: journald RuntimeMaxUse=400M + RateLimit off on every node
  (fixes the 85s window; full-suite journal now survives).

## Next
- Loop `timeout 1100 bash tests/suite_iter.sh 4 tcp` until a face fires WITH
  full journal + bins; then: for fairness face — trace who allocated the chunk,
  whether init was queued-not-drained when dirent published; for ds face —
  parent block dump shows the swallow; fix candidate = publish-order (child
  cluster durable before dirent visible) and/or shortform-parent RMW epoch.
- Then FIX + ladder ×6-10; then 8/tcp, 2/tcp, 1/tcp on final build.
