---
name: sess-tcp-cache-coherency-flaky
description: 2-node TCP cache_coherency PASSES sometimes (201/201 checks, 23s) but is FLAKY: across runs saw PASS/PASS, HANG(90s), FAIL+PASS(87s slow), FAIL+FAIL(…
metadata:
  type: project
---

## Build B77AD901 — 5 fixes land cache_coherency in the PASS zone but FLAKY
See [[sess-tcp-2node-three-root-fixes]] (3 fixes) + [[sess-tcp-progress-subtests-123-pass]]
(atime-EX skip = fix 4). Fix 5 below. The crash/wedge/EFSCORRUPTED blockers are GONE.

## Reliability data (warm mount, manual 2-node runs, COORD_TIMEOUT=30-40)
- single run: test1 PASS (201/201 checks) test2 PASS (200/200) — 23s. ALL 4 subtests pass.
- iter1: both HANG (90s timeout, no RESULT) — but NO FS D-state when checked post-kill.
- iter2: test1 FAIL test2 PASS — 87s (SLOW, near barrier timeout).
- iter3: test1 FAIL test2 FAIL — 23s (FAST coherency miss, not a hang).
=> genuinely FLAKY + DEGRADES across repeated runs (1st warm run clean, later ones fail).

## Three intertwined remaining problems
1. **Slowness**: cross-node ops are slow (P-TCP-VERIFY-COORD coordinated reload = DLM
   round-trip + force-peer-flush on first read of each peer-written inode; ~slow enough that
   a 4-subtest test that runs in 23s when fast drifts to 87s, desyncing the MQTT barriers
   at COORD_TIMEOUT). RULE 0: slowness IS a fail.
2. **Intermittent coherency miss**: occasionally a peer's write/dirent not visible (asymmetric:
   iter2 test1 FAIL while test2 PASS). Need a captured fast-fail trace to localize the subtest.
3. **State degradation across runs**: each repeated run starts worse. Inter-run `rm -rf` of the
   cc dir may wedge the unlink path (earlier saw `rm` D-state in vfs_unlink). run.sh avoids
   inter-run rm (fresh mkfs each) but STILL failed earlier — so the fresh-mount single->multi
   transition timing is also implicated.

## NEXT — highest leverage
- Attack SLOWNESS first (it causes the desync cascade): make the CREATOR push the new inode
  cluster durable+visible at create time (cheap on write-through LIO) so readers DON'T need
  the per-read P-TCP-VERIFY-COORD round-trip. That should make reads fast AND prompt, shrinking
  both the slowness and the intermittent-miss window. Look at xfs_create deferred-publish path
  (xfs/xfs_inode.c ~L1593-1660, m_mxfs_unpub_list, mxfs_dlm_dir_durable_signal) and whether a
  synchronous new-inode-cluster flush on multi-node create is cheap+correct here.
- Get a captured FAST-FAIL bash -x trace (tr*.log in /src/mxfs/.testlogs, NFS-visible) to name
  the exact first failing check.
- The criterion (run.sh -> criteria.json -> showstat 2 tcp) needs RELIABLE pass, not 1-in-N.

## Test method that works for observation
Manual 2-node launch with logs to /src/mxfs/.testlogs/ (NFS-visible from both clyde and the
isolated bg-task /tmp). `rm -rf /mnt/shared/.cache_coherency; sync` between runs. PS4 with
timestamps for per-op timing. Background Bash tasks have ISOLATED /tmp — write logs to NFS.
</body>
