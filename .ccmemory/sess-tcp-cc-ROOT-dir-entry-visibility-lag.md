---
name: sess-tcp-cc-ROOT-dir-entry-visibility-lag
description: PROVEN: 2/tcp full-suite SOLE blocker = crash_consistency. Root is shared-DIR entry-visibility lag (test1 stat→ENOENT on node2's later-created .md5 d…
metadata:
  type: project
---

## STATE (build 30D3C28E, both nodes): `./run.sh 2 tcp` = 15 PASS / 1 FAIL.
SOLE failing test = **crash_consistency**. Reliably FAILS in the FULL suite (after ~11 prior
multi-node tests churn inodes); PASSES standalone and in 2-test (rsync_paired→cc) runs. So it is
CUMULATIVE-STATE dependent. tcp_dlm_scaling PASSED both recent full runs (the prior sessions'
double-grant obsession is NOT the current blocker; deprioritize it).

## PROVEN ROOT (RULE 4, forensics added to tests/suite/crash_consistency.sh — fires only on FAIL,
writes $MNT/.crash_consistency/.cc_forensic_r<R> + /dev/kmsg marker):
crash_consistency: each node writes 50 data files (oflag=sync) THEN 50 `.md5` sidecars (`>`redirect
+ one `sync`), barrier "cc_written", drop_caches, then EVERY node md5-verifies EVERY node's files.
FAIL line `node2_fNN(exp= got=<hash>)`: exp empty.
**Forensic at failure time:** `md5file ino= size= content=[]` — `stat -c%i` returns EMPTY = the
.md5 file is **ENOENT / not visible** on test1 (NOT empty content). The DATA file IS visible
(datafile ino=2635662 size=32768). Only node2's **later-created** .md5 dirents (f31..f50) missing;
f1..f30 visible. A 2nd drop_caches+reread on test1 STILL empty (~0.3s later). **Minutes later
(manual query) test1 sees all .md5 files perfectly (ino=2636864 size=33 [hash]) and node2 always
saw its own.** => TRANSIENT shared-DIRECTORY entry-visibility lag that resolves eventually.

## MECHANISM (strong hypothesis, confirm next): test1 + node2 both create into ONE shared dir
`.crash_consistency` (200 entries). They ping-pong the dir DLM EX during concurrent creates. node2
adds its .md5 entries LAST and still holds dir EX (per-inode lock caching — not released on
`sync`). test1's verify-loop `cat node2_fNN.md5` does a path lookup; xfs_lookup igets with
lock_flags=0 → test1 performs NO dir-DLM acquire → reads its STALE cached dir blocks (from when
test1 last held the dir) → misses node2's latest entries. node2's `sync` flushed its file data but
the shared dir's new dirents are not promptly visible to the peer (deferred to DLM-release drain /
LIO FUA-drop). Eventually node2 flushes (BAST from a later test / eviction) → test1 sees them.
This is the dir-block read-coherency family (sess83/87/88 DIR-BLOCK lost-update) + the sess127
"xfs_lookup igets lock_flags=0 → no inode-DLM acquire" gap, on TCP.

## NOT confirmed yet / to nail down:
- Is node2's dir block DURABLE on the LUN at read time (test1 stale-read) or NOT durable (node2
  sync didn't push the dir block)? Decisive. (No userspace dir-block FUA tool; need a kernel probe
  or a controlled experiment: does forcing a dir-DLM PR acquire / readdir on test1 restore prompt
  visibility?)
- Why f1..f30 visible but f31+ not: dir grew to block/leaf; test1 has SOME dir blocks fresh, the
  block holding the latest entries stale.

## FIX DIRECTION (next): make test1's shared-dir READ coherent — acquire dir-inode DLM PR (force
BAST→holder flush + fresh re-read) on multi-node dir lookup/readdir, OR ensure i_dlm_dir_gen is
advanced so xfs_da_read_buf (v0.4.7 gen-invalidation) re-reads stale dir blocks. CAUTION (sess38):
a per-lookup DLM/CAW poll (d_revalidate) previously caused barrier TIMEOUTS — must be cheap. Look
at xfs_lookup (xfs/xfs_inode.c), xfs_da_read_buf gen-inval (xfs/libxfs/xfs_da_btree.c),
i_dlm_dir_gen bump on dir DLM reload (xfs_mxfs_dlm.c). Validate: full `./run.sh 2 tcp` 16/16,
several times. Build/repro loop = full suite (~5min, reliable repro). Fallback build 30D3C28E.
See [[sess-tcp-cc-ROOT-dir-entry-visibility-lag]] supersedes the tcp_dlm_scaling focus in
[[sess-tcp-tcp-dlm-scaling-DOUBLE-GRANT-proven]].
