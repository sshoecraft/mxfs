---
name: sess85_lessons
description: "sess85 (ccloop, 2026-06-04) — cache_coherency: cross_visibility lost-update FIXED (was ~0/5, now 4/5 all-files-visible; the 1 fail = 124s barrier-latency timeout, NOT a lost dirent). PROVEN the cross_visibility loss = LAST committer's shortform dirent reverted (test4 P-DIRFLUSH count=4 own=1 → count=3 own=0). Key infra: /mnt/mxfs-src NFS mount drops off test1 after reboot (sess81) → node1 rc=127 'mxfs_test.sh: No such file' → node1 never participates, contaminating the result; ALWAYS re-mount on ALL nodes before runs. Criterion still FAIL passed=1 failed=3 (rename 28 misses fast; unlink 1-21 misses+140s; cross_write_read 1 miss+244s). Merge_dirs DLM/count skips are INERT (detectors fire 0×) — merge is NOT the revert path. Build 7C44AF11 KEEP (no regression)."
metadata:
  node_type: memory
  type: project
  originSessionId: 29df431e-relay
---

# sess85 lessons (ccloop run 29df431e, 2026-06-04)

## HEADLINE: cross_visibility shortform lost-update FIXED (4/5, was ~0/5). Criterion still FAIL (3 of 4 subtests).

## CRITICAL INFRA (cost me 2 wasted runs — fix FIRST every session)
`/mnt/mxfs-src` (NFS export `192.168.120.1:/src/mxfs`, holds `tests/mxfs_test.sh`)
**drops off test1 after a reboot/reset** (test2/3/4 keep it). Symptom: node1 rc=127
`bash: /mnt/mxfs-src/tests/mxfs_test.sh: No such file or directory` → node1 NEVER
runs the test → node1.txt "lost" is a FALSE POSITIVE (node1 never created it) and
peers fail seeing it. ALWAYS, after every reset4.sh, run on ALL nodes:
`mountpoint -q /mnt/mxfs-src || mount -t nfs4 192.168.120.1:/src/mxfs /mnt/mxfs-src -o rw,hard,proto=tcp,timeo=600`
The cross-node realns-sorted P-SFDIR timeline is the tool that exposed this (node1
events were 125s adrift = it stalled on the missing harness, not a real RMW).

## VM HOST: test1-4 run under libvirt `qemu:///system` ON THIS HOST (clyde).
`virsh list` (default URI) shows all "shut off" — WRONG URI. Use
`virsh -c qemu:///system list` → test1-4 running (ids 63-66). To recover a hung
node (network-dead but "running" = kernel hang): `virsh -c qemu:///system destroy
testN; sleep 3; virsh -c qemu:///system start testN`; boots in ~10s. Serial console
is a pty (NOT logged to file) so past panic output is unrecoverable — can't post-mortem
a hang from the log. test2 hung once during a reset this session (pre-existing teardown
flakiness, NOT proven to be my change — xfs_iget(INCORE,lock_flags=0) is deadlock-safe:
IRECLAIMABLE→skip L954, live→igrab+spinlocks only, no ILOCK/buffer lock).

## PROVEN cross_visibility mechanism (RULE-4, full cross-node P-SFDIR/P-DIRFLUSH/P-CRNAME timeline)
The shared dir (e.g. ino=6291585) is SHORTFORM (dirents inline in dinode). Clean RMW
chain: node3 adds node3.txt(cnt1)→node1 adds(cnt2)→node2 adds(cnt3)→**test4 (LAST)
adds node4.txt → P-DIRFLUSH count=4 own=1** (its OWN iflush writes cnt=4 to the cluster
buffer + bio). Then **test4 P-DIRFLUSH count=3 own=0** (a CO-RESIDENT child inode flush
re-writes the SAME cluster buffer, but the dir slot is back to cnt=3) → on-disk dir
REVERTS to cnt=3 → node4.txt durably lost from ALL nodes. `own` = P-DIRFLUSH flushing-mask
(own=1: this node iflushing the dir itself; own=0: dir is a foreign co-resident slot in a
cluster written for some other inode). See xfs_inode_buf.c::mxfs_inode_buf_write_dirlog.

## REVERT PATH IS *NOT* merge_dirs (ruled out this session)
`mxfs_iflush_cluster_merge_dirs` (xfs_inode.c ~L3320, sess61) FUA-reads the on-disk
cluster + overlays FOREIGN dir slots (disk-authoritative-when-NL). HYPOTHESIS: it overlays
the dir slot with stale platter cnt=3, clobbering buffer cnt=4. I added TWO guards:
(1) skip overlay if we hold the inode non-NL (P-CLMERGE-SKIP-HELD); (2) skip if buffer
LOCAL-dir cnt > disk cnt (P-CLMERGE-DIRAHEAD). **BOTH fire 0× even in failing+passing
runs** → merge is NOT writing the cnt=3 dir slot. So the buffer's dir slot becomes cnt=3
by ANOTHER path: most likely the dir cluster buffer is INVALIDATED (XBF_DONE cleared by
eager dir-evict / dir-gen invalidation / BAST set-stale) then FUA-RE-READ from the stale
platter (test4's cnt=4 still in SCST write cache, not destaged), and a later co-resident
child flush writes that re-read cnt=3 back. ⇒ ROOT = SCST-write-cache-vs-FUA-read +
buffer invalidation while THIS node's own dir change is un-destaged. (Same deep class as
the bnobt/di_size sessions.) NEXT: instrument the cluster-buffer XBF_DONE-clear + FUA
re-read for the cross_vis dir ino while in-core has uncommitted dirents.

## My changes this session (build 7C44AF11, KEEP — no regression, cross_vis 0/5→4/5)
1. xfs_mxfs_dlm.c: `mxfs_inode_cluster_durable(ip)` helper (log_force→imap_to_bp→
   iflush_cluster→bwrite→blkdev_issue_flush) + call it in `mxfs_dlm_evict` for FMT_LOCAL
   dirs (P-EVICT-SFDIR). **Fires 0×** (at reclaim the dir is already mode=NL → released
   earlier; evict not the path). Harmless defense-in-depth.
2. xfs_inode.c merge_dirs: the two INERT skip guards above (P-CLMERGE-SKIP-HELD,
   P-CLMERGE-DIRAHEAD). Inert but harmless; KEEP DIRAHEAD as it's correct-if-ever-hit.
**Unclear if cross_vis 4/5 is causal or variance** (sess84 said "every run" failed; my
side effects: the iget/igrab in merge, the evict flush). NOT yet proven causal — the
detectors that would prove it never fire. Treat as provisional.

## REMAINING (criterion passed=1 failed=3)
- **rename_visibility**: 28/240 misses, FAST 9s (no timeout). 80 dirents (20/node) in one
  shared dir ⇒ BLOCK-format dir → dirents in DATA blocks, NOT the dinode. Different
  mechanism from cross_vis (shortform). Path = mxfs_dir_flush/evict_data_blocks + the
  noino-BAST (P-NOINO-BAST fires 8-18×/run on the shared dir = inode reclaimed mid-run,
  peer BAST releases slot with NO data drain). Next target (cleanest: fast, no timeout).
- **unlink_visibility**: 1-21 misses + 140s (barrier timeout).
- **cross_write_read**: 1 miss + 244s (barrier timeout).
- **Barrier latency** (the 120/240s timeouts, also hit cross_vis run4 @124s): barrier
  marker files are shortform dirs; markers become visible SLOWLY (not lost). Common
  slowness factor across 3 subtests. sess50 = CAW writer starvation; defer_for_waiter
  landed there.

## RULE 5 candidate
This is the recurring deep cross-node inode-cluster + dir-DATA-block coherency problem
(SCST write-cache vs FUA-read, durable-before-NL invariant violated when a node's own
un-destaged change is FUA-re-read). Landed one provisional fix. If the next 2-3 attempts
on rename/barrier stall, consult Gemini with: the merge-ruled-out finding, the
buffer-invalidate-then-FUA-reread-stale hypothesis, and the noino-BAST no-drain path.

See [[sess84_lessons]] [[sess83_lessons]] (noino-BAST root for block dirs) [[sess50_lessons]]
(CAW writer starvation = barrier latency) [[sess61_lessons]] superseded re: merge being
the revert path (it is NOT). State head = sess85.
