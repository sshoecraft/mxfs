---
name: sess-tcp-subtest3-atime-ex-deadlock
description: 2-node TCP cache_coherency subtest3 (rename) wedges: read→touch_atime→xfs_ilock(EXCL)→mxfs_dlm_ilock_begin hangs 122s+ (atime-on-read takes cluster E…
metadata:
  type: project
---

## Status after the 3 root fixes ([[sess-tcp-2node-three-root-fixes]], build A70942DB)
Basic cross-node create+read works. cache_coherency subtests 1+2 PASS (proven via
bash -x trace): `cross_visibility` OK, `cross_write_read` (1MB random, md5-verified
BOTH directions) OK, PASS_N=11 on both nodes. MQTT coord_barrier primitive is reliable
(8/8 distinct barriers ~2s each in isolation — NOT the blocker).

## NEXT BLOCKER: subtest 3 (rename_visibility) WEDGES — atime-on-read EX deadlock
The test reaches `rename_visibility` then hangs. Root (PROVEN via /proc/PID/stack on test1):
- `cat:4408` D-state, blocked >122s:
  `mxfs_dlm_ilock_begin ← xfs_ilock(EXCL) ← xfs_vn_update_time ← touch_atime ←
   filemap_read ← xfs_file_buffered_read ← vfs_read`
  i.e. the subtest-3 content-verify `cat "$D/node${n}_after_${i}"` triggers a relatime
  atime UPDATE, which takes **ILOCK_EXCL → a cluster-wide DLM EX acquire** that never
  completes (122s+, well past any sane timeout = a hang/deadlock).
- `rm:4738` D-state in `vfs_unlink` (secondary — stuck behind cat's held locks; was an
  inter-run `rm -rf` cleanup).
- test2 was IDLE (load 0.03) the whole time → the EX acquire is waiting on a peer grant
  test2's DLM never serviced, OR a test1-local lock inversion.

A READ taking a cluster EX lock for atime is both a correctness/deadlock hazard and a
perf disaster. Mount is `relatime` (default) so it only fires on first-read-after-write
— exactly subtest 3's pattern. sess45 memory claims an "atime skip" fix
(5ED458EB: node-affine alloc + atime skip + getattr SHARED reload) — evidently NOT
covering this buffered-read touch_atime path on TCP, or regressed.

## Hypothesis to test next
1. Remount `noatime` (or make multi-node read-atime NOT acquire DLM EX) → does subtest 3
   complete? If yes, atime-EX is confirmed the trigger. Root fix candidates: skip lazy
   atime update under multi-node mxfs, or downgrade atime update to not need cluster EX.
2. Get the mxfs DLM inode lock-table state for the stuck inode (who holds EX) — need a
   sysfs/dmesg dump path; test1 was wedged so capture before it wedges.

## Infra note
A wedged node (D-state in mxfs_dlm_ilock_begin) cannot umount/rmmod — recover with
`virsh -c qemu:///system destroy/start` (see [[reference-node-power-control]]). The
hung-FS `ls /mnt/shared` itself hangs the ssh — probe with `echo alive; ps ... D-state`
WITHOUT touching the mount.
</body>
