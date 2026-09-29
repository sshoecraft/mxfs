---
name: trap-timeout-around-an-unkillable-umount-never-returns-so-a-stall-capture-after-it-never-runs
description: TRAP (0.90.16): `timeout 60 umount` waits for its child; an umount stuck in the kernel never exits, so the capture after it never ran (twice). Backgr…
metadata:
  type: feedback
---

# timeout(1) around an unkillable umount never returns

**What bit us (0.90.14 and 0.90.16, 4/tcp chk_clean, twice):** the detector did
`timeout 60 umount $MNT` and then, if still mounted, was to capture the kernel
stacks of the in-flight tasks.  `timeout` sends SIGTERM at 60 s and then WAITS
for its child to exit; an umount looping or sleeping uninterruptibly inside the
kernel (xfs_ail_push_all_sync) never exits, so `timeout` never returned, the
harness's 180 s row budget killed the whole node script, and both runs recorded
`rc=124` with an empty output and no stack.  `timeout -k` does not help: SIGKILL
does not end a task in the kernel either, and `timeout` still waits.

**What works (tests/tooling/chk_clean.sh, 0.90.16):** run the umount in the
background, poll `kill -0 $pid` against the script's own deadline, and take the
capture while the umount is still in flight: `/proc/<pid>/stack` of the umount
task, xfsaild, every mxfs-* worker, kworkers with xfs/mxfs frames, D-state
tasks.  The umount's own pid is known, so its stack is the first thing read.

**Rule of thumb:** any harness step whose failure mode is "stuck in the kernel"
(umount, mount, sync, a fenced node's I/O) must not be wrapped in `timeout`
if something after it has to observe the stall; background it and poll.
