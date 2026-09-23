---
name: trap-a-release-pause-knob-left-armed-through-the-verdict-parks-the-holders-own-re-release-and-empties-every-cold-capture
description: TRAP (sess606/607, D-0958 controls): live_holder_wait.sh cleared dbg_rel_pause_* only at exit, so H's cold reads in the verdict (drop_caches re-cache…
metadata:
  type: feedback
tags: [harness, live_holder_wait, dbg_rel_pause, D-0958, false-fail]
---

# A release-pause knob left armed through the verdict empties the holder's cold captures

## What happened (s606k-n, s607e/g/i/j; tests/live_holder_wait.sh)
- The lap arms `dbg_rel_pause_ino/stage/ms` on H so H's release drain of the target pauses when W's request arrives. W's operation waits it out and lands. Correct so far.
- The verdict then asked H for cold state: `echo 3 > drop_caches; stat; md5sum; getfattr`. Each drop_caches evicts H's inode; if H had re-cached a grant (the previous cold stat took PR), the eviction RELEASES it, the bast worker hits the still-armed knob, and `mxfs_dbg_rel_pause` sleeps PAUSE_MS. The ssh's `timeout 30` killed it with an empty capture: `got=none want=v958` on every xattr control, `got= want=mmw!` on the mmap_write control, walls 317-320 s against 290 s for laps that happened not to re-release.
- Proof: by hand on the idle rig the same command was 11 ms with the knob clear and hung >120 s with it armed; H's dmesg showed `P-D512-RELPAUSE-END ino=10686` 240 s AFTER the s607j lap had ended, and `kworker mxfs-ino-bast` parked in `mxfs_dbg_rel_pause+0x68`. The operations under test had all landed; only the harness's own late reads were parked.
- Same family as s596h (`got=2 want=1` pause count): the knob fires on EVERY release of that inode by H, not once.

## The rule
- Clear a pause/drop knob the moment the operation under test has returned, BEFORE any verdict-side access to the target on the node that carries it. `clear_knobs` at exit is too late for a verdict that touches the file.
- A verdict wall that is consistently one ssh-timeout longer than a passing lap's is a hung capture, not a slow node.
- A knob's set-call can hang behind the pause it controls (the clear itself took >20 s while a worker slept); wait for `P-D512-RELPAUSE-END` count == `P-D512-RELPAUSE` count before trusting the rig is idle.

Fixed 0.84.21: live_holder_wait.sh clears the pause knob on H right after `tread=` (W's return), and reads the attribute in the same cold pass as its stat and digest.
