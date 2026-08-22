---
name: ccloop-c7ee71c6-sess225-board-27of28-green-480-ccprofile-grant-wait-still-top
description: sess225: FULL closure board 27/28 PASS on 0.11.480 (only open_defects policy red); virgin-fs cc stackprof: caw_wait_for_grant STILL top at 26.7% ticks
metadata:
  type: project
---

# sess225

## Closure board DONE (owed by #20/#27)
0.11.480 sv 567D9BDA19C009274B87A73, 32/caw, 2026-08-10 ~22:00-22:12Z.
27/28 PASS; only red = open_defects (POLICY, 31 ledger entries open).
Walls: prep 119s/74s, dir_reuse 101/120, fence_during_write 21/60,
fault_netpartition 9/60, soak 31/60, dirent_durability 65/240 loss=0,
node_responsive 12/90, kernel_health 3/120 hits=0, dirent_publish 3/60,
dirent_type 3/60, ag_strand_repair 78/240, sustained_load 5/180,
dlm_lock_correctness PASS. cc + rsync carried from sess224 same-build
standalone PASSes. Board cells persist per build; run.sh only marks
non-PASS cells PENDING.

## Virgin-fs crash_consistency stack profile (ledger #27 item 2 DONE)
Fresh prep, cc PASS 87s/90s (hostload 31.7 — rode the edge again),
stackprof 32 nodes, 95651 ticks:
- caw_wait_for_grant did NOT drop to noise: 26.7% of ALL ticks in
  cond_timedwait < caw_nudge_wait < caw_wait_for_grant < mxfs_dlm_caw_lock
  < mxfs_v5_dlm_inode_lock (dd 13.2%, bash 11.6%, md5sum 1.8%).
- The earlier ">5ms waits = noise" probe missed it: wall is many sub-5ms
  nudge/poll cycles per grant (52.6 slot READs/grant known figure).
- FOCUS (release/holder side) 1.73% — holders not stuck.
- Transport service ~2% — not the wall.
- NEW SECONDARY: md5sum|open_last_lookups 11.9% (verify-phase cold opens;
  wait primitive inlined/stripped — identify before attacking).
Conclusion: root remains per-grant poll/nudge pacing of the CAW inode
lock. Next live thread = ledger #27 item (a) forced-inline A/B knob and
reducing poll cycles per grant. AG-DLM alloc / journal serialisation
refuted as the wall on this profile.

## Sampler trap
mxfs_stackprof.py writes output only at duration END — harvesting before
dur_s elapses reads empty files (nodes=0). Wait out the duration.
