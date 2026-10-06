---
name: trap-a-kept-row-kernel-log-starts-with-the-ring-backlog-so-count-only-after-the-rows-own-mark
description: TRAP (0.90.54): kmsg_test*_fromnode.gz begins with dmesg's ring dump; a path_failover file held a killed lap's rows from the OLD module before its ow…
metadata:
  type: feedback
---

kmsg_follow_start (tests/lib/rig.sh) runs `dmesg --follow`, whose first act is to dump the whole ring, then writes PF-MARK-<row>-<run>. A module reload (prep) does not clear the ring, so a row's kept log (tests/evidence/board_<run>_path_<row>/kmsg_<node>_fromnode.gz) can begin with lines from earlier rows, earlier laps, even a different BUILD.

Measured 0.90.54: a sweep counted 81 P-FUA-READ-ERR in lap a's path_failover files and concluded the FUA re-resolve fix failed. Every one sat before that row's own mark — they were the killed previous lap's path_fabric row on the build without the fix. Counted after the own mark: 0 ERR, 501 P-FUA-READ-REPATH on the fixed build.

How to apply: any count, sample or timeline taken from a kept row log starts at the line containing `PF-MARK-path_<row>-<run>` for that row's own run id (the run id is the board_<run> part of the directory name). Tell a subagent sweep to do that explicitly. The first PF-MARK in a file is not necessarily its own.
