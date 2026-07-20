---
name: sess13-lkt-dirtrace-harness-gaps
description: sess13: tests/tcp_lkt_dirtrace.sh harness gaps to fix next session (lkt_ino watcher didn't fire; dir unmounted before failure-capture). Partial trace…
metadata:
  type: project
---

## tests/tcp_lkt_dirtrace.sh (CF359E6C) ran but did NOT isolate the dir — two harness gaps to fix BEFORE the next decisive trace:

1. **lkt_ino watcher never fired** — at failure, test1 `lkt_ino=0` (still recording all). The node-side `ssh node "nohup bash -c '... echo \$(stat -c %i $DIR) > $PARAM/lkt_ino' &"` either: the nested-quote/escaping broke, or the dir path/param wasn't ready in the 600×0.1s window, or stat ran before mount. FIX: test the one-liner standalone on a node first; consider writing a small persistent node script (tests/ + NFS) instead of an inline nohup, and have it log to dmesg when it sets lkt_ino so you can confirm it fired.

2. **dir unmounted before failure-capture** — post-run.sh `stat -c %i /mnt/shared/.tcp_dlm_scaling` returned EMPTY and the leftover-dirent listing was empty, i.e. run.sh (single-test) tore down / the mount was gone by the time the driver captured. The drained-check leftover exists DURING the test (rank1 ckeq at the end) but not after run.sh returns. FIX: capture the dir ino + trigger lktdump + read leftovers from INSIDE the test or via a node-side post-fail hook while still mounted — e.g. add to tests/tcp/tcp_dlm_scaling.sh: on the rank1 drain-fail branch, `echo $(stat -c %i "$D") > /sys/module/mxfs/parameters/lktdump` and dump the leftover names to dmesg, so the driver just greps dmesg afterward.

## REINFORCING OBSERVATION (partial trace, build CF359E6C): child inodes (n1_rN, ino 2097xxx) show **GRANT-REMOTE + REMOTE-RELEASE** on the master node (test1) and **GRANT-LOCAL + UNLOCK-GRANTED** on the creator (test2) — i.e. cross-node child grants ARE routed through the master and serialized cleanly (no overlap). Consistent with [[sess13-doublegrant-REFUTED-serialized-stale]]. owner ids seen: 1612911255 (test2), 2457548494 (test1). A trailing `REMOTE-RELEASE ino=132 owner=...` (low ino = a parent/root dir) is the only non-child event that survived the flood — the shared test dir (2097xxx) events were evicted because lkt_ino wasn't applied.

## So the next decisive trace, once the 2 harness gaps are fixed, will finally show the shared-dir grant/release/reaffirm timeline correlated with the resurrected dirent → decides read-coherency vs within-node release-timing. Build CF359E6C deployed. [[sess13-HEAD-status]] [[feedback-never-background-wait-poll]]
