---
name: trap-the-16mb-iscsi-tcp-window-tuning-costs-a-third-of-write-throughput-on-the-scst-pool-luns
description: WITHDRAWN 2026-10-01: the 'tuning costs a third of seqW' finding was measured under uncontrolled host load. See trap-a-throughput-yardstick-from-an-i…
metadata:
  type: feedback
---

This note claimed scripts/tune_iscsi_tcp.sh's 16 MB window on test1-16 cut 4/net/mesh/direct seqW to 1150-1864 MiB/s against ~2000 at kernel defaults. It said "quiet host", which was wrong. Every one of those samples ran while clyde carried the user's own workloads and other rig clusters on the same NVMe. An untuned g4 run an hour later read 1018 MiB/s, inside the "tuned" range.

The tuning's effect on throughput is unmeasured. test1-16 were put back to kernel defaults (socket caps 212992, window 524288) so the rig is uniform with test17-28, which is a separate reason to keep them there.

The lesson that replaced this one: trap-a-throughput-yardstick-from-an-idle-host-grades-boards-that-ran-beside-other-clusters-and-the-users-load.
