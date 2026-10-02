---
name: trap-a-throughput-yardstick-from-an-idle-host-grades-boards-that-ran-beside-other-clusters-and-the-users-load
description: USER-CORRECTED (0.90.39): native yardstick ran solo on an idle clyde; MXFS fio rows ran with 6 clusters up + user's jobs on the same NVMe. Measure al…
metadata:
  type: feedback
---

The native-XFS yardstick (`tools/xfs_baseline_refresh.sh`) runs on test1 with every rig group powered off. The release boards ran their `fio_perf` rows side by side: the host-wide throughput lock does serialize the fio windows themselves (a row logs "waited Ns for the shared host lock"), but while one row measured, the other five clusters stayed up and mounted on the same NVMe that backs every pool LUN (the disk/caw boards' disk heartbeats included). Clyde also carries the user's own workloads on that NVMe (a model-training job, a dispatcher worker, redis), and they were busy during the 0.90.39 boards.

`fio_perf` records only the host's load average (`hostload=`), nothing about I/O, and clyde keeps no sysstat history, so a low reading cannot be told apart from host contention after the fact.

What this produced: 4/net/mesh/direct seqW read 1018 MiB/s (72%) on g4 after the iSCSI tuning was reverted, against 1992 and 2024 on the same group an hour earlier. Last session had called the tuning "PROVEN" as the cause from two samples per arm taken under the same uncontrolled load. The user corrected it: "it's mostly idled now, but not when you were doing the damn testing", and the yardstick was a single node with nothing else running.

Do:
- Measure both sides of `fio_perf_vs_xfs` under the same host conditions. Run the yardstick, then each configuration's throughput rows alone, with only that group powered up.
- Run a host sampler alongside: `/proc/diskstats` nvme0n1, `/proc/pressure/io` and loadavg every 5 s, written into the evidence directory, so every fio window can be checked against what else the host was doing.
- Never name a cause of a throughput difference from two samples per arm on this host. The pass-to-pass spread inside one run is already 2x (e.g. rank1 seqW passes 453/224/232/172).
