---
name: board-32caw-chunking-measured-walls-and-harness-overhead
description: Measured 32/caw board chunk walls, the 12s/test harness-overhead constant, and the P6->P8 manifest ORDER dependency that makes two criteria fail if c…
metadata:
  type: reference
tags: [rule0, timeouts, board, run.sh, 32caw]
---

Companion to `feedback-sane-timeouts-derive-from-measured-wall-never-pad`.
That memory says DERIVE; this one holds the numbers to derive FROM, plus the
two traps that cost sess378 real time.

## The formula (both terms measured 2026-08-20, 32/caw)

    wrapper = sum(measured test walls) + 12s x n_tests + 15s startup

`12s x n_tests` is harness overhead per test at 32 nodes: ssh fan-out to 32
nodes, MQTT coord-broker retained sweep, per-node aggregation, criteria.json
record. It is invisible in `showstat`'s `elapsed` column (test body only) and
is the term a naive "sum the walls" wrapper misses. Both directions confirmed:
omitting it made a 193s-of-tests chunk run **254s** and get killed; including
it predicted 88s for a chunk that ran **61s**.

**Use the ENFORCED budget, not the measured wall, for any test that has run
near its ceiling.** `dir_reuse_coherency` measured 105-109s against a 120s
budget; a wrapper derived from 109s killed it mid-run twice. Derived from the
120s budget it completed at 108s with room.

## TRAP 1 — the manifest's ORDER is load-bearing (cost sess378 two runs)

`dirent_durability` (phase **P6**) stamps `MXFS_DIRENT_WINDOW` into /dev/kmsg
and writes `/run/mxfs_dirent_window_start`. The phase **P8** criteria
`dirent_publish_integrity` and `dirent_type_integrity` SCOPE THEIR MEASUREMENT
to that window (`dirent_window_scope()` in tests/suite/lib.sh).

Run the P8 pair without P6 first in the same cluster incarnation and they
report `window=0 win_src=none` and FAIL on 30/32 nodes — with every measured
count at zero, so it reads like a mass correctness failure and is not one. A
re-prep power-cycles nodes, clearing both /run and the dmesg ring, so the
window does not survive a prep either.

**If you chunk the board, keep manifest order, and never put the P8 dirent_*
pair in a chunk that does not follow dirent_durability.**

## TRAP 2 — a killed `run.sh` loses its output

`timeout N ./run.sh ... | grep ...` prints NOTHING when the timeout fires, not
even the `=== run @` header that is emitted immediately. The output is
buffered in the pipe and dies with it, so a cut run looks like a run that never
started. Redirect to a file and grep the file afterwards:

    timeout N ./run.sh 32 caw <tests> > "$LOG" 2>&1; grep -E '...' "$LOG"

A cut test is left `PENDING` in criteria.json (it is marked PENDING at
dispatch), so `./showstat.sh 32 caw` tells you what actually happened.

## Whole 32/caw board = ~12 minutes of test wall

Chunks and measured walls on 0.14.11/0.14.12, 2026-08-20:

| chunk | tests | wrapper | ACTUAL |
|---|---|---|---|
| prep | `run.sh 32 caw prep_cluster` | 150 | **56-119s** |
| 1 | precond_readiness, fio_perf, fio_perf_vs_xfs, cache_coherency, strong_consistency, posix_multi, mmap_coherency, zero_silent_loss | 210 | **176s** |
| 2 | dlm_fairness, dlm_membership, scaling_curve, dlm_scaling, rsync_paired (+P8 tail only if P6 ran) | 224 | **208s** |
| 3 | dir_reuse_coherency, fence_during_write, fault_netpartition | 291 | **279s** |
| 4 | crash_consistency, dirent_durability, soak, node_responsive, kernel_health, dirent_publish_integrity, dirent_type_integrity, ag_strand_repair | 400 | **315s** |

## prep_cluster's hidden dependency on the fleet being unmounted

`prep_cluster` took **56s** against an already-unmounted fleet and **failed at
119s** ("mxfs module loaded and won't rmmod after retries") against a fully
mounted one — because its own mass unmount hits
`D-MASS-UMOUNT-ROOT-EX-SERIALIZE-100S-526B` and exhausts prep's rmmod retry
budget. Unmount the fleet yourself first, in parallel, then prep:

    for i in $(seq 1 32); do ( timeout 170 tools/mxfs_sshpass.sh test$i \
      "timeout 150 umount /mnt/shared 2>/dev/null; \
       for t in 1 2 3 4 5 6; do rmmod mxfs 2>/dev/null && break; sleep 5; done" ) & done; wait

Measured 2s (already clean) to 170s (one node exceeding its 150s umount).
CAUTION: `timeout` kills the umount PROCESS but not the uninterruptible
syscall, so a cut umount leaves a D-state task and the next umount reports
"target is busy". Let it finish rather than retrying.
