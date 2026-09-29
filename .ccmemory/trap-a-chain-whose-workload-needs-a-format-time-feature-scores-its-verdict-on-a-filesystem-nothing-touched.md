---
name: trap-a-chain-whose-workload-needs-a-format-time-feature-scores-its-verdict-on-a-filesystem-nothing-touched
description: TRAP (0.90.12): chain 116's normal laps PASSed the SB-seal verdict at 4/tcp while its sharded-dir workload got EOPNOTSUPP (no mkfs -D): icount=64 eve…
metadata:
  type: feedback
tags: [harness, chain116, D-0133, dirshard, vacuous]
---

# A chain whose workload needs a format-time feature scores its verdict on a filesystem nothing touched

**What bit (2026-09-28, sess475 chain116 at 4/tcp, tests/evidence/sess475_chain116_d0133_s4e_4tcp.log):**
the chain's normal laps run tests/dirshard_reuse_peer_list.sh as the SB-dirtying workload, then
fleet-unmount and compare the highest-epoch writer's SB counters with chk_mxfs.  Every sharded mkdir
returned `ERR ENOTSUP MXFS_IOC_DIRSHARD_MKDIR` because `mxfs_dirshard_enabled(mp)` needs a filesystem
formatted with `mkfs_mxfs -D`, and the rig prep formats without it.  The reuse harness reported 110
failures per lap (so it was not silent), but the chain's OWN verdict lines — seal-ok, distinct epochs,
counters == chk — all PASSed, on `icount=64 ifree=61` for every lap: a fleet unmount of a filesystem
whose counters had never moved verifies nothing about the summary lock.

**Two harness misses stacked:** the chain's lock-line grep (`epoch=N at=put_super`) predated the
`master_self=` field added 0.89.66, so `lock_ok=0` on every lap — read as a filesystem fault at first.
Both are harness staleness; the verdict function's seal and last-write witnesses were counting 4/4.

**Fixes:** the chain exports `MXFS_MKFS_OPTS="${MXFS_MKFS_OPTS:--D}"` (run.sh passes it to
tests/setup/prep_fs.sh), and the lock pattern allows fields between `epoch=` and `at=`.

**The general check, before trusting a chain's PASS:** read one lap's counters in the VERDICT/TERMINAL
line and the workload's own verdict.  If the workload harness says FAIL/VACUOUS, or the counters equal
the fresh-format values (icount=64 on this mkfs), the lap exercised nothing, whatever the chain says.
