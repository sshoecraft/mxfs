---
name: ccloop-c7ee71c6-sess21-measurement-traps-and-degradation-defect
description: sess21: three measurement traps that produced false conclusions (ratelimited probe counts, storm dmesg only on FAIL, serial console vs ssh), plus the…
metadata:
  type: project
---

# sess21 — measurement traps that produced FALSE conclusions, and one new defect

## Trap 1: ratelimited probes make a hot path look rare
`P65-EPOCH-CONVGATE` uses `pr_warn_ratelimited` and reads **0-1 per storm run**.
I concluded "this path is too rare to get statistical power on" and nearly
abandoned a valid A/B.

The counted `pr_warn` I added at the same decision point (`P193`) shows the path
actually fires **68x per storm run**.

**Rule: before reasoning about ANY probe count, check whether it is
`pr_warn_ratelimited` vs a capped `atomic_inc_return` counter.** The two are not
comparable and ratelimited counts are not measurements.

## Trap 2: sf_mkdir_storm dumps dmesg ONLY on FAIL
A failing run's log dir has `dmesg_test*.log` (32 files, ~30 MB).
A passing run's log dir has only `markers_test*.log` — a FIXED 6-marker subset
(P3-REFUSE-OLDER-DISK, P21-RB, P179, P178, P174, P-SFDIR-REVERT) and nothing else.

`grep -c` across `$PASSRUN/dmesg_test*.log` therefore returns 0 for every marker,
which reads as a perfect "everything fixed" table. I produced exactly that table
and it was entirely fictitious.

**Rule: after a PASSING storm, capture dmesg yourself before re-prepping** —
the ring is still on the nodes:
`for i in $(seq 1 32); do tools/mxfs_sshpass.sh test$i "dmesg" > $LOG/test$i.dmesg & done`

## Trap 3: a soft-locked node is invisible to every ssh-based capture
See `ccloop-c7ee71c6-sess21-tcp-wedge-root-sleep-in-atomic`. Node pings, `virsh
domstate` says running, but sshd cannot fork so `dmesg`/`ps` return NOTHING.
Read `/var/log/libvirt/qemu/<vm>-serial.log` (sudo) — the soft lockup, rcu
stalls and atomic BUG were only there.

## NEW OPEN DEFECT — the mount degrades with use (UNROOTED)
A test that passes comfortably on a fresh prep cannot finish inside its budget
after a storm plus a dozen tests on the SAME mount:

| condition | test | after prior work | fresh prep |
|---|---|---|---|
| 32/caw @0.11.163 | rsync_paired | 0/32 NO_TERMINAL_RECORD [60s] | PASS 14s |
| 32/caw @0.11.163 | crash_consistency | 31/32 | PASS 32/32 |
| 32/caw @0.11.167 | crash_consistency | 0/32 NO_TERMINAL_RECORD [90s] | PASS 57s |

Critically: running the **identical 13-test sequence** on a fresh prep passes
every time, so this is NOT test ordering — it is accumulated mount state.

Do NOT dismiss this as a harness artifact. It is reproducible, and it is exactly
what a long-running production mount would hit. Under RULE 0 a clustered FS that
must be remounted to stay inside its performance budget is not shippable.

Suspects not yet tested: DLM lock-table growth, AG grant cache churn, inode
cache/AIL growth, CAW slot-table pressure, `pag_dlm_*` counters that never reset.

## Also: transport switch needs a forced re-prep
The one 32/caw sweep that showed real failures was the one run immediately after
a tcp->caw switch; its prep took 214 s vs 63-130 s normally. Always
`MXFS_FORCE_PREP=1 ./run.sh <N> <dlm> prep_cluster` after changing transport
before trusting any cell.
