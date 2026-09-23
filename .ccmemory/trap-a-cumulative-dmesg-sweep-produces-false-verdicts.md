---
name: trap-a-cumulative-dmesg-sweep-produces-false-verdicts
description: TRAP (sess414): tck's dmesg sweeps had 3 verdict-corrupting flaws — ssh-timeout counters summed as ZERO (false FAIL/false PASS), --no-prep WAIT relea…
metadata:
  type: feedback
---

# tck sweep verdict corruption (sess414, all three fixed in tests/tmpfile_churn_kill.sh)

Three compounding flaws produced two consecutive FALSE FAILs of the node_death_replay board row
on 0.27.7 while the FS was behaving correctly:

1. **ssh-timeout counters summed as zero.** Each survivor's sweep `timeout 60 $SSH ... >$D/s$i`
   wrote rc=124 on timeout and the bare header line carried NO counters — `sum()` silently
   treated the node as all-zeros. Run board_20260824T040959Z: 5 nodes rc=124 including test1 the
   replayer, whose ring PROVABLY held both victims' "foreign replay of slot N complete" lines
   (verified directly at 04:12Z) → frc=0 < victims=2 → FALSE FAIL. Same gap can hide a real
   shutdown (sd) on an unreported node → FALSE PASS. FIX: command hoisted to TCK_SWEEP_CMD, one
   retry pass for unreported nodes, then SWEEP_MISSING fails the lap fail-closed ("an evidence
   gap is a verdict, never a zero").

2. **--no-prep lap greps CUMULATIVE dmesg.** arm_prep clears rings; the board row's lap 1
   (--no-prep) does not, so the recovery WAIT counted the PREVIOUS run's replay-complete lines
   and released at +21s — before HB expiry (~62s) — unmounting the fleet mid-death-window
   (board_20260824T042006Z): frc=0 legitimately because recovery never got to run, shaped
   exactly like a real no-replay defect. FIX: `dmesg -C` on every node at --no-prep lap start
   (slot mapping unaffected — it reads journald).

3. **36 separate full-ring greps per sweep.** 16MB printk-flooded ring × 36 passes on a pegged
   1-2 vCPU VM right after churn > 60s → the rc=124s in (1). FIX: TCK_SWEEP_CMD now dumps the
   ring ONCE to /tmp/tck_ring and greps the file (36× less ring reading).

After all three: board_20260824T042733Z PASS 316s/470s, WAIT released at genuine +77/+79s,
frc=2/2 both laps, sweeps complete.

**Generalizable rule: any harness that sums per-node counters MUST fail-closed on a missing
per-node report, and any cumulative-dmesg grep MUST be windowed (ring clear or marker).**
Other harnesses with the same cumulative-grep shape are suspect — check before trusting their
counts across back-to-back runs (d526_mass_unmount_verify, fr_mount_barrier_fail, rman_matrix).

Also learned: run.sh RETAINS fail logs at /tmp/run_<name>_<RUN_ID> — the `logs: /tmp/tmp.*`
path it prints is deleted immediately at exit. Harvest the run_* copy. (And rman_matrix.sh's
$1 is the EVIDENCE DIR, not an arm: `rman_matrix.sh base_shared base_shared base_shared` runs
TWO arms with evidence in ./base_shared — the sess413 chain2 made exactly this mistake.)
