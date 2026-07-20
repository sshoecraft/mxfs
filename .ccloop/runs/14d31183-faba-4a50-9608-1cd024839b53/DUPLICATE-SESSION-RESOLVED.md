# Duplicate ccloop resolved — 2026-06-11 04:2x UTC

After the host reboot at 03:59 UTC, two ccloop wrappers resumed this run
concurrently:

- PID 10555 (started 04:00:22 UTC, PPID 1, headless) → session 21180450 ("session 16")
- PID 14911 (started 04:02:32 UTC, user terminal pts/1) → session 8947b4e5 ("session 17")

Both drove the 16-node test cluster at the same time (two cluster_resets,
overlapping storms, a zero_silent_loss run, virsh destroys mid-test). All
cluster test results between 04:02 and ~04:25 UTC are cross-contaminated and
must be discarded — including the zero_silent_loss FAIL and both p133 storm
runs. Details in project memory `sess93-duplicate-ccloop-incident`.

Session 21180450 detected the duplication and terminated its own wrapper
(kill 10555) so that the user-visible terminal session 8947b4e5 owns the run
exclusively from here on.

To the surviving session: build 9C2D4FA6 (RELFLUSH-for-dirs) is still
UNVERIFIED. Restart validation from a clean, quiet cluster:
  1. ps aux | grep ccloop   # confirm you are the only driver
  2. scripts/cluster_reset_n.sh 16
  3. scripts/p133_storm_errcap.sh 100   # expect 0 HOLEs / 0 silent loss
  4. 3x tests/criteria/zero_silent_loss.sh
