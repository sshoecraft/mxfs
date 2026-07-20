---
name: sess93-duplicate-ccloop-incident
description: 2026-06-11: TWO ccloop sessions ran run 14d31183 concurrently after host reboot — ALL test results 04:02-04:25 UTC contaminated; 9C2D4FA6 still UNVER…
metadata:
  type: project
---

# Duplicate ccloop session incident — 2026-06-11 ~04:00-04:25 UTC

## What happened
Dev host clyde rebooted twice (03:22 and 03:59 UTC / 22:22+23:00 CDT), killing
ccloop sessions 14/15 and wiping host /tmp (including /tmp/.mxfs_pass — restore
it from `/home/steve/.mxfs/pass`). After the 03:59 reboot, TWO ccloop wrappers
resumed run `14d31183-faba-4a50-9608-1cd024839b53` concurrently:

- PID 10555 (04:00:22 UTC, PPID 1, headless `claude -p`) → session 21180450 (session-16)
- PID 14911 (04:02:32 UTC, user's terminal pts/1) → session 8947b4e5 (session-17)

Both sessions independently ran `cluster_reset_n.sh 16`, storms, and
`zero_silent_loss.sh` against the SAME 16-node cluster simultaneously.
Session 21180450's storm run 1 was destroyed mid-flight by session 8947b4e5's
virsh power-cycle at 04:10:27; 8947b4e5's `zero_silent_loss.sh` (04:13:57)
overlapped 21180450's second storm. Session 21180450 detected the duplication
at ~04:25, yielded (killed its own wrapper), and the user-visible terminal
session 8947b4e5 continued the run alone.

## Consequences — treat these results as INVALID
- BOTH p133 storm runs in session-16 (visible=0/1598-loss and visible=100/1500-fail)
  are artifacts of cross-session virsh resets + SCSI PR clears, NOT mxfs bugs.
- The `zero_silent_loss` FAIL recorded 2026-06-11T03:46/04:13 in
  `.criteria_results.json` is contaminated (a second cluster_reset and a
  concurrent storm were running). Re-run on a quiet cluster.
- The `mkfs_timing` FAIL (rc=1, 2026-06-11T01:11) predates this window — verify separately.
- Apparent symptoms seen during the window (root dir ino=128 read as empty
  shortform by 15 peers / P127-DIRMISS storm; test1 SCSI reservation conflict;
  P135-FOREIGN-STRIP on ino=128) were caused by mkfs/mount racing a power-cycle
  and PR-clear from the other session. Do NOT chase them as mxfs bugs unless
  they reproduce on a quiet cluster.

## Build status (unchanged from sess13 handoff)
- `9C2D4FA6` (= verified bast_notify-serialization P108 fix + UNVERIFIED
  RELFLUSH-for-directories fix) is deployed-built but its storm validation is
  STILL PENDING. P119-NONEX-FLUSH-SKIP count was 0 in the contaminated runs
  (weak positive signal the flag change took effect). Next step is unchanged:
  quiet-cluster `cluster_reset_n.sh 16` → `p133_storm_errcap.sh 100` expecting
  0 HOLEs → 3× `zero_silent_loss.sh`.

## Operational lessons
1. Before ANY cluster operation, check for a concurrent driver:
   `ps aux | grep -E 'ccloop|claude'` — if more than one ccloop is on the same
   run id, STOP and resolve (the later/user-terminal one wins).
2. Host reboot wipes /tmp/.mxfs_pass; restore with
   `cp /home/steve/.mxfs/pass /tmp/.mxfs_pass && chmod 600 /tmp/.mxfs_pass`.
3. All-16-VM simultaneous reboots / qemu lstart times = host-side virsh actor,
   not an mxfs fencing bug (mxfs has no reboot path — verified by grep).
4. Related: [[feedback_runbook_prompts]], [[project_test_cluster_scst]].
