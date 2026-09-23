---
name: trap-run-dir-kernlogs-carry-the-whole-boot-journal-shutdowns-in-a-cc-run-dir-may-be-an-earlier-injection-leg
description: TRAP (sess495): 'Corruption of in-memory data at mxfs_ailpin_work_fn' in 10 cc run dirs today was the D-0487 INJECTED fail-stop (P487-INJECT-UNDER-LO…
metadata:
  type: feedback
---

# TRAP: a marker census over run_*/kernlog_test*.gz counts the whole boot journal

sess495 evidence census (scripts/evidence_marker_census.sh) reported 'Corruption of in-memory data (0x8) at mxfs_ailpin_work_fn ... Shutting down filesystem' in 10 run_crash_consistency_* directories of 2026-09-04, including the chain 139 leg A rows (111915Z, 112148Z). The context sweep showed every hit is on test1 at 08:45:51, 08:48:00, 10:40:54 or 11:00:22, each 10 s after `P487-INJECT-UNDER-LOCK slot=0 armed_agno=7 ... rc=0` — the deliberate injection legs of tests/sess488_ailpin_fleet_umount.sh (s493e at 10:40, s494z at 11:00) whose fail-stop shutdown is the leg's PASS criterion. The cc run directories' kernlogs are `journalctl -k` captures that reach back to boot, so a run directory contains every earlier marker on that node since its last reboot.

Rule: before attributing a shutdown/marker to a run, check its timestamp against the run's own window (the mxfs-CCph PHASE=start marker or the STAGE line time) and look 15 lines above for an INJECT marker. The identical byte-for-byte context blocks in two different run dirs were the tell.
