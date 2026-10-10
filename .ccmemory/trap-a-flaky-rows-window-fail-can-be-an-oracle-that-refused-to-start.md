---
name: trap-a-flaky-rows-window-fail-can-be-an-oracle-that-refused-to-start
description: TRAP: crash_audit FLAKY came from a FAIL whose oracle.log was only 'ABORT: srcversion != tree' (exit 2, no I/O). Read the FAIL's evidence before plan…
metadata:
  type: feedback
---

A board row reading FLAKY means a FAIL sits in its 11-run window (tools/flake_laps.py gives k and the laps needed). Before spending laps, read that FAIL's own evidence directory.

2/disk/caw/direct crash_audit read FLAKY on 0.90.107 because of a 2026-10-05 FAIL ("oracle=FAIL acked=0 ... (got 2:)"). Its `oracle.log` held only `ABORT: test15 srcversion != tree ...`: tests/tcp_death_replay.sh refused to start because a node ran a module other than the tree's (the tree was rebuilt under the run). The filesystem was never exercised. tests/death/crash_audit.sh scores ANY non-zero oracle exit as a failed death oracle, and the reason text matches none of criteria.RIG_NOISE, so the board counted it as genuine.

Ways to clear it:
- `tools/criteria.py amend --at <cfg> --iso <iso> --detector-defect "..."` needs a detector fix ALREADY in the tree. Editing a test script after a version's evidence was gathered opens a new version and voids that evidence.
- Otherwise run the laps: LAPS="<cfg>:<row>:<10-k>" on tests/release_verify_chain.sh. 9 crash_audit laps on 2/disk/caw/direct took about 3 min each.

Open record: D-CRASH-AUDIT-SCORES-AN-ORACLE-THAT-REFUSED-TO-START-AS-A-FAILED-DEATH-ORACLE.
