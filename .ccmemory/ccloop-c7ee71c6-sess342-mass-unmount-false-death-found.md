---
name: ccloop-c7ee71c6-sess342-mass-unmount-false-death-found
description: sess342: NEW unledgered defect — mass 31-node unmount stops hb at umount entry, teardown ~100s, peers false-declare LIVE nodes dead + fence; A5 scrip…
metadata:
  type: project
---

# sess342 — mass-unmount false-death discovery (mid-A5)

Context: continuing #90/#91 pre-rig checks on 0.12.6 (sv FE2B7E1CF2A875536F20577).

## Done
- Wrote tests/d513_lone_mount_torn.sh (check A5: lone-node mount over shape-4 torn dead peer → durable TERMINAL_REFUSED publish + mount -EIO). Syntax-checked, NOT yet run to completion.
- Re-prepped fleet once (120s), then the script's step-1 mass unmount (31 nodes) exposed the new defect below and the run aborted at the verify gate.

## NEW DEFECT (not yet ledgered — RULE 6 requires ledgering next session)
Mass simultaneous `umount /mnt/shared` on 31 of 32 quiescent nodes:
1. Heartbeat publishing stops at umount ENTRY; teardown then takes ~100s under 31-way contention (test3: umount invoked 14:23:37, "Unmounting Filesystem" 14:25:17, clean slot release 14:25:17.7). >100s quiescent unmount = RULE 0 violation too.
2. At 62s peers mass-declare the still-unmounting LIVE nodes dead (test3 journalctl 14:24:39.8 burst: slots 1,2,16,19,23,26,29,30,31 "no longer responding ... initiating recovery" + "fencing; recovery starting"). Fencing a live mid-teardown writer is the hazard; here every fence intent failed P238-FENCE-NOINTENT rc=-116 so no preempt consumed — luck, not containment.
3. test2 (slot 20, the one node not unmounting) latched pending recovery for ALL 31 slots, loops "re-elected ... after replayer death" and every foreign replay refuses "no proven exclusion of the dead node (-2)" — phantom recovery livelock against cleanly-released slots. State persists on test2 (still mounted).
4. No P278-HB-STALL on any unmounting node — hb thread not stage-stuck; watchdog parks stage at SLEEP on deliberate exit (dlm/disklock.c:1710-1712). So the hb stop is an ORDERING choice in teardown: find who calls mxfs_disklock_stop_heartbeat relative to the long pre-teardown sync and the final "released heartbeat slot (clean teardown)". Hypothesis (RULE 4 open): heartbeat is stopped (or starved) ~100s before slot release; hb must persist until release.
Distinct from but related to #22 D-MASS-FALSE-DEATH-FROZEN-GRANT-STALL-482 (that one is hb-thread stall under load; this is teardown ordering).

## Evidence (live, harvest before re-prep)
- test2 dmesg: full phantom-recovery loop (uptime ~257s block).
- test3/test30 journalctl -k --utc 14:23:00-14:27:30.
- Round-1 umount wave: 60s-timeout killed ssh but umounts completed later; a second umount wave clears in ~1s.

## Next
1) Harvest evidence → tests/evidence/, ledger the defect.
2) Re-prep, run tests/d513_lone_mount_torn.sh 32 test2 test1 (timeout 420s).
3) Then A1-3 forged-sector imports (outcome record at hb+160: magic 0x4F435652 RVCO, ver@+4, outcome@+6, reason@+8, domain@+10, vslot@+12, crc@+92 binds victim identity), A4 two-victim abort, B #91 replay-write IO-error knob.
