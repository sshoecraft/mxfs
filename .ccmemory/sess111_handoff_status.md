---
name: sess111_handoff_status
description: sess111 HANDOFF: drain-wedge fix build 413C9D5D deployed all 4, cc_run4 IN PROGRESS at relay boundary — healthy past the ~100s shutdown point (no rc=…
metadata:
  type: project
---

## sess111 handoff (ccloop run 4eef1f39, relay boundary)

### State at handoff
- Build `413C9D5D` (drain-wedge fix, see [[sess111_drain_wedge_fix]]) built + deployed on
  all 4 nodes, mounted, dmesg cleared.
- cache_coherency run IN PROGRESS: `/tmp/cc_run4.log` (background task b4ed70ga9). At
  ~155s elapsed it was HEALTHY on all 4 (P109-INODE-DRAIN=0, rc-110/unrecoverable=0,
  FREE-AG-EXTENT-FAIL=0, INACT-SKIP-STALE=0, Shutting-down=0, all mnt=UP) — already PAST
  the ~100s mark where build 87726318 shut test2 down via the drain-wedge timeout. Strong
  early sign the fix holds, but the FULL run (all 4 subtests, ~10-15 min) had not finished.

### NEXT SESSION — FIRST ACTIONS
1. Read `/tmp/cc_run4.log` for the RESULT line (passed=N failed=M) + grep EXIT=.
2. dmesg all 4 for: `unrecoverable` (rc=-110, the wedge we fixed — should be 0),
   `P109-INODE-DRAIN` (if fires, check `cbuf_rc/cbuf_flags/redrained` fields — redrained=1
   means the fix engaged; cbuf_rc=-EAGAIN means buffer locked by ANOTHER holder = a
   different wedge), `FREE-AG-EXTENT-FAIL`/`P47-INACT`/`P81-DEXT` (the stale-inode
   double-free, see [[sess111_reframe_bnobt_red_herring]]), and the cross_visibility
   "node3 reads node4's content" / durable lost-write signatures.
3. If the drain-wedge mode is gone but OTHER subtests still fail → iterate on the next
   failure mode (likely stale-inode double-free OR the ~5% durable lost-write per
   [[sess108_lessons]]). If cc_run4 PASSED 4/4 → run `tests/criteria/verify_ship.sh`
   end-to-end (the ship gate).

### Methodology reminders (cost me time this session)
- cache_coherency BUFFERS stdout until done (log stays 0 bytes); judge progress via
  dmesg on nodes, but peeking loads the cluster + slows the run under SSH — peek sparingly.
- P109-INODE-DRAIN only prints at iter&255 (~2.5s stuck); the fix engages at iter≥8
  (~80ms), so P109 may legitimately stay 0 even when redrain fired. Decisive signal =
  `unrecoverable`/rc=-110 staying 0 + all nodes mounted through the whole run.
- Clean reboot ALL 4 (virsh -c qemu:///system destroy+start) before every trusted run;
  then `bash tests/reset4.sh 4`; then `dmesg -C` on all 4. fua_disable=1, instr=0.
Related: [[sess111_drain_wedge_fix]] [[sess111_reframe_bnobt_red_herring]] [[sess109_lessons]].
</body>
