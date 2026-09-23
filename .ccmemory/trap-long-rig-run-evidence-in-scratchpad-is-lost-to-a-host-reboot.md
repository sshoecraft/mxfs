---
name: trap-long-rig-run-evidence-in-scratchpad-is-lost-to-a-host-reboot
description: TRAP (sess400/401): the 6-lap d385 board's D385_OUT lived in the session scratchpad (/tmp) and clyde was rebooted mid-run — result GONE. Long rig-run…
metadata:
  type: feedback
tags: [trap, evidence, scratchpad, host-reboot, rig, d385, feedback]
---

# Long rig-run evidence must live under the repo, not the scratchpad

## What happened (2026-08-22, ccloop sess400 → 401)
- The previous session launched the 6-lap d385 verification board for
  D-AGI-FREECOUNT-BTREE-DIVERGENCE-STALE-AGI-RMW-399 via a rig-runner with
  `D385_OUT=/tmp/claude-1000/-src-mxfs/<session>/scratchpad/board13`.
- clyde was cleanly rebooted at 18:05 CDT (not a crash: no pstore record,
  `mxfs-crash-latch: no new crash records`, services stopped in order) — about
  15 min into the board.  The session, its in-flight agent, the scratchpad and
  every lap log died with it.  The VMs came back shut off; the rig had to be
  rebuilt (`scst_setup.sh setup` → `virsh start` ×32 → `mpath_up.sh up 32` →
  passfile trap fix → preflight → `MXFS_FORCE_PREP=1 ./run.sh 32 caw
  prep_cluster`, ~7 min total) and the whole board re-run.

## Rule
- Anything a rig run writes that a later session must read — board lap logs,
  dmesg harvests, probe sweeps, churn outputs — goes under
  `tests/evidence/<sessNNN_topic>/` (NFS, survives a host reboot) at launch
  time, not copied there afterwards.  The scratchpad is for this session's
  scratch only; a 30-minute rig run outlives the assumption that the session
  will still be there to copy its results.
- Same for `AGIFC_OUT`, `TMPC_OUT`, `FTR_OUT`: point them at the evidence dir.

## Also observed
- This session (ccloop "400") found a ccmemory note already labelled sess400
  written by the transcript `d82236f1` — the previous session self-numbered
  400 while ccloop's resume called it 399.  This session's evidence is
  labelled `sess401_*` to stay unambiguous.
