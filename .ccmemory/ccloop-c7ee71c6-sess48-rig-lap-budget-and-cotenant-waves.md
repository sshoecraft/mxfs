---
name: ccloop-c7ee71c6-sess48-rig-lap-budget-and-cotenant-waves
description: sess48 rig lesson: run.sh has a SEQUENTIAL 32×15s mount preflight — outer lap timeout must be ≥580s; co-tenant load waves (Wow.exe/worldserver/other…
metadata:
  type: project
---

# sess48 rig mechanics — the "broker corruption" that wasn't

## The false trail
394-c3/c4 laps kept dying at my 160-240s outer timeouts. I blamed broker state and re-prepped repeatedly (each prep = fresh mkfs = soak substrate reset — harmful). bash -x trace showed the truth: after the run banner, run.sh runs a **SEQUENTIAL per-node mount preflight** — `timeout 15 mxfs_sshpass testN "mountpoint && mount|grep && ls /mnt/shared"` for each of 32 nodes, one at a time (~line with pa_pids/wait loop). Under host load each probe takes seconds → preflight alone runs 100-480s BEFORE any test output. My outer cap killed run.sh mid-preflight → no cleanup → leftover processes → next lap slower → spiral.

## The rules
1. **Outer timeout for any ./run.sh invocation: 580s minimum** (preflight ceiling 480 + workload 60 + collect). The workload's own internal 60s budget is unchanged — RULE 0 intact (18-26s observed when scheduled).
2. Never kill run.sh externally mid-flight if avoidable; if killed, clean leftovers: per node `pkill -f <test>; fuser -k -m /mnt/shared` (run.sh's own idiom).
3. **Clyde is co-tenanted**: Wow.exe (~390% CPU), worldserver, python3/tesseract/VLLM, and TWO other claude sessions (prime suspect for the unattributed 393-c1 NMI injections — tests/drc_autocapture.sh-style tooling injects NMI on hard-hang detection). Load waves 80-190 recur every ~10-20 min and starve all 32 guests (NO_TERMINAL_RECORD=32 at hostload=178 = environmental, NOT an mxfs defect). Do NOT kill co-tenant processes.
4. Gate each lap on load<45 (`cut -d' ' -f1 /proc/loadavg`); wait in 120-180s guest-side sleeps (`mxfs_sshpass test1 "sleep 120"`) between checks.
5. Sweep scans `dmesg | tail -n 200000` (60k lost marks on chatty nodes → false NOMARK).

## Soak state at this writing
0.11.394 (srcver 1497466E...), fleet 32/32, fresh substrate (last prep after the spiral), d1 clean cycle banked (sweep bad=0, ov=2 benign, NUFIX healing live — 61 heals on first 394 cycle). Need ~4-6 total clean cycles + matrix for the P53-family disposition. CHANGELOG 387-394 entry written; xfs.md/pal.md awareness updated.
