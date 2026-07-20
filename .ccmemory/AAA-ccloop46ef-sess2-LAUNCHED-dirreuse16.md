---
name: AAA-ccloop46ef-sess2-LAUNCHED-dirreuse16
description: sess2 tail: dir_reuse@16 attempt 3 running (pid on clyde, log scratchpad/dirreuse16-attempt3.log). Attempts 1-2 died on prep: leftover-extras converg…
metadata:
  type: project
---

# dir_reuse_coherency@16 — attempt log (sess2 tail)

## Attempt 3 (RUNNING at relay): 
`MXFS_DEV=/dev/mapper/mpatha MXFS_EXTRA_MODARGS="caw_fair_handoff=1" timeout 3100 ./run.sh 16 caw dir_reuse_coherency`
- Detached shell-bg (pid 1992002 on clyde), log: /tmp/claude-1000/-src-mxfs/eb86d5cb-4dfe-4534-aa32-12b1a65e25c0/scratchpad/dirreuse16-attempt3.log
- Pre-launch state made deterministic: ALL extras test17-32 force power-cycled (genuinely mxfs-free); participants 1-16 left mounted-healthy on 6CFAB18E (attempt 2's prep remounted them) — next prep tears them down normally.
- Check result: the log file, and ./showstat.sh 16 caw. If it died: relaunch same cmd (extras may need the cycle again if 32-node runs happened in between).

## Why attempts 1-2 failed (lessons)
1. Attempt 1: prep converge gate hit active_count=17 — a leftover 32-node-run node still heartbeating. Root: step-0 extras teardown marked some extras MXFS_CLEAN while they stayed MOUNTED (test18 proven mounted with live traffic AFTER passing "clean"). The TEARDOWN's `umount -l` lazy path + wrapper-flattened quoting are suspects — UNPROVEN, worth a look in run.sh TEARDOWN (line ~86).
2. Attempt 2: relaunched too fast — attempt 1's power-cycled nodes were mid-boot → unreachable ⇒ treated as dirty ⇒ mass power-cycle cascade of ALL participants + 6 extras simultaneously → clyde IO saturation → every teardown timed out ("did not release — escalating" ×16). RULE: after any run that power-cycled nodes, WAIT for ssh on sentinels before relaunching run.sh.
3. Extras from 32-node runs DON'T self-clean: downward ladder transitions (32→16) reliably leave test17-32 holding mounts; if converge fails with count=N+1, power-cycle ALL extras in parallel and retry.
