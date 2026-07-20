  Read CLAUDE.md first (RULES 0-4, the awareness system), then read state.md in the project
  root — it has the full saved state from this session: the RULE-0 calibration ladder
  progress (2/caw done, 4/8/16/32 not done) plus a long, fully-documented but UNRESOLVED
  dir_reuse_coherency bug investigation (7 fix attempts, all reverted per a Fable code-review
  consult, tree is back to a clean passing baseline). The immediate next step is to resume
  the calibration ladder at N=4: RULE0_CALIBRATE=1 ./run.sh 4 caw. Do NOT restart the
  dir_reuse_coherency investigation unless explicitly asked — it consumed most of the
  previous session and is fully documented in state.md for a dedicated future session.
  Watch for the known stale-multipath gotcha on any node reboot (fix: multipath -f mpatha).
  After reading state.md, confirm your understanding of where things stand before running
  anything against the live test cluster.
