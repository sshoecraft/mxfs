---
name: trap-a-lap-chain-started-as-a-session-background-task-dies-at-the-relay-mid-row
description: TRAP (0.90.53→54): g2/g4 lap chains run as Bash background tasks died with the session at 17:40, mid-row, leaving paths cut and run.sh stuck.
metadata:
  type: feedback
---

A lap chain (tests/mpath/lap_chain.sh, board chains, run.sh) launched with the Bash tool's run_in_background is a child of the session and is killed when the session ends or relays. Observed at a ccloop relay: g2 (path_peer_withdrawn) and g4 (path_fenced_return) chains stopped writing at the session end, mid-fault, with SAN links possibly left down, loads left on nodes, and the next session found nothing running and a stale board row (ABORTED/NOT RUN).

How to apply:
- Launch rig chains detached: `nohup setsid tests/mpath/lap_chain.sh laps ... > tests/evidence/lapchain_<tag>.out 2>&1 < /dev/null &` (nohup and setsid are in the project allowlist). Wait on them with a separate run_in_background `timeout <budget> tail -F <chain log> | grep -m1 VERDICT`, which may die harmlessly.
- To stop a detached chain: `kill -TERM -- -<pgid>` (the setsid leader's pid); run.sh traps TERM and may linger on a pipe read with no children — check /proc/<pid>/wchan and KILL it. Then `scripts/san_net.sh link <node> a|b up` and `mute ... off` on every node of the group, because a row killed mid-fault leaves its cut in place.
- After a relay, check the evidence dir mtimes before trusting that a lap is still running.
