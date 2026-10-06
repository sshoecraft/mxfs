---
name: trap-a-bash-c-chain-that-runs-a-function-with-dollar-at-is-refused-by-the-rm-safety-check
description: TRAP: nohup setsid bash -c '... step(){ "$@"; } ...' was refused as a possible rm (unresolvable command). Spell each command out; a for-loop over arg…
metadata:
  type: feedback
tags: [claude-code, safety-check, rig, bash]
---

A detached rig chain launched as `nohup setsid bash -c 'step() { echo ...; "$@"; echo rc=$?; }; step scripts/drbd_rig.sh x; ...'` was refused by Claude Code's built-in removal safety check: it cannot resolve what `"$@"` runs, so it treats the -c script as possibly running `rm`. The refusal cannot be approved in an unattended session.

**How to apply:** in a `bash -c` script, never execute a variable as the command. Use a fixed command with variable arguments, e.g. `for s in "self-outage-test" "takeover-test self"; do scripts/drbd_rig.sh $s; done`, and branch with `if` for an env-prefixed variant (`SELF_OUTAGE_PEER_PRIMARY=1 scripts/drbd_rig.sh self-outage-test`). Also: `cmd && L=x && nohup ... &` backgrounds the whole && list, so `$L` is unset afterwards in the parent; separate with `;`.
