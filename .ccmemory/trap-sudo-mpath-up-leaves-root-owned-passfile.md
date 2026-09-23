---
name: trap-sudo-mpath-up-leaves-root-owned-passfile
description: FIXED IN TOOLING sess452: root:600 /tmp/.mxfs_pass (from any sudo'd harness) made steve's sshpass 1.09 HANG; wrapper now checks -r, secrets falls bac…
metadata:
  type: feedback
tags: [rig, ssh, sshpass, sudo, trap]
---

# Root-owned passfile hangs every fleet ssh (proven sess452, root cause of the sess451 chain-70 prep hang)

## Mechanism
- Any harness run under `sudo` (rig-runner's `mpath_up.sh` at 21:44Z sess451) materializes `/tmp/.mxfs_pass` as **root:600**.
- `tools/mxfs_sshpass.sh` tested `[ -s ]` (true for the unprivileged caller — stat works, size 8) and handed the path to sshpass.
- **sshpass 1.09 prints `SSHPASS: Failed to open password file "/tmp/.mxfs_pass": Permission denied` to stderr and then HANGS** on the password prompt (does not exit). With stderr piped through `tail` nothing appears until the outer timeout kills it: rc=124, zero output.
- Symptoms that discriminate it: `ssh -o BatchMode=yes root@node true` answers instantly (Permission denied), ping OK, port 22 open, VMs running — only the sshpass path stalls.

## Fix (sess452, in tree)
- `tools/mxfs_sshpass.sh`: readability test (`! -r || ! -s`) triggers re-materialization; if still unreadable, **refuse with exit 96** and a clear stderr line instead of letting sshpass hang.
- `tools/mxfs_secrets.sh secrets_passfile`: if the path exists, is not ours (`! -O`) and is unreadable/unwritable, materialize `${path}.uid$(id -u)` instead and print that path.
- Verified: root-owned probe file -> resolved `/tmp/.mxfs_pass_probe.uid1000`, ssh OK; with no secrets store -> rc=96 immediately.
- Immediate unblock used: `sudo -n chown steve:steve /tmp/.mxfs_pass`.

## Trap for diagnosis
When fleet ssh "hangs" after a subagent sweep, check `ls -l /tmp/.mxfs_pass*` FIRST.
