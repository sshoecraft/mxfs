---
name: trap-sudo-mpath-up-leaves-root-owned-passfile
description: After `sudo mpath_up.sh`/any sudo harness call, /tmp/.mxfs_pass may be root:600 — steve's sshpass then HANGS silently at a password prompt. sudo rm +…
metadata:
  type: reference
---

## Symptom

`./run.sh N caw ...` produces ZERO output and hangs forever (or a bare
`tools/mxfs_sshpass.sh testN cmd` hangs) while ping to the node is fine and
`mpath_up.sh` just succeeded. bash -x trace stops at the first `ssh_node`.

## Cause

`tools/mxfs_secrets.sh passfile` materializes `/tmp/.mxfs_pass` as the CALLING
user. Running `sudo -E bash scripts/mpath_up.sh up 32` (the documented rig
recovery) creates it as **root:600**. The unprivileged harness's sshpass then
cannot read it; sshpass falls through to an interactive password prompt that
never returns. After a clyde reboot /tmp is empty, so the first creator wins —
and the recovery sequence's first creator is the sudo call.

## Fix (seconds)

    sudo rm -f /tmp/.mxfs_pass
    tools/mxfs_secrets.sh passfile     # as steve
    ls -la /tmp/.mxfs_pass             # must be steve:steve 600

Seen sess386 (2026-08-21) after the post-wedge host reboot: cost one 400s
silent prep timeout before diagnosis.
