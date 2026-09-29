---
name: trap-a-backgrounded-umount-inherits-the-ssh-sessions-stdio-so-a-stuck-unmount-hangs-the-harness-into-an-abort
description: TRAP (0.90.22): `( umount ... ) &` inside an ssh command keeps ssh open while the umount hangs; the lap ended ABORT rc=124 with no log capture.
metadata:
  type: feedback
tags: [harness, ssh, umount, stall, evidence]
---

# A backgrounded umount inherits the ssh session's stdio

**What happened (0.90.22, `tests/quiesce_remount_access.sh`, lap `v22c_lap11`):**
the remote script ran `( umount $MNT; echo ... > file ) & up=$!`, polled it for
60 s, printed `UMOUNT_STUCK after=60s` and exited.  The unmount was stuck in
the kernel for 127 s.  The backgrounded subshell still held the ssh session's
stdout and stderr, so ssh did not return when the script did; the caller's
90 s bound killed it (rc=124), the capture gate saw a failed capture and the
lap ended `RESULT: ABORT stage=capture` instead of a graded FAIL.  The abort
path pulls no kernel logs, so the stall's own reports (the unmount's stuck-AIL
lines) survived only because the node's ring was read by hand minutes later.

**How to apply:**

- Anything backgrounded inside an ssh command that may outlive the script gets
  its stdio cut: `( ... ) > /dev/null 2>&1 < /dev/null &`.  The result travels
  through a file the script reads back, never through the inherited pipe.
- A step that can hang needs a log capture on ITS failure path, not only on the
  first one: the second quiesce had none (`klog stall2` added).
- When a lap ABORTs at a capture stage, read the node's kernel ring at once;
  at this log volume a rig node's ring holds about four minutes.
- `rc=124` from the remote-shell wrapper with the expected marker line in
  stdout means the script finished and the session did not: look for an
  inherited descriptor before suspecting the node.
