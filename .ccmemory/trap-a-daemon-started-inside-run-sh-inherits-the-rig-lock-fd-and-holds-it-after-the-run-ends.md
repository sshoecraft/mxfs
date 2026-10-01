---
name: trap-a-daemon-started-inside-run-sh-inherits-the-rig-lock-fd-and-holds-it-after-the-run-ends
description: TRAP (0.90.37): netconsole socat started by run.sh prep kept fd 9 on /tmp/mxfs_run.lock from PPID 1; next run saw a holder. Close fds >2 before nohup.
metadata:
  type: feedback
---

**What happened.** After a `run.sh 2/disk/caw/mpath prep_cluster` exited, `/tmp/mxfs_run.lock` was still held. `fuser -v` named `socat -u UDP-RECV:6666` (PPID 1). That is the netconsole panic listener, which `tools/netconsole_listen.sh start` launches with `nohup … &` from inside run.sh's prep, so it inherited run.sh's `exec 9>"$RUNLOCK"`. `/proc/<pid>/fd` showed the lock file among its descriptors.

**Why it was invisible.** The old exclusive lock path "reaps orphans" when no run.sh is alive, so every next whole-rig run silently killed the panic listener, then prep restarted it. A shared-mode (rig-group) lock just failed.

**Rule of thumb.** Anything run.sh (or any lock holder) starts that must outlive it closes its inherited descriptors above 2 before launching (`for fd in /proc/$$/fd/*; …; exec $fd>&-`). Rig-group runs hold dynamic fds (`exec {fd}>>`), not just fd 9. Verify with `ls -l /proc/<pid>/fd` (safe), never `/proc/<pid>/cmdline`.
