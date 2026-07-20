---
name: infra-timeout-orphans-hold-run-lock-not-rival-session
description: The "/tmp/mxfs_run.lock held by another run.sh" error can be caused by YOUR OWN timeout-orphaned per-node ssh children, not a rival ccloop session --…
metadata:
  type: project
---

## What happened (ccloop 703f15c3 sess1, 2026-07-12)

Spent a long stretch chasing what looked like a rival ccloop session fighting for
the 8-node cluster: `/tmp/mxfs_run.lock` contention with a fresh PID every 1-2
minutes ("steve PID run.sh" + "steve PID tail"), 4-8 nodes simultaneously failing
"did not release mxfs" during prep, `virsh domstate`/ssh calls hanging for the full
2-minute tool timeout on specific nodes.

Initial hypothesis (WRONG): a genuinely separate, independent `claude` process
(found via `ps -ef --forest`, PID running for hours) was a rival ccloop session on
this same project. **Verified false** by checking `readlink /proc/<pid>/cwd` — it
pointed at `/src/aitrader` (a completely different project under a different Linux
user, `itrader`). A second suspect PID (`--session-id ... /home/itrader/.local/...`)
was also aitrader, not mxfs. Don't skip this check — a `claude` process with high
uptime on the same host is NOT evidence it's touching your project.

## Actual root cause

My OWN `scripts/repro_dblreclaim.sh` loop's `timeout 1720 ./run.sh ...` fired
mid-test (fence_during_write stragglers on 2-3 nodes past the outer budget).
`timeout` only signals the DIRECTLY-invoked process (the top-level `run.sh`), not
its whole process tree. `run.sh` forks each node's ssh call with `&`
(`( timeout "$tt" "$SSH" "$n" "$PASS" "..." ) &`) — those backgrounded children are
NOT a new session/process-group, so killing/timing-out the parent does not touch
them. They become orphans (PPID=1) and keep running: a real, live ssh connection
to the remote node, remote bash still executing the test script.

The killer detail: `run.sh` takes its exclusive lock via `exec 9>"$RUNLOCK"; flock
-n 9` in the top-level shell — and **bash-forked `&` children inherit open file
descriptors, including fd 9**. So even after the top-level `run.sh` that acquired
the flock is long dead, an orphaned descendant that inherited fd 9 keeps the flock
held. A LATER run.sh's own `flock -n 9` then fails intermittently — exactly
matching the observed pattern (a live holder that vanishes by the time you `ps` it,
because it's actually a short-lived grandchild in the orphaned tree, not one fixed
process).

My first cleanup attempt only killed the outer `timeout`/`mxfs_sshpass.sh` wrapper
layer (e.g. PIDs from `pgrep -af "mxfs_sshpass.sh test"`), which EXEC's into a bare
`sshpass ssh ...` process — after the exec, the process's own cmdline no longer
contains the string "mxfs_sshpass.sh", so that pattern stops matching the actual
survivor. The real fix needed `pkill -9 -f "ssh.*root@test.*<suite-script>.sh"`
(or killing every PID in the full local process tree) AND killing the matching
remote process via a fresh ssh (`pgrep -af 'fence_during_write|dir_reuse_coherency'`
per node, then `pkill -9 -f <name>` remotely — a killed local ssh client does NOT
kill the remote bash, per run.sh's own RULE-0 cascade-guard comment).

Confirmed fixed by: `flock -n /tmp/mxfs_run.lock -c "echo LOCK_IS_FREE"` succeeding
only after killing ALL of: the orphaned local sshpass/ssh PIDs (every layer, not
just the wrapper) AND (belt-and-suspenders) power-cycling any node that wouldn't
respond to ssh/pkill within a normal timeout.

## Takeaway for future sessions

When `/tmp/mxfs_run.lock` reports a holder that's already gone by the time you
check:
1. Don't assume a rival ccloop session — verify with `readlink /proc/<pid>/cwd`
   for ANY claude process before treating it as a suspect. It's very likely a
   different project (this host runs multiple concurrent projects/users).
2. Check for YOUR OWN orphaned test-infra processes first:
   `ps -eo pid,ppid,user,etimes,cmd | grep -iE "run\.sh|mxfs_sshpass|<suite-name>"`
   — if you see PIDs with PPID=1 (reparented to init) and a `sshpass`/`ssh` command
   line (not necessarily containing the wrapper script's name, since exec replaces
   the cmdline), those are likely fd-9 lock leakers from a PAST timeout.
3. Kill by exact PID (`kill -9 <pid>`), not by a name pattern that only matches
   the pre-exec wrapper.
4. Also kill the matching remote process per node (`pgrep -af <suite-script>` then
   `pkill -9 -f <suite-script>` via a fresh ssh call) — the orphaned LOCAL ssh
   client dying does not stop the REMOTE bash.
5. Verify with `flock -n /tmp/mxfs_run.lock -c "echo LOCK_IS_FREE"` before
   relaunching.
6. If any node won't respond to ssh/pkill within ~10-15s, just power-cycle it
   (`virsh -c qemu:///system destroy/start <node>`, RULE 2 permits test-VM
   cycling) rather than fighting it further — cheaper than more diagnosis.

This is a NARROWER, more mechanistic companion to
`infra-ccloop-leaves-stale-sessions-alive-KILL-AT-START` (which is about a whole
rival `claude` process surviving a ccloop relay) — this note is about a single
run.sh invocation's OWN orphaned children outliving it after an outer timeout,
even with zero rival sessions involved.
