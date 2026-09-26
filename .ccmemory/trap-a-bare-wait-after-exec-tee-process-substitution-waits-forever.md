---
name: trap-a-bare-wait-after-exec-tee-process-substitution-waits-forever
description: TRAP (0.89.93): in a script that did exec > >(tee log), a bare `wait` also waits for the tee and hangs forever; wait on the collected PIDs.
metadata:
  type: feedback
tags: [harness, bash, trap]
---

tests/unmount_agrelease_window.sh ran its per-node jobs with `( ... ) &` and then `wait`. The script had started with `exec > >(tee -a run.log) 2>&1`; that process substitution is a child of the shell, and a bare `wait` waits for it too — tee never exits, so the lap hung after the workload until the outer timeout killed it, with the evidence half-written. Collect `PIDS="$PIDS $!"` and `wait $PIDS`.

Related capture trap from the same lap: with thousands of held files the kernel ring overflowed before the harness read it, so `dmesg | awk '/MARK/,...'` found neither the marker nor the P483 line; journald had also dropped the marker in the same burst. Read `journalctl -k --since=@<lap start>` instead of dmesg-after-marker for any lap that generates heavy probe traffic.
