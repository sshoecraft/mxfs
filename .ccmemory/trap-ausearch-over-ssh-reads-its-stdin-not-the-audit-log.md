---
name: trap-ausearch-over-ssh-reads-its-stdin-not-the-audit-log
description: TRAP (0.89.91): ausearch without --input-logs reads stdin when it is a pipe (always, over ssh): AVC checks counted nothing, and it blocks on open std…
metadata:
  type: feedback
tags: [harness, selinux, ssh, trap]
---

ausearch reads its STDIN instead of the audit log whenever stdin is a pipe (is_pipe(0)). Over ssh without -n the remote stdin is always a pipe fed from the caller's stdin.

Consequences seen in MXFS harnesses (selinux_svirt_mxfs.sh, packaged_round.sh selinux step):
- the "zero AVC denials" check never read /var/log/audit: it counted an empty stream and always passed. Positive control on alma9-1: old form found 0 USER_LOGIN records (and blocked 9.8 s on a 10 s open pipe); `ausearch --input-logs ... </dev/null` found 73 in 36 ms.
- it blocks for as long as the caller's stdin stays open (open 25 s pipe held it 24.8 s); killing the ssh client releases it — the remote shell then carries on with the next command.

Rule of thumb: every remote ausearch gets `--input-logs` and `</dev/null`. Same class: any tool that auto-detects "stdin is a pipe" (ausearch, aureport) behaves differently under ssh than at a terminal.
Background Bash tool calls here get stdin=/dev/null (readlink /proc/<pid>/fd/0), so the blocking form cannot fire from them — only from a caller with an open stdin.
