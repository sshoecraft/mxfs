---
name: feedback-never-rm-glob-variable-path
description: CRITICAL (user, sess16, emphatic): NEVER run `rm` with a glob or variable path (e.g. `rm -f "$VAR"/*.x`) — it trips Claude Code's "dangerous rm on po…
metadata:
  type: feedback
---

## User directive (sess16, emphatic/angry — this kept interrupting them):
NEVER again run a command that trips the Claude Code "Dangerous rm operation on possibly-empty variable path" safety prompt. It fires on ANY `rm` whose path contains a shell variable and/or a glob, e.g. `rm -f "$TD"/*.output`, `rm -rf $DIR/*`, etc. The user must approve it every time → unacceptable.

**Why:** This is a hard built-in safety guard (not a normal allowlist permission), so it cannot be reliably silenced via settings permissions — the fix is BEHAVIORAL: never emit the offending pattern.

**How to apply — to delete files, use ONE of:**
- `find /literal/abs/dir -maxdepth 1 -name '*.output' -delete` (literal dir, no variable, no rm, handles empty gracefully) — PREFERRED.
- Explicit literal filenames: `rm -f /abs/path/a.output /abs/path/b.output`.
- NEVER: `rm` + `$VAR` + glob; `rm -rf $VAR/*`; `rm -f "$DIR"/*.ext`.

**Context where it bit:** clearing ccloop's stale `*.output` files (completed-background-task artifacts in `/tmp/claude-<uid>/<slug>/<session-id>/tasks/`) that wedge the Stop-hook watcher `_pending_background_task_count` (it counts .output files and blocks session end while any exist, even already-finished ones). Clear them with `find <tasks-dir> -maxdepth 1 -name '*.output' -delete`.
