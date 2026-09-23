---
name: trap-awareness-track-hook-only-sees-edit-write-not-bash-heredoc
description: TRAP (sess480): appending to an awareness doc with `cat >>` never registers — the track hook is PostToolUse on Edit|Write only, so sync keeps reporti…
metadata:
  type: feedback
tags: [awareness, hooks, trap, docs]
---

# Updating an awareness doc via Bash does not count

The project-awareness enforcement is two hooks
(`~/.claude/skills/project-awareness/scripts/awareness_hooks.py`):

- **`track`** — PostToolUse on **`Edit|Write|MultiEdit`**. It records which
  source files and which awareness docs were touched this session, into
  `.claude/awareness/.state/touched-<session>.json`.
- **`sync`** — Stop. Computes drift: subsystems whose **source** changed this
  session but whose **subsystem doc was NOT edited**, and BLOCKS the stop.

The consequence, learned the slow way in sess480: appending to
`.claude/awareness/subsystems/tools.md` with a Bash heredoc

    cat >> .claude/awareness/subsystems/tools.md <<'EOF'
    ...
    EOF

writes the file perfectly, leaves its mtime **newer** than the source files, and
**still leaves the drift unresolved** — because `track` never fired, so the
ledger has no record that the doc was touched. The Stop hook re-fires with the
same message no matter how much correct prose was added, and re-reading mtimes
to work out why is a dead end: drift is computed from the session ledger, not
from timestamps.

**Use the `Edit` or `Write` tool on awareness docs.** Same reason RULE 7 says to
use `Read` for source: the hooks are attached to the dedicated tools, and a
shell equivalent that produces the same bytes does not produce the same
side effects.

Corollary worth remembering generally: in this harness, *which tool* performed a
file operation is itself semantic. `sed -i`, `cat >>` and a heredoc are
invisible to PostToolUse hooks; ccmemory's injection (on `Read`) and the ledger
guard (on ledger writes) have exactly the same property.
