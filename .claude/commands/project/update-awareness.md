---
description: "Review and update all awareness docs based on recent codebase changes"
---

# Update Awareness Docs

Maintenance pass — not a full bootstrap.

1. **Check drift**: Read [AWARENESS] last-updated date. Run `git log --since="{date}" --stat --oneline`.
   Identify which subsystems had files modified.
2. **Update affected subsystem docs**: Read current doc, read diffs, update API, pitfalls,
   dependencies, clean up Session Notes.
3. **Update CLAUDE.md if needed**: Check if subsystem list, invariants, build commands, or
   design tensions changed. Keep under 200 lines.
4. **Optionally refresh structural map**: Suggest `/project:refresh-map` if significant
   new files/functions were added.
5. **Update metadata**: Set new last-updated date in [AWARENESS] section.
6. **Report**: What was updated, flag areas needing human input.
