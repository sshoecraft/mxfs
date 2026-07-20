---
description: "Regenerate the structural map from current source code"
---

# Refresh Structural Map

Regenerate `.claude/awareness/structural-map.md` from current source.

1. Run the structural map generator:
   ```bash
   python3 ~/.claude/skills/project-awareness/scripts/generate_structural_map.py ./ --verbose
   ```

2. Review the output — report what changed (new/removed/changed functions).

3. Update [AWARENESS] section in CLAUDE.md with new date and token count.

If the user specifically requests a Mermaid call graph, add `--mermaid` to the command above,
or run separately:
```bash
python3 ~/.claude/skills/project-awareness/scripts/generate_mermaid_callgraph.py \
    .claude/awareness/structural-map.md --cross-subsystem-only \
    -o .claude/awareness/structural-map.mermaid
```
