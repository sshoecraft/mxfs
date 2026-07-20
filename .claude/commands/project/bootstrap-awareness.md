---
description: "Analyze the project and build the three-layer awareness infrastructure"
---

# Bootstrap Project Awareness

Follow the project-awareness skill protocol. Steps:

1. **Recon**: Run the project analyzer to get a comprehensive overview:
   ```bash
   python3 ~/.claude/skills/project-awareness/scripts/analyze_project.py ./ --verbose
   ```
   Also read CLAUDE.md/README for context the analyzer can't capture (design intent, invariants).

2. **Identify subsystems**: Review the analyzer's `subsystems` array. Adjust as needed —
   merge tightly coupled subsystems, aim for 3-7 total.
   **Present to user for confirmation before proceeding.**

3. **Generate structural map**: Run the structural map generator:
   ```bash
   python3 ~/.claude/skills/project-awareness/scripts/generate_structural_map.py ./ --verbose
   ```
   This writes `.claude/awareness/structural-map.md` in compact notation.

4. **Generate subsystem docs**: For each confirmed subsystem, read key files and generate a doc
   at `.claude/awareness/subsystems/{name}.md` using the subsystem template.

5. **Update CLAUDE.md**: Add/update subsystem table, invariants, routing table,
   and [AWARENESS] section. Preserve existing content. Stay under 200 lines.

6. **Install commands**: Copy command templates to `.claude/commands/project/`.

7. **Report**: What was documented, token count of map, gaps needing human input.

CRITICAL: Always ask the user to review invariants. You will miss some. The user knows
things about the system that the code doesn't express.
