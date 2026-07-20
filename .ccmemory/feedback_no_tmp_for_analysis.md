---
name: Don't save session-persistent analysis to /tmp
description: Analysis/scratchpad files that must outlive a reboot belong in the project dir, not /tmp
type: feedback
originSessionId: 92758226-a92c-4666-8d95-34447dc82c55
---
Analysis docs, design notes, and scratchpads for ongoing multi-session work go in the project directory (e.g. `/src/mxfs/analysis-<topic>.md`), NOT `/tmp/analysis.md`.

**Why:** /tmp gets wiped on reboot. The MXFS bug under investigation has already eaten one session attempting a fix; this work spans sessions and the analysis must survive. The deep-focus skill suggests "/tmp/analysis.md OR <project>-analysis.md" — for MXFS, always pick the project-dir form.

**How to apply:** When writing a deep-focus scratchpad or any multi-session design doc, write to the project root or a docs/ subdir. The global CLAUDE.md "NEVER put temporary files in project dir — use /tmp" rule applies to *throwaway* test scripts and temp data, not to design/analysis docs that must persist.
