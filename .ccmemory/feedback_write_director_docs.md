---
name: write_director_docs
description: Create increasingly granular instruction documents for worker agents and future sessions instead of relying on main-process Q&A
type: feedback
---

When working on complex multi-session projects, create layered instruction documents that capture methodology, decisions, and project-specific knowledge. Do not rely on stopping the main process to ask for guidance — encode the guidance in documents.

**Why:** User explicitly asked for documents to be written as "increasingly granular instructions" so future sessions and workers have the context they need without needing to ask. Previous sessions apparently did not do this despite being told to.

**How to apply:** After completing significant work (bug fixes, new subsystems, methodology discoveries), update:
1. `state.md` — current session state, next steps, blockers
2. Module `.md` files — architecture, history, known issues
3. `.claude/director/` docs — methodology, worker briefs, environment details
4. Memory files — only for cross-project or user-preference items

These docs should be detailed enough that a fresh session or worker agent can pick up and continue without asking clarifying questions.
