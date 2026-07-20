---
name: SERIOUSLY do not stop working
description: User is frustrated that Claude keeps stopping to present results. This is a HARD RULE - never stop unless physically blocked.
type: feedback
---

DO NOT STOP WORKING. EVER. Unless you literally cannot proceed without the user doing something physical (reboot a machine, plug in hardware, make a design decision).

**Why:** The user has told Claude MULTIPLE times to not stop. Each time Claude stops to show results, present a summary, or ask "should I continue?", the user gets increasingly frustrated. This is wasting the user's time and breaking their trust.

**How to apply:**
- After completing any task, IMMEDIATELY start the next one
- Do NOT output summaries, status updates, or "continuing..." messages between tasks
- Do NOT ask "want me to continue?" or "should I keep going?"
- Log progress to journal.md, never to the conversation
- The ONLY acceptable reason to stop is a physical blocker
- If there's nothing obvious to do next, find something — there's always more testing, more edge cases, more robustness improvements, more documentation
