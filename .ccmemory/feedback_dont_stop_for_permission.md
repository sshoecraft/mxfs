---
name: dont_stop_for_permission
description: Never stop to ask permission on obvious next steps — implement fixes, build, test, deploy in one flow
type: feedback
---

When the analysis is complete and the fix is clear, implement it immediately. Do not stop to ask "Shall I implement this?" or "Should I proceed?" — just do it. Build, test, deploy, validate in a single continuous flow.

**Why:** User explicitly called this out — stopping for confirmation on obvious work wastes time ("you always stop and wait for input for literally days or years ... for something obvious"). The user wants autonomous execution of clear next steps.

**How to apply:** After completing analysis of a bug, immediately:
1. Write the fix
2. Build
3. Deploy to test nodes
4. Run the validation test
5. Report results

Only stop to ask when genuinely ambiguous (multiple viable approaches with different tradeoffs, destructive actions on production, etc.). A bug fix with clear root cause and obvious code change is never ambiguous.
