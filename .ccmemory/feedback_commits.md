---
name: Commits only when work is done/working
description: User does not want commits proposed mid-development; only commit when feature/fix is complete and working
type: feedback
originSessionId: fa77fb58-4e87-481f-bf22-0934c67b7873
---
Do not suggest committing changes mid-session or as part of session handoffs. Only propose commits when a feature/fix is fully working or the user explicitly asks.

**Why:** User said "Why release something that doesn't work?" — version control here tracks working states, not in-progress experiments. Mid-development commits add noise.

**How to apply:** When wrapping up a session with broken/in-progress code, save state to state.md and memory but do not list files-to-commit or propose `git` operations. If the user asks for a commit explicitly, follow normal commit protocol. (Note: global CLAUDE.md also bans `git` entirely unless directed.)
