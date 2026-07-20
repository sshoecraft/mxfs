---
name: No next-session-prompt.md file
description: At session end, print the next-session prompt directly to the screen — do NOT write it to /src/mxfs/next-session-prompt.md or any other file
type: feedback
originSessionId: 89133fcd-a031-4a52-b3b3-d1581bd5ed89
---
Do not write a `next-session-prompt.md` file (or any equivalent handoff file) at the end of a session. Print the prompt directly to the chat output instead so the user can copy it.

**Why:** The user reads the prompt off the screen and starts the next session manually. Writing it to a file is redundant work, and the file then auto-replays directives like "Use the deep-focus skill" on every subsequent session, polluting context.

**How to apply:** When wrapping up a session (context handoff, "save state", end-of-work summary, etc.), generate the next-session prompt as plain chat text only. Still update `state.md` with technical state — that file IS useful — but the *prompt itself* is screen-only. If `next-session-prompt.md` already exists in the project, leave it for now unless the user asks to delete it.
