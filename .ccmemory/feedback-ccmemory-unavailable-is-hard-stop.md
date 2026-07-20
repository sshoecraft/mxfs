---
name: feedback-ccmemory-unavailable-is-hard-stop
description: ccmemory (or its MCP transport) being unavailable is ALWAYS a hard stop — never rationalize it as benign.
metadata:
  type: feedback
---

**Rule (user directive, sess after session-78 handoff):** If ccmemory — or the MCP tool interface that exposes it — becomes unavailable / "disconnected" mid-session, treat it as a **HARD STOP. ALWAYS.** Do not continue working as if nothing happened, and do not rationalize it away.

**Context / what triggered this:** A prior session saw the harness drop the MCP transport (it batched ccmemory + ccteam + ask_gemini + searxng + ccusage into one "disconnected" notification) and concluded "not a hard stop, no memory loss" because ccmemory's data is flat `.md` files on disk and the server is just a query layer. The user explicitly **overrode** that conclusion: ccmemory being unavailable IS a hard stop, every time.

**Why:** Memory is load-bearing for this project's multi-session ccloop work. Without ccmemory you cannot reliably recall prior lessons, you may re-derive things already solved, and (critically) the regen-index hook won't fire — bypassing `memory_write` with direct file writes leaves `MEMORY.md` stale and risks silent divergence. The user does not accept "the files are still on disk" as a reason to keep going.

**How to apply:** The moment ccmemory / its MCP interface drops, STOP. Report that ccmemory is unavailable and that this is a hard stop per user directive. Do not proceed with substantive work, do not write memories via direct file writes as a workaround-and-continue, and do not declare "no memory loss, carrying on." Surface it and halt.
