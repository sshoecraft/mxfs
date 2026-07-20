---
name: feedback_minimize_gemini
description: "Gemini is OK when genuinely stuck (worth the cost to finish the project); just don't call it routinely."
metadata: 
  node_type: memory
  type: feedback
  originSessionId: f4befd6e-fdd3-459a-bf58-c7cbc7310079
---

User (sess25-of-run, 2026-06-03) interrupted to say the Gemini calls cost real money and the relay loop has been invoking `mcp__ask_gemini__query` far too often (sess55/60/63/64 all consulted it; the automated loop kept hitting CLAUDE.md RULE 5's "consult after 2-3 failures" because this AG-coherency class has failed ~10 sessions).

**Why:** Each ask_gemini call is billed; the loop was treating RULE 5 as "call Gemini whenever a class is hard" rather than "only when genuinely blocked with no path of my own."

**CLARIFICATION (sess26-of-run, 2026-06-03):** User clarified — "I don't mean not to call Gemini at all. You can definitely call Gemini, especially if you're stuck. It does cost me money, but it is worth it if we are able to finally complete this project." So Gemini is AUTHORIZED when genuinely stuck; it just must not be a routine/reflexive step.

**How to apply:** Do NOT call ask_gemini (or ask_flash) reflexively or for an unsolicited "second opinion." DO call it when you have genuinely exhausted your own cheap measurements AND face a deep/architectural blocker — that's worth the cost to finish. Default loop: read the code, instrument, measure (RULE 4), form your own fix; escalate to Gemini with a concrete evidence package (refuted hypotheses + decoded detector output) when stuck. Always OMIT max_tokens (RULE 5: capping truncates the answer). sess26 followed this well: refuted 3 hypotheses by measurement first, THEN consulted with hard evidence — Gemini's answer (Theory D drain-leak + decisive double-FUA-read experiment) was high-value. Related: [[reference_ship_criteria]].
