---
name: state-md-deprecated-do-not-maintain
description: USER DIRECTIVE sess35: state.md is a legacy artifact of the pre-ccloop/pre-ccmemory handoff system — do NOT read or maintain it
metadata:
  type: user
tags: [directive, workflow, state-md, handoff]
---

# state.md is deprecated (user directive, 2026-07-31, wrapper session 17)

The user: "state.md is an artifact of a previous system."

It was the manual session-handoff document from before ccloop + ccmemory existed. This run's original prompt says "read state.md", so every fresh session tends to resurrect it. **Do not.**

Where each of its roles now lives:
- **Session handoff / resume program** → ccloop's auto-generated resume summary (from the transcript). Make sure the final turn before a relay states the program clearly in plain text.
- **Cross-session durable knowledge** → ccmemory (`memory_write`, project/user notes).
- **Build history** → `CHANGELOG.md`.
- **Defect state + next steps per defect** → `tests/criteria/OPEN_DEFECTS.json` (the authority).

Do not write to state.md at relay boundaries. Do not treat its contents as current (last meaningful update: sess35; it will only rot from here). Deleting it is the user's call — leave the file alone.

Current program at the moment of deprecation (so nothing is lost from the last state.md write): (1) finish boarding 0.11.302 — chunks A–C done, 15 PASS / 1 FAIL (dir_reuse pace 7/8 rounds), chunk D pending (node_responsive kernel_health ag_strand_repair sustained_load dirent_publish_integrity dirent_type_integrity) plus P1 rows; (2) FIX-A terminal-store TOCTOU (in-flight-FIX-25-ioend counter + pend==durable re-check, Gemini P2, D-RELEASE-BARRIER); (3) B3/C injection verification (Gemini A/B plan); (4) dir_reuse pace = protocol-IO reduction (ledger next_step); (5) ledger backlog (SILENT-MKDIR reproducer, UNMOUNT-BUSY audit, MATRIX, FOREIGN-REPLAY, CAW-YIELD review, CAW orphan-grant reap on next capture).
