---
name: Use test1/test2, not T1/T2
description: When referring to the MXFS test cluster nodes, use test1 and test2 (the actual hostnames), not T1/T2 abbreviations. Applies to dmesg analysis, state.md, lessons files, and any prose.
type: feedback
originSessionId: fee3092a-f2cc-45d5-a973-ff759a2cf5d3
---
Use `test1` (192.168.120.186) and `test2` (192.168.120.182) — the actual hostnames — when referring to the MXFS test cluster nodes.  Do NOT abbreviate as `T1`/`T2`.

**Why:** User preference (sess33).  Consistent with hostnames as they appear in `bench/rsync_bench.sh` output, ssh prompts, and `mount` listings.  Past sessions (state.md, sess32_lessons.md, sess33_lessons.md) used T1/T2 extensively — those existing references can stay, but new prose should use test1/test2.

**How to apply:** All future state.md edits, lessons files, dmesg commentary, bench summaries, and conversational responses use the full hostname.  When updating existing T1/T2 references during edits, also rename them to test1/test2 if the surrounding text is being rewritten anyway.
