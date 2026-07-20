---
name: Keep trace instrumentation permanent
description: Use compile/runtime-toggleable trace macros instead of ad-hoc printk add/remove cycles
type: feedback
---

Do NOT remove trace/debug log lines after debugging. Instead, use a permanent trace macro system (like MXFS_TRACE) that can be enabled/disabled at compile time or runtime. The old codebase (~/src/mxfs.old) had this — Claude Code created a macro for tracing that could be toggled, with extensive trace points throughout the code. Traces were captured via `dmesg -w > file`.

**Why:** Ad-hoc printk insertion/removal wastes an entire worker round-trip per debug session. Permanent trace points accumulate institutional knowledge about what's worth observing.

**How to apply:** When adding debug instrumentation, wrap it in a trace macro and KEEP it in the code. When porting from mxfs.old, bring the trace macro system along.
