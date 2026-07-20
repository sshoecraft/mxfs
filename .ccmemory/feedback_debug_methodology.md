---
name: Debug methodology
description: Required debugging workflow — analyze, hypothesize, instrument, then change only if proven
type: feedback
---

Never make code changes to fix a bug without first proving the hypothesis with instrumentation.

**Required workflow:**
1. **Analyze** — observe the symptom, read the relevant code paths
2. **Hypothesize** — form a specific theory about the root cause
3. **Instrument** — add `pr_debug()` (not raw printk) to prove/disprove the hypothesis
4. **Only then change** — if instrumentation confirms the hypothesis, make the fix

**Why:** Jumping straight to "fixes" without proof leads to wrong fixes, wasted time, and code churn. Instrumentation should use `pr_debug()` so it stays in the code permanently (compiled out unless dynamic debug is enabled). Never add raw `printk` that needs to be removed later.

**How to apply:** Every time a bug is encountered, state the hypothesis explicitly before writing any instrumentation. If the instrumentation disproves the hypothesis, form a new one — don't just shotgun changes.
