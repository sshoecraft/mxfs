---
name: Don't stop for intermediate results
description: Keep working autonomously, log progress to journal.md instead of stopping to show user
type: feedback
---

Don't stop to show intermediate results. Keep implementing and testing autonomously.

**Why:** User wants continuous progress toward a complete product. Stopping to present results wastes time and breaks flow. User will check progress on their own.

**How to apply:** Write progress updates to `/src/mxfs/journal.md` as work proceeds. Only stop when something requires the user's physical intervention (reboot a node, hardware, critical design question). Keep going through all features, fixes, and VM testing until the product is complete and ready for physical server testing.
