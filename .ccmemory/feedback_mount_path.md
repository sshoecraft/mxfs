---
name: MXFS mount path
description: Always mount MXFS on /mnt/shared, not /mnt/bench or other paths
type: feedback
---

Always use /mnt/shared as the mount point for MXFS testing.

**Why:** Consistency across sessions and tests. The user corrected use of /mnt/bench.

**How to apply:** Any mount command for MXFS or benchmark testing should use /mnt/shared.
