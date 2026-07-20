---
name: feedback_kill_builds
description: Never use kill -9 on mkosimage/packer builds — use normal SIGTERM so cleanup hooks run
type: feedback
---

When killing mkosimage/packer build processes, use plain `kill` (SIGTERM), NEVER `kill -9` (SIGKILL).

**Why:** mkosimage and packer have cleanup handlers that remove temp files and destroy partially-created VMs on graceful termination. SIGKILL bypasses all cleanup, leaving orphaned VMs and temp files that must be manually cleaned up.

**How to apply:** Any time a build needs to be cancelled, send SIGTERM and wait for the process to exit cleanly.
