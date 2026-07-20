---
name: Never reboot nodes
description: NEVER reboot any node/server without explicit user confirmation — always ask, never act
type: feedback
---

NEVER reboot a node. Ever. Ask the user to reboot it if needed, but do not issue the reboot command yourself.

**Why:** Rebooting a remote server is destructive and can cause cascading issues (iSCSI reconnection, stuck mounts, data loss). In Session 48, an unauthorized reboot of serv (192.168.1.5) was issued to clear a D-state process, without asking first.

**How to apply:** When a D-state process or stuck module requires a reboot, explain the situation and ask the user to perform the reboot themselves. Never run `reboot`, `shutdown`, `init 6`, or any equivalent command on any node.
