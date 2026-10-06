---
name: trap-an-outer-timeout-below-the-wrapped-operations-own-bound-kills-it-just-before-it-reports-why
description: TRAP (0.90.64→65): boot program bounded mount at 180 s; module's own refusal due at ~184 s (scan 64 + fence 120). Kill → exception → no retry ever.
metadata:
  type: feedback
tags: [drbd, boot, timeout, retry]
---

The DRBD boot program (`tools/mxfs_drbd_fence_self.py`, `cmd_boot`) ran `mount` under `subprocess.run(..., timeout=180)`. After a pair outage the module bounds its own waits: bootstrap scan ~64 s (dead-heartbeat window) + DRBD startup fence `V5_DRBD_STARTUP_FENCE_MS` 120 s + replay. Measured on rig test2: the program killed the mount at +180 s (`P-BOOT-MOUNT-REFUSED rc=-4`), 3 s before the module would have refused with its reason. The `TimeoutExpired` escaped `cmd_boot`, `main()` returned 1, and the 6-attempt step-down-and-retry loop never ran: node left Primary, pair needs an operator.

**Why:** an outer bound below the inner component's own worst case converts a clean, explained refusal into a kill with no reason, and an exception path that bypasses the retry loop turns one slow attempt into a permanent failure.

**How to apply:**
- When wrapping a kernel operation (mount, recovery) that bounds itself, sum its own bounds and set the outer bound past that sum; say the sum in a comment.
- Catch the timeout as a failed attempt inside the retry loop; never let it escape the loop.
- Exercise the retry path in a test (here `SELF_OUTAGE_PEER_PRIMARY=1 scripts/drbd_rig.sh self-outage-test`); a retry loop nobody has driven to its second attempt is unverified.
