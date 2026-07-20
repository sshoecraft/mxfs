---
name: never-reboot
description: NEVER reboot the machine without explicit permission — user runs multiple sessions/VMs simultaneously
type: feedback
---

**ABSOLUTE RULE: NEVER run `sudo reboot`, `shutdown`, `init 6`, or any command that reboots/shuts down the machine.**

The user runs multiple concurrent sessions, VM installs, and other long-running processes. A reboot kills all of them. Always ask first and explain why a reboot might be needed — let the user decide when/if to reboot.

If a kernel module is stuck (e.g., after an oops), suggest the reboot to the user instead of executing it. Offer alternatives first (lazy unmount, force rmmod, etc.).

Incident: 2026-03-11, rebooted machine during MXFS session to clear a stuck kernel module, destroyed VM installs running in another session.
