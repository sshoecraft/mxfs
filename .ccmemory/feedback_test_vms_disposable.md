---
name: Test VMs are disposable
description: MXFS test VMs (test1..test32) can be destroyed/restarted/recreated freely without asking — they're disposable test infrastructure
type: feedback
originSessionId: c2038692-d484-42f0-bf9c-f67eeb2173a4
---
`virsh destroy testN` / `virsh start testN` / full rebuild on the MXFS test VMs is fine without asking. There are 32 of them, the user can rebuild any in ~5 minutes.

**Why:** They're disposable test infrastructure for kernel module work. Confirmed 2026-04-25 in v0.3.4 session — got a stuck D-state on test2 from v0.3.3 self-deadlock and asked permission to virsh destroy. User: "I could give a shit what you do with the test VMs."

**How to apply:** Power-cycle / destroy / rebuild any test* VM as needed during MXFS dev work. The `feedback_no_reboot.md` rule still applies to *production* hosts (clyde, serv, etc.) — only the testN guest VMs are fair game.
