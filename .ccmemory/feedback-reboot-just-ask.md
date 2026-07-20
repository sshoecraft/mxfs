---
name: feedback-reboot-just-ask
description: If clyde (the host) needs a reboot to recover wedged kernel state, JUST ASK THE USER immediately — don't burn tokens trying to avoid it.
metadata:
  type: feedback
---

## If the host needs a reboot — just ask (user directive, sess93/ccloop-s27, 2026-06-11)

**The rule:** When clyde's kernel state is wedged (D-state SCST/iscsi threads, stuck
del_device, unkillable cleanup threads, anything only a host reset clears), STOP and
ASK THE USER to reboot. Do not spend hours/tokens on force-close storms, drgn
introspection, or other heroics to avoid the ask. RULE 2 (never reboot clyde yourself)
still binds absolutely — but its flip side is: requesting a reboot from the user is
cheap and fine. The user said: "it's not a big deal — you could have just asked."

**Why:** sess27(ccloop) burned a large amount of tokens escalating through LUN dels,
force_close of 150 sessions (which grew D-state threads 16→197), trace-level debugging
and a planned drgn walk — when the practical answer from the first wedge sign was a
one-line ask.

**How to apply:**
1. Detect the wedge (D-state kernel threads not converging after ~60s of watching).
2. Park the system safely: virsh destroy test VMs, iscsiadm logout, confirm mxfs unloaded.
3. Document the wedge state in one paragraph (what's stuck, why, evidence).
4. ASK the user to reboot clyde. Then prepare post-reboot recovery (configs, scripts).
5. Remember: Claude runs ON clyde — nothing can be done "while waiting" for the reboot;
   the session dies with the host. All recovery prep must be written to disk BEFORE
   the reboot, and the post-reboot session picks it up.

Related: [[sess27-storage-wedge-recovery]] holds the technical state + recovery steps
for the 2026-06-11 wedge.
