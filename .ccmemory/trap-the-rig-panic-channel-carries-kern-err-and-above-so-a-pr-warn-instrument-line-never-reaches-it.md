---
name: trap-the-rig-panic-channel-carries-kern-err-and-above-so-a-pr-warn-instrument-line-never-reaches-it
description: TRAP (0.90.29): rig guests netconsole only KERN_ERR+; 10 pr_warn unload-instrument lines were in journals, 0 in tests/evidence/netconsole.log.
metadata:
  type: feedback
tags: [netconsole, instrument, rig, loglevel]
---

# The rig's panic channel carries errors, not warnings

**What happened (0.90.29):** an instrument printed at module unload with
`pr_warn` so that "the line reaches the console before the panic it explains".
Ten such lines were in the nodes' journals; `tests/evidence/netconsole.log`
held none.  The guests' console level passes `KERN_ERR` and above to
netconsole (boot-time warnings do arrive, before the level is lowered).

**What to do:**
- An instrument line that must survive a guest panic prints with `pr_err`
  (or `printk(KERN_ERR ...)` chosen at run time when only the bad case needs
  it).  `pr_warn`, `pr_info`, `mxfs_probe` and `pr_debug` lines die with the
  journal's last lines.
- Before relying on the channel for a line, check one known occurrence of it
  is in `tests/evidence/netconsole.log`.
- A count of 0 in the channel for a warn-level tag is a capture limit, never
  evidence of absence.
