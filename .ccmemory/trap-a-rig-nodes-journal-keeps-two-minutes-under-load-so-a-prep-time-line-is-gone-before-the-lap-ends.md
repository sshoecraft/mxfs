---
name: trap-a-rig-nodes-journal-keeps-two-minutes-under-load-so-a-prep-time-line-is-gone-before-the-lap-ends
description: TRAP (0.90.29): guest journals held 78-82K kernel lines (&lt;2 min under multi-victim load); unload lines printed at prep read 0 five minutes later.
metadata:
  type: feedback
tags: [journal, rig, instrument, capture]
---

# A rig node's journal keeps about two minutes of a loaded lap

**What happened (0.90.29):** the module-unload instrument prints at a lap's
PREP.  A read of `journalctl -k --since @<before the prep>` on test1/test4
five minutes later returned 0 lines: the journal's first retained line was
newer than the unload.  Every node's journal held 78,000-82,500 kernel lines
whatever `--since` asked for, which under the multi-victim load is under two
minutes.  The harness's followed logs (`klog_<node>.txt.gz`) begin at T0,
after the prep, so they do not hold prep-time lines either.

**What to do:**
- Read a prep-time line (module unload, mount, join) within a minute of the
  prep, or print it at error level so the panic channel keeps it.
- When a journal read returns 0 for a tag, print the journal's first and last
  epoch beside the count; a first epoch later than the event makes the zero a
  capture failure.
- `journalctl -b` also hides everything from before a victim's restart.
