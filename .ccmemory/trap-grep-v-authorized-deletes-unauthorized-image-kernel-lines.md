---
name: trap-grep-v-authorized-deletes-unauthorized-image-kernel-lines
description: TRAP (sess402): filtering ssh output with `grep -v authorized` deletes kernel lines containing "unauthorized image(s)" (P227-FR-ATOMIC-SKIP). Anchor…
metadata:
  type: feedback
tags: [trap, ssh, banner, grep, foreign-replay, P227-FR-ATOMIC-SKIP, evidence, feedback]
---

# `grep -v authorized` is not a banner filter — it is an evidence shredder

## What happened (sess402, 2026-08-23)
The first crash/replay run (`tests/tmpfile_churn_kill.sh kill1`) ended with
`foreign replay of slot 13 failed: error -117` and the ledger/refusal verdict
said `refused=2` — but a 32-node log sweep and two hand greps found ZERO
per-item skip notices.  An hour of "which silent path counts refusals?" code
reading followed.  The notice was there all along:

    MXFS foreign replay: ATOMIC-SKIP whole transaction lsn=... — contains
    unauthorized image(s); partial apply would tear (P227-FR-ATOMIC-SKIP ...)

Every pipeline in the tree stripped the ssh login banner
(`Unauthorized access to this system is prohibited.`) with
`grep -v authorized`, which also matches **un**authorized — so the one line
that named the mechanism was deleted from every pulled log, the sweeper's
per-node files, and my own greps.  `grep -c` on the node itself (no filter)
showed 3.

## Rule
- Filter the banner ANCHORED and only on its own lines:
  `grep -av '^Unauthorized\|^Warning:\|^If you'`
  (`tests/d385_publication_verify.sh` already did this right).
- Never filter pulled kernel logs by a bare substring that can occur inside a
  kernel message (authorized, warning, error, failed ...).
- When a counter says N refusals and the notices are absent, suspect the
  pipeline before the kernel: `grep -c` on the node with NO filter first.

## Fixed sess402
tests/tmpfile_churn.sh, tmpfile_churn_kill.sh, ag_handoff_lap_sweep.sh,
tmpfile_churn_ftrace.sh, agifc_churn_experiment.sh, iunl_mismatch_negative.sh
all switched to the anchored pattern (22 sites).
