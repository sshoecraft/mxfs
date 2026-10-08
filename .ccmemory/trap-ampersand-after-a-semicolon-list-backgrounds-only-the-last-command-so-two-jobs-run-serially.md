---
name: trap-ampersand-after-a-semicolon-list-backgrounds-only-the-last-command-so-two-jobs-run-serially
description: TRAP: `A > f; echo rc >> f & B > g; ...; wait` backgrounds only the echo: A runs in the foreground, B after it. Wrap each job: `( A; echo rc ) & ( B;…
metadata:
  type: feedback
tags: [bash, trap, parallel]
---

Meant to update the physical and nested PVE pairs at once:

    scripts/pve_pair_update.sh > phys.log 2>&1; echo "UPDATE_RC=$?" >> phys.log & PVE_PAIR=... scripts/pve_pair_update.sh > nested.log 2>&1; ...; wait

`&` terminates only the simple command (here the pipeline) before it, so it backgrounded the `echo` alone. The physical update ran in the foreground, the nested one started only after it finished (twice the wall, ~8 min each), and the nested log did not exist while the first ran, which looked like a failed launch.

**Why:** in bash `a; b & c` is `a`, then `b` in the background, then `c`; a list joined by `;` is not grouped by a trailing `&`.

**How to apply:** group every multi-command job before backgrounding it, each with its own log and captured rc:

    ( job1 > l1 2>&1; echo "RC=$?" >> l1 ) & ( job2 > l2 2>&1; echo "RC=$?" >> l2 ) & wait

Check that each job's log exists right after a parallel launch.
