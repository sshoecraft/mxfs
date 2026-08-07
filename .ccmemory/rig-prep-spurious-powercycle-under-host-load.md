---
name: rig-prep-spurious-powercycle-under-host-load
description: prep_cluster misreads slow ssh (host under unrelated load) as a wedged node and power-cycles it, causing a self-sustaining flap loop. How to recognis…
metadata:
  type: reference
tags: [rig, prep_cluster, infrastructure, false-positive, nfs]
---

# prep_cluster flap loop: slow ssh -> spurious power-cycle -> lost /src

## The failure

    --- prep: test1 did not release mxfs / lost /src (or unreachable) — escalating ---
        power-cycling test1 (virsh destroy+start)

…repeating forever, with prep never converging and each attempt taking longer
than the last.

## Why it happens (sess25, diagnosed)

`prep_cluster` step 1 runs, per node in parallel:

    timeout 150 "$SSH" "$n" "...mount /src...; $TEARDOWN..." > "$td/$n"

and then requires **both** `MXFS_CLEAN` and `SRC_OK` in that file. If the ssh
does not finish inside 150 s the file is empty, which is indistinguishable from
a genuinely wedged node — so prep escalates to `virsh destroy+start`.

Two things make that misfire:

1. **clyde carries unrelated user workload.** Measured during this session:
   load average 8–29 with `Wow.exe` at 362 % CPU, `worldserver` 86 %,
   `python3` 156 %, `tesseract` 125 %. Per-connection ssh latency went to
   **669–1101 ms**, and 32 parallel connections plus prep's own work pushed the
   per-node script past 150 s.
2. **A power-cycled node comes back without `/src`.** `/src` is deliberately
   not an fstab automount (see CLAUDE.md), so the "recovery" *creates* the
   `SRC_MISSING` condition that triggers the next escalation. Self-sustaining.

Confirmation that the node was never actually broken: running prep's exact
teardown by hand on the "failing" node returned `SRC_OK` + `MXFS_CLEAN`
immediately.

## How to break the loop

- Check host load FIRST (`uptime`, `ps -eo pcpu,comm --sort=-pcpu`). If it is
  someone else's workload, **do not kill it** — but know that RULE 0 timing
  measurements taken under it are not trustworthy, and say so rather than
  recording them as results.
- Kill stale prep trees by anchored pattern — `pkill -f '^/bin/bash \./run\.sh'`.
  **Never** `pkill -f "run.sh 32 caw"`: that string appears in your own
  `bash -c` wrapper, so the pkill kills its own shell (observed: background task
  exited 144 having never started the prep).
- Remount `/src` on all nodes:
  `mount -t nfs4 192.168.1.4:/src /src` (host exports `/src` to 192.168.0.0/16;
  verify with `showmount -e 192.168.1.4`).
- Do **not** run a parallel "keep /src mounted" watcher while prep is running —
  32 ssh sessions every 15 s contend with prep itself and make it worse
  (observed: 94 concurrent sshpass processes).

## Rig-level fix worth doing

Prep should distinguish "ssh timed out" from "node reported a dirty state" and
retry the former before escalating to a power-cycle; and the power-cycle path
should re-establish `/src` as part of recovery rather than leaving the node in
the exact state that re-triggers escalation.
