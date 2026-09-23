---
name: trap-suite-detectors-run-on-the-nodes-where-no-ssh-credentials-exist
description: TRAP: tests/suite detectors execute ON the test nodes, which hold no ssh secrets — a helper that reaches other hosts returns "unknown" there, silentl…
metadata:
  type: feedback
tags: [harness, suite, rig, ssh, secrets]
---

# A suite detector runs on the node, not on clyde

`tests/suite/*.sh` detectors execute **on the test nodes** — their results spool
through node-local `/run/mxfs-suite/$RUN_ID.$name.result`. That has a
consequence that is easy to miss when writing a helper for one of them:

**A node holds no ssh credentials for its peers.** The lab secrets
(`~/.config/mxfslab/secrets`, consumed by `tools/mxfs_sshpass.sh`) live on the
dev host only. Verified: `test -r /root/.config/mxfslab/secrets` → absent on
test1.

So any helper a detector calls that reaches another host **fails silently on
the node** and returns whatever its "cannot determine" path returns. If the
caller treats that as a legitimate unknown, the detector declines to score and
the cell shows SKIP with a reason that describes the wrong cause.

## How it bit (sess578)

`tools/mxfs_rig_tag.sh` resolves which physical rig a cluster is on, ending in
"read the LUN's SCSI vendor from sysfs" so a device rename cannot defeat it. It
did that read over ssh. On the dev host it answered `qnap`; called from the
detector it exited 1 — **while running on the node that owned the device**.
`cat /sys/block/sda/device/vendor` right there returns `QNAP`.

Fix: read local sysfs FIRST, fall back to ssh only when the device is not
present locally (which is the dev host's case, not the detector's).

## The general rule

When writing a helper that a suite detector will call, ask where the fact
lives:

- **On the node** (its own sysfs, /proc, mounts, dmesg, the LUN): read it
  directly. The detector is already there.
- **On the dev host** (the repo, the cluster marker, build artefacts): reachable
  over the `/src` NFS mount, which nodes do have.
- **On another node**: you cannot get it from a detector. Redesign so the fact
  is recorded somewhere both can read — the cluster marker is the established
  place, written by `run.sh` at prep time.

## Related

A one-shot sanity check is not enough: verify the helper **from the node**, not
just from clyde. `tools/mxfs_sshpass.sh test1 "cd /src/mxfs && ./tools/<helper>"`
is the check that would have caught this before the run.
