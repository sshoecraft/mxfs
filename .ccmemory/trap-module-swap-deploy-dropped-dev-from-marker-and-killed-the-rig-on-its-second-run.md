---
name: trap-module-swap-deploy-dropped-dev-from-marker-and-killed-the-rig-on-its-second-run
description: TRAP (sess572): scripts/module_swap_deploy.sh rewrote .cluster_marker.json without the `dev` field it had just read from it, so the SECOND consecutiv…
metadata:
  type: feedback
tags: [rig, deploy, harness, cluster-marker]
---

# A deploy script that consumes a marker field and then drops it

## What happened

`scripts/module_swap_deploy.sh` resolves the LUN like this: `MXFS_DEV` if set,
else the `dev` field of `.cluster_marker.json`, else `/dev/mapper/mpatha` as a
last resort (a multipath name that does not exist on the QNAP rig).

At the end of a successful run it rewrote the marker with
`jq -n '{nodes, dlm, srcversion, node_list, iso}'` — **no `dev`**.

So the first swap after a `run.sh prep_cluster` worked (prep writes `dev`), and
the second one fell through to `/dev/mapper/mpatha`. By the time it discovered
the device did not exist it had already unmounted and rmmod'd **every node**:

    --- all 2 nodes down (fs preserved) ---
    blockdev: cannot open /dev/mapper/mpatha: No such file or directory
    NODE_PREP_FAIL: blockdev --flushbufs /dev/mapper/mpatha failed

The cluster was down with no way for the script to bring it back, and the
recovery attempt left the rig in a SCSI-PR reservation-conflict state that cost
a full re-prep on top.

## Why it is worth remembering

The failure is invisible on the run that causes it. The run that *breaks* is
clean, prints `SWAP_OK`, and quietly removes the fact the next run depends on.
Anything that reads a value from a state file and then rewrites that file must
write the value back — a partial rewrite of a state file is a delayed-action
bug, and this one's blast radius was the whole rig because the check that
catches it runs *after* the teardown.

## Fixed

0.75.118: the marker rewrite carries `--arg dev "$DEV"` and `SWAP_OK` prints the
device it stored. Verified by two consecutive swaps.

## The general shape

Order matters as much as the field. `module_swap_deploy.sh` tears down all nodes
in step 1 and validates the device in step 2. A precondition that can fail
belongs before the destructive step, not after it.
