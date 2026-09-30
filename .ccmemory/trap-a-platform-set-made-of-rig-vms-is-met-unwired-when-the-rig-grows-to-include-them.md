---
name: trap-a-platform-set-made-of-rig-vms-is-met-unwired-when-the-rig-grows-to-include-them
description: TRAP (0.90.25): ubuntu2404 set = test5-8; first 8-node board: PREP FAIL bad nodes test5..8(unmounted), shared-lun-0 absent. Rig wiring, not the FS.
metadata:
  type: feedback
tags: [rig, prep, platform, iscsi, 8-node]
---

# A platform set made of rig VMs is met unwired when the rig grows to include them

**What happened (0.90.25).** The 4-node release kept the `ubuntu2404`
verification set on test5..test8 (moved there from test3/test4 after the same
trap at 4 nodes). The first 8-node boards (`NODES=8 tests/board_4node_chain.sh
... tcp cawd`) both failed in 60 s:

    PREP FAIL: bad nodes: test5(unmounted) test6(unmounted) test7(unmounted) test8(unmounted)
    NODE_PREP_FAIL: device identity: ...:shared-lun-0 is not the LUN the cluster formed on (... absent)

test5..8 held one iSCSI node record, for `plat-ubuntu2404`, and none for the
rig's `:shared` target. The identity binding in `prep_node.sh` refused, which
is what it is for.

**How to read it:** `NODE_PREP_FAIL: device identity ... absent` is rig wiring.
It is never a filesystem verdict, and `tools/criteria.py` classes a prep
failure as rig noise, not as a genuine failure in the flake window.

**What was done:** the ubuntu2404 set became VMs of its own
(`ubuntu2404-1..8`, clones of test5, which had verified the platform); test5..8
got their platform record deleted, the `mxfs` package purged, and the
`:shared` record (`node.startup = automatic`) created and logged in.

**Rule:** platform sets are named `<platform>-N` and are never `testN`. Before
the first board at a new node count, check every rig node for exactly one node
record naming `:shared`:
`iscsiadm -m node` on test1..testN.
