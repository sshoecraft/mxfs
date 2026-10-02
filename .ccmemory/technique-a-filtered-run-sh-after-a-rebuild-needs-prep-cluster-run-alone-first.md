---
name: technique-a-filtered-run-sh-after-a-rebuild-needs-prep-cluster-run-alone-first
description: TECHNIQUE: run.sh refuses a filtered run whose cluster marker names another build; `prep_cluster` must be the ONLY name on its own invocation first.
metadata:
  type: feedback
tags: [run.sh, harness]
---

A filtered run (`run.sh <config> <test...>`, or `scripts/drbd_rig.sh suite <test>`) reuses the cluster only when `.cluster_marker.<group>.json` names the same configuration and srcversion. After a rebuild it exits with:

> ERROR: cluster is prepped for ... (srcver=OLD), you requested ... (srcver=NEW)

Listing `prep_cluster` with other test names does not help. The forced-prep branch requires `ONLY == (prep_cluster)` exactly (`run.sh` ~2103). Run two invocations:
1. `scripts/drbd_rig.sh suite prep_cluster` (or `run.sh <cfg> prep_cluster`);
2. `scripts/drbd_rig.sh suite <test>`.

A node set mounted by `drbd_rig.sh mxfs` does not satisfy the marker. Only `run.sh`'s own prep writes it.
