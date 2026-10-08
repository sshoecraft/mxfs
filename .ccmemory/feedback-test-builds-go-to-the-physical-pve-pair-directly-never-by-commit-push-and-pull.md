---
name: feedback-test-builds-go-to-the-physical-pve-pair-directly-never-by-commit-push-and-pull
description: USER 2026-10-07: "stop pushing to github then pulling on the nodes to test them ... unnecessary churn". Test builds reach pve1/pve2 directly; no comm…
metadata:
  type: feedback
tags: [process, user-correction, pve, deploy]
---

The user, 2026-10-07, while 0.90.93 (the dual-write passenger fix) was about to go to the physical pair: "you can stop pushing to github then pulling on the nodes to test them ... thats uncessary churn".

**What it replaces:** the run's earlier process (session c6d8f205: "commit and push then git fetch && git pull on each node and make install OVERWRITE=1"), which sessions 0.90.83-0.90.92 followed for every test deploy, pushing one GitHub commit per test build.

**How to apply:**
- To test a build on pve1/pve2 (192.168.1.80/.81), put it on the hosts straight from the working tree, the way the nested pair (pve9-1/pve9-2) gets one: rebuild the module on each host from the tree (scripts/pve_dkms_rebuild.sh reads clyde's NFS /src), then swap it in with scripts/pve_pair_update.sh SKIP_INSTALL=1 (CHECK=1 adds a cold chk_mxfs). Confirm the loaded srcversion equals the tree's before measuring.
- Do not commit, push or pull to get a build onto a test host. With that process gone there is no standing direction to run git at all: commit or push only when the user says so.
- The user-path install (git clone/pull + make install) is still what a release must survive; test it when the user asks for a release, not on every test iteration.
- Check that the host loads the module just built, not an older copy from an earlier `make install` (modinfo -n mxfs, the loaded srcversion).
