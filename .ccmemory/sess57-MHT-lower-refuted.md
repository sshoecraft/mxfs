---
name: sess57-MHT-lower-refuted
description: sess57: inode_mht_ms=20 REFUTED for 2/tcp — 15/17 (dlm_fairness + tcp_dlm_scaling fail, wall 558s near timeout). Lower MHT = more ping-pong = WORSE.…
metadata:
  type: project
---

## sess57 — MHT-lower lead REFUTED. Do NOT pursue inode_mht_ms reduction.

Tested MXFS_EXTRA_MODARGS="inode_mht_ms=20" (vs default 300, xfs_mxfs_dlm.c:4015) on build DDF775DD: full ./run.sh 2 tcp = **15/17** (dlm_fairness 1/2 + tcp_dlm_scaling 1/2), wall=558s (near the 560s timeout). WORSE than the default-300 baseline (which gets 16-17/17). Lower MHT → more cross-node lock ping-pong → MORE resurrection-prone releases AND slower (the sess51 symmetric PR→EX livelock amplifies). The MHT default 300 is already tuned; do not lower it.

This closes the cheap-experiment phase of sess57. All non-ICLUSTER levers tried this session are exhausted/refuted (durable-verify, AG-pre-acquire, MHT-lower — see [[sess57-FINAL-state-and-next-steps]]). The remaining convergent fix is the ICLUSTER DLM lock ([[sess54-gpt-coresident-cluster-flush-design]]). Tree is at the clean DDF775DD baseline (drain-sample fix only, ~50% reliable).
