---
name: ccloop-c7ee71c6-sess286-501-root-proven-preacq-optional-ruling
description: sess286: D-501 ROOT PROVEN = rename AG-preacquire false coupling (ag21 x dir-EX double wait); GPT ruling: mandatory/optional AG intent; fix unimpleme…
metadata:
  type: project
---

# D-501 root cause proven + fix ruling (sess286)

## Measurement (0.11.502, P291-EXWIN, dlm_fairness 32/caw reproduced FAIL 0/32)
- H1 (biased EX nomination) REFUTED: dir-EX (ino 88080512, AG 21) rotates fair+fast — 887 grants/30s, median inter-grant gap 23ms, 2/886 consecutive repeat wins, every node first-granted <5.1s.
- P291 gotcha: `yt=`/`wex=` fields are HEX (%llx no prefix) — a `\d+` regex silently drops most lines. Parser: scripts/p291_aggregate.py.
- dmesg timebases differ per node — always calibrate boot epoch via P291 realms (wall-ms) before cross-node windowing.
- Real mechanism (observed in one 18ms window on test1): mv preacquires participating inodes' home AGs; trylock miss on peer-held ag21 → ILOCK handoff → dir EX granted away 17ms after a 642ms-wait adoption → blocks ~600ms holding nothing for ag21 → relock re-queues ~600ms for dir EX. Two serialized cross-node waits per rename that touches NO AG metadata.
- Census: 1590 in-window AG waits; 850+ comm=mv; 1227 on ag=21. Per-node AGwait count ↔ slowness near-perfect (110 waits → 6/16 rounds; 0-2 waits → done <7s). Cached-ag21 holder batches 48 ops in 0.4s; makespan ≈ 32 × ag-handoff ≈ 32s vs 30s budget.

## RULE-5 ruling (GPT sess286): phase-aware mandatory/optional AG intent
- Mandatory (today's trylock+handoff+block-holding-nothing) ONLY for AG demands reachable past a non-restartable boundary: target_ip's AG when rename has an existing target (in-trans iunlink); xfs_remove's ip AG (xfs_inode.c:5945, unchanged).
- Optional (trylock; miss → PROCEED, no handoff, no block): rename src/target dir + src_ip home AGs. No-target same-dir rename: mandatory set EMPTY.
- Tripwire probe at deep P1-AGWAIT site (xfs_mxfs_dlm.c ~36596) when a DIRTY trans blocks on AG — evidence of how often skipped insurance fires; dev-assert candidate.
- Option C (dir-EX reservation held across AG wait) REJECTED — hidden hold-and-wait.
- Blanket "always proceed on miss" NOT approved until ifree/defer-finish/trans-roll/dir-shrink paths audited restart-safe.

## Code map
preacquire: xfs/xfs_mxfs_dlm.c:41148 (trylock loop 41211+); rename caller xfs/xfs_inode.c:6501 (passes all inodes[]); remove caller :5945. Deep blocking + P1-AGWAIT: xfs_mxfs_dlm.c:36582-36666.

## Next
Implement split, 0.11.503, make clean+modules, prep_cluster, dlm_fairness (expect ≤30s PASS), then rsync_paired + scaling_curve regression (D-488 birth suite).
