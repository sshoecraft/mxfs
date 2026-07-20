---
name: sess8-DECISIVE-not-doublegrant-not-splitbrain-serialized-coherence-gap
description: sess8 DECISIVE: 2/tcp lost-update is NOT double-grant and NOT split-brain (P-DOUBLEGRANT=0 AND P-STALEMASTER-GRANT=0 at failures). It's a serialized-…
metadata:
  type: project
---

## DECISIVE REFUTATION (RULE 4) — redirects the entire investigation.
Build 174E2CD5226C5C5969037B7 (deployed both nodes) adds TWO always-on, rate-limited, deadlock-safe
(table_rwlock-only / lockless reads) master-side detectors in dlm/dlm.c:
- **P-DOUBLEGRANT**: fires when the master grants EX while its shadow shows another node's active EX
  on the same resource (single-master concurrent double-grant). Shadow SET on every master-side EX
  grant, CLEARED only on genuine release (not administrative removals).
- **P-STALEMASTER-GRANT**: fires when this node reaches a master-side EX grant but the LOCKLESSLY
  recomputed master (active_nodes[hash%count]) != local_node — i.e. mastership flipped under it
  (membership-flap split-brain).

At REAL dlm_fairness FAILURES (multiple, production timing, no dirwr), BOTH counters = **0** on BOTH
nodes. Therefore the rotating 2/tcp shortform-dir lost-update is:
- NOT a single-master concurrent double-grant (P-DOUBLEGRANT=0), AND
- NOT a transient split-brain mastership (P-STALEMASTER-GRANT=0 → mastership stable+consistent at
  grant time).
This ELIMINATES the double-grant family ([[sess-tcp-tcp-dlm-scaling-DOUBLE-GRANT-proven]],
[[sess8-symmetric-clobber-confirms-doublegrant-detector-design]]) that consumed sess-tcp + many
prior sessions. EX grants ARE serialized and consistent, and the slow-path EX acquire ALWAYS reloads
(xfs_mxfs_dlm.c ~7055/7079).

## THEREFORE the mechanism is a SERIALIZED-EX-HANDOFF COHERENCE GAP (not a locking failure):
Leftover (durable, BOTH nodes agree, e.g. n1_r7 / earlier n1_r1.done+n2_r7.done) = a dirent the
owner created+renamed+rm'd, RESURRECTED on disk. With serialized EX + reload, node B acquires EX
AFTER node A's durable delete+release, reloads, yet RMWs from a base that STILL CONTAINS the deleted
dirent → durably resurrects it. So node B's EX-acquire RELOAD read a STALE shortform dinode despite
A's durable release.

## CONFLICTING SUB-EVIDENCE to resolve (the precise next question):
- P-SFREL (in bast_process release path): showed the releasing node's shortform dinode DURABLE on the
  LUN (plain-bio read-back) at release → supports "write durable, read-side stale".
- P-SFDIR-REVERT FUA probe (earlier): showed fua_cnt == disk_cnt < incore_cnt → the LUN GENUINELY
  lacked the entry → supports "write NOT durable on LUN".
These conflict. RESOLVE with ONE correlated trace across a SINGLE handoff (both nodes UTC, realns):
on node A log P-SFREL(ino, count) at the release that hands the dir to B; on node B log
P-SFDIR-RELOAD(ino, count) at the very next EX acquire of that SAME ino. If A.count > B.count →
read-side stale (B's reload didn't get A's durable image — fix the reload to truly re-read the LUN
coherence point / invalidate the cached inode-cluster buffer on cache-HIT EX reload). If A.count is
ALSO short → write-side (A released before its shortform dinode delete was durable — re-examine
bast_process drain ordering vs the DLM unlock for the dir inode).

## NEXT SESSION: implement that single correlated handoff trace (gate to the test dir ino to keep
volume low so dmesg doesn't roll), reproduce ONE failure, read the A→B count delta, then fix the
proven side. Detectors P-DOUBLEGRANT/P-STALEMASTER-GRANT can stay (cheap, prove the negatives).

## STABLE STATE: 15/16, no shutdown cascade. KEEP rename guard (xfs_inode.c). Deployed build
174E2CD5 (rename guard + P-SFREL + P-CONVBLK-REMOVE + P-DOUBLEGRANT + P-STALEMASTER-GRANT, all
harmless). Marker NOT written. Fallbacks: E143DF7B (rename guard only), E8BF16B2 (pre-guard).
</body>
