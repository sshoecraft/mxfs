---
name: sess8-doublegrant-detector-built-PDOUBLEGRANT-zero-at-failure
description: sess8: built safe single-master double-grant detector (P-DOUBLEGRANT, build BD571915). Fired ZERO at a real failure → REFUTES single-master concurren…
metadata:
  type: project
---

## Built a SAFE double-grant detector (build BD5719158460A281FC63583, deployed both nodes).
Instrumentation only, zero behavior change, table_rwlock-protected (no new lock → no deadlock risk).
In dlm/dlm.c: a 512-entry `dg_shadow` of current EX holders for INODE resources, SET on every
master-side EX grant (process_remote_request immediate/reaffirm/conversion; mxfs_dlm_lock local
immediate; all 3 promote_waiters dispatch loops), CLEARED only on GENUINE release
(process_remote_release, mxfs_dlm_unlock) — NOT on administrative removals. At each EX grant it scans
for an existing active EX held by a DIFFERENT node on the same resource → `P-DOUBLEGRANT` (always-on,
rate-limited). Forward decls added before send_grant. (purge_node clear intentionally omitted — no
node death in dlm_fairness, so it can't false-positive there.)

## DECISIVE RESULT (RULE 4): at a REAL dlm_fairness FAILURE (build BD571915, no dirwr, production
timing), `P-DOUBLEGRANT` fired **ZERO** times on BOTH nodes. The detector is complete for a
single-master resource (the master is the sole arbiter; all its grant sites are hooked). Therefore
the rotating 2/tcp shortform lost-update is **NOT a single-master concurrent double-grant**. Combined
with the proven fact that the SLOW-PATH EX acquire ALWAYS reloads (xfs_mxfs_dlm.c ~7055/7079), serial
reloading EX acquires should not lose updates — yet they do.

## NEW PRIME SUSPECT: TRANSIENT SPLIT-BRAIN MASTERSHIP.
master = active_nodes[resource_hash % count] (dlm.c mxfs_dlm_resource_master ~1889). If a membership
flap momentarily changes count/ordering (or the two nodes' active_nodes lists transiently differ),
BOTH nodes can compute themselves as master for the same ino at once → each grants EX in its OWN lock
table without coordinating → genuinely concurrent EX that NO single-node detector can see (the two
grants live in two different masters' tables). Weak supporting hint: across iterations BOTH nodes
logged P-CONVBLK-REMOVE for ino=131 (both acted as master for 131 at some point) — but run.sh
re-forms the cluster each iter so this may be cross-iter, NOT simultaneous (for the FAILING dir
ino=2097280 only test1 was seen as master). NOT yet proven simultaneous.

## NEXT SESSION (RULE 4 — confirm split-brain, then fix):
1. Extend the detector: log EVERY master-side EX grant as `P-EXGRANT-MASTER ino=%llu owner=%u
   master_self=%u realns=%llu` (rate-limited or ring), on BOTH nodes. At a failure, correlate by
   realns: if BOTH nodes grant EX for the SAME ino in OVERLAPPING windows → split-brain CONFIRMED.
   Also log resource_master(ino) + active_nodes.count/ordering on each node at grant time.
2. If split-brain: the fix is in membership/mastership stability — ensure both nodes agree on
   active_nodes ordering (sorted, not arrival-order) and that a master cannot grant EX while a
   membership change is in flight (epoch-guard the grant; reject/queue grants during membership
   transitions). Look at mxfs_dlm_update_active_nodes (~1918) + the epoch handling.
3. If NOT split-brain: the vector is a serialized coherence gap — node B acquires EX after A's
   release but reads A's PRE-modify image (invariant #1 / grant-races-drain). Re-examine the EX
   grant-vs-release-drain ordering for the dir inode.

## STABLE STATE: 15/16, no shutdown cascade. KEEP: rename guard (xfs_inode.c). Diagnostics (all
harmless): P-SFREL, P-CONVBLK-REMOVE, P-DOUBLEGRANT detector. Marker NOT written. Prior memories:
[[sess8-symmetric-clobber-confirms-doublegrant-detector-design]] (now refined — single-master
double-grant refuted), [[sess8-rename-guard-fix-and-shortform-lostupdate-root]]. Fallbacks: E143DF7B
(rename guard only), E8BF16B2 (pre-guard).
</body>
