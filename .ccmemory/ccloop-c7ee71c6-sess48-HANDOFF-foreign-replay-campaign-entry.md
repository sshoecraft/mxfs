---
name: ccloop-c7ee71c6-sess48-HANDOFF-foreign-replay-campaign-entry
description: sess48 handoff: next campaign = D-FOREIGN-REPLAY full fix (authority tokens); entry points xfs_log_recover.c:2049/2128 (P223 skip), sess32 ruling = s…
metadata:
  type: project
---

# Relay entry point: D-FOREIGN-REPLAY-UNGATED-IMAGES full fix

## Current state
Containment SHIPPED (0.11.273-274): live foreign replay + adopted-slice mount recovery SKIP untagged buf/dquot/quotaoff/icreate images (`mxfs_foreign_replay_untagged_apply=0` default). Code: `xfs/xfs_log_recover.c:2049` and `:2128` (P223-FR-UNTAGGED-SKIP print at :2136), `xfs/xfs_log.c:629` (XLOG_MXFS_ADOPTED_SLICE). Inode records stay applied (di_changecount gate is node-independent). RESIDUAL (why still OPEN critical): the dead node's fsync-ACKED buffer-image changes that never destaged are applied by NOBODY — bounded durability gap.

## The spec (memory ccloop-c7ee71c6-sess32-GPT-ruling-A-D-foreign-replay-stop-ship §4)
Log records carry authority tokens {resource_id, grant_incarnation, tenure_id} captured at logging time; replay applies iff token == exact grant held at death; durable held-set manifest (checksummed, captured pre-purge); IMAGE_REPLAY_DONE marker gates purge + survivor resume + mount-time suppression; replayer-death restart from manifest under quarantine; untagged old logs → fail closed (offline recovery).

## Suggested shape (not yet designed in detail — RULE 5 consult before implementing)
1. Where to put tokens: buffer log item format extension (new BLF flag + trailing token struct in the format region) vs a separate companion log item per checkpoint carrying the held-set delta. GPT consult on which survives upstream log format constraints + torn-checkpoint semantics.
2. The disklock slot table / lease machinery already persists per-node grant state — the "durable held-set manifest" may extend the existing disklock slot claim records (dlm/disklock.c) rather than a new structure.
3. Verification harness: tests/foreign_replay_ab.sh precedent (A/B victims, acked-visibility 40/40 checks) + fault injection at the 5 ruled points.

## Also open (same family tree)
D-INODE-CLUSTER-PUBLISH-WITHOUT-AUTHORITY (critical; sess32 ruling §5 B EX-side capability gate — check what shipped), D-CROSSNODE-OPEN-UNLINK-DATA-LOSS (critical; openunlink_matrix currently 9/9 — its entry has the specific cross-node repro), D-RSYNC-RENAME-361 rename arm (instrument first-failing rename helper per gpt_ruling_sess45).

## Soak duty (continues alongside)
Fossil-arm tripwires ride every future cycle free: any same-gen FOSSILWR / WRSITE / LIVESKEW / RELLEAK / P53+QUERY line = regression alarm. 9 clean cycles banked on 0.11.394.
