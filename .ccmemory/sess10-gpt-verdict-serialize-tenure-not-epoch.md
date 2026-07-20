---
name: sess10-gpt-verdict-serialize-tenure-not-epoch
description: sess10 GPT-5.5 VERDICT: root=double-grant via lossy heartbeat; fix=strict dir-EX tenure serialization + reload-on-reacquire + MHT batching, NOT a CAW…
metadata:
  type: project
---

## GPT-5.5 consult (escalation after Gemini x2 same issue). DECISIVE. For [[sess10-progress-reliable-repro-and-unsound-changecount]].

## VERDICT: The CAW shared-epoch is NOT the minimal fix (it fixes staleness DETECTION but not concurrent-RMW lost-update). The ROOT is DOUBLE-GRANT: dirs are kept cached-EX on BOTH nodes and reconciled via the LOSSY async evict-ring heartbeat (`note_dir_modified` -> `mxfs_v5_dlm_note_dir_modified` -> DIR_MODIFY) INSTEAD of a real DLM BAST. That "cached-EX-on-both + async reconciliation" scheme is the bug for RMW metadata. Gemini's 1st consult (strict barrier) agreed; GFS2 model.

## MINIMAL SOUND FIX (implement in THIS order; converges Gemini+GPT):
1. **No double-grant for dirs.** A local dir-RMW fast path may run ONLY if this node owns a REAL writer tenure (real DLM EX that BASTs peers), not a cached grant both sides hold. No tenure -> real acquire.
2. **Unconditional reload-on-reacquire.** After acquiring the dir EX following possible remote ownership, FUA-reload the shortform fork BEFORE the first mutation. Do NOT trust i_dlm_dir_gen / di_changecount / content-compare-while-dirty. After a real reacquire you have NO local uncheckpointed dir mods, so wholesale reload is SAFE (sidesteps the destage race entirely).
3. **MHT batching on BAST (anti-starvation).** Don't bounce per-op (that was sess9-A starvation got=7/50). On BAST: keep tenure until MHT deadline; then QUIESCE = stop admitting new local dir ops, drain active ops, force-log + push-AIL + bwrite dinode/cluster + blkdev_issue_flush (dir durable), THEN release EX. Reload happens once per tenure, not per op.
4. Ordering for handoff: dir CONTENT durable FIRST, (optional epoch publish) SECOND, release/handoff THIRD. Handoff must NOT occur while pincount>0 / ili_fields / IN_AIL / dirty dinode buf (existing refresh gate is correct; arrange handoff so it isn't hit).

## CAW epoch = OPTIONAL later (diagnostic / skip-reload optimization / recovery audit), in an MXFS-private CAW side table keyed by ino+gen — NOT in the dinode (XFS writeback/replay would clobber it). Do NOT make epoch-only detection the correctness mechanism.

## Optimistic CAW-RMW on dir content = REJECTED as minimal fix: create/rename/remove touch multiple metadata objects (parent fork, child nlink, inode alloc, rename = 2 dirs, log/AIL/LSN/replay) — would be a full clustered optimistic-transaction system. Too big/risky.

## NEXT: find where dir mutation takes its lock + where note_dir_modified is called (xfs_mxfs_dlm.c:9921 mxfs_dlm_note_dir_modified; evict-ring). Make dir-EX a real serialized tenure with reload-on-reacquire, MHT-bounded. Heavy + delicate (dir fast-path has many deadlock/starvation patches) — validate with FULL `./run.sh 2 tcp` x3 (reliable repro), watch for starvation (dlm_fairness got<50) + deadlock.
