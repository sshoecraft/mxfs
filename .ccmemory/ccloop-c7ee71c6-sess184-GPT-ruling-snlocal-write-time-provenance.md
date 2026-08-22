---
name: ccloop-c7ee71c6-sess184-GPT-ruling-snlocal-write-time-provenance
description: sess184 RULE-5 ruling (blocker 1): OPTION C — kind-17 never unlocks P227 alone; durable write-time snlocal marker at claim + kind-17 at recovery, sco…
metadata:
  type: project
---

# sess184 RULE-5 ruling — single-node untagged slice replay (blocker 1 of D-SHUTDOWN-UMOUNT-CLEAN-RELEASE-DIRTY-SLICE)

Consult: gpt-5.6-sol, sess184. Question: may a kind-17 SINGLE_NODE_EXCLUSIVE
certificate authorize applying a single-node victim's structurally untagged
images (P227 gate), or must single-node mounts emit trailers?

## Ruling: OPTION C — neither. Distinct single-node/local-log recovery with fail-closed provenance.

- Kind-17 proves at most "claimant may proceed NOW without PR fence". It does
  NOT prove the victim was sole writer when the untagged images were written.
  Using it directly as a P227 exception = exactly the expansion the sess180
  item-2 LIMIT prohibits. A mis-set param on a shared LUN would silently apply
  unauthenticated metadata images — too catastrophic for an automatic rule.
- Option B (synthetic trailers) refused: never fabricate DLM authority
  trailers where no grant existed. A future single-node authority token would
  be a separately defined class behind proto-gen — and doesn't help existing
  untagged slices anyway.

## Required design (C)
1. **Durable write-time provenance**: BEFORE the first untagged record of the
   dirty incarnation, durable slice/slot metadata classifies the incarnation
   SINGLE_NODE_LOCAL_LOG with slice identity + incarnation/generation.
   Recovery must prove the ENTIRE dirty interval belongs to that incarnation
   (holds because claim requires a clean slice → all dirt is this incarnation).
2. **Hard exclusivity** per sess180 item 5 (exclusive bdev / no shared path);
   module param alone is assertion, not enforcement.
3. **No dirty mode transition**: snlocal↔clustered requires clean log/zeroed
   slot + new incarnation; never reclassify a dirty incarnation.
4. **Exact replay scope**: exception applies only to the identified slice AND
   incarnation. Anything outside fails closed.
5. **Two separate predicates**, in code: takeover_is_exclusive_now (kind-17)
   vs log_was_single_node_authorized_when_written (marker). Neither implies
   the other.
6. Normal ordering: lease → exclusion → validate provenance → recover →
   durable completion → zero → separate ordinary claim.
7. **Mixed-version**: marker must make old kernels REJECT, not ignore —
   fail-closed discipline; don't introduce during proto-gen 3 if an old
   kernel could mount and interpret under legacy rules (rides proto-gen 3→4).
8. **P227 unchanged** for clustered/unknown logs; no fallback to the global
   knob; SEPARATE counters for local-log-provenance acceptance (never counted
   as authority-trailer acceptance).
- Kind-17 + NO marker → not auto-accepted: admin/offline recovery, salvage,
  or leave unreplayed. Claimant being the victim's next incarnation changes
  nothing.

## Precedent boundary (verbatim)
"Untagged replay is permitted only for a log incarnation durably classified
BEFORE WRITING as a local single-node log and operated under hard
exclusivity. Recovery/fence certificates never retroactively classify
untagged records."

## Blocker 2 diagnosis (same session, code-proven)
(a) Step 6.5 snapshots ACTIVE-only → WITHDRAWN slot never in barrier cohort
→ recovery async via monitor while mount completes; single-node claimant has
no frozen-grant protection → must fold WITHDRAWN slots into the 6.5 cohort
(skip freeze-confirm; voluntary death definitive).
(b) put_super orders m_mxfs_dlm=NULL → v5_shutdown(FREES ctx) → only then
cancel_work_sync(foreign_replay_work): measured P163-COMPLETE-BAIL ctx=0 =
lost publication; also a UAF window. Fix = withdraw-work pattern (cancel
before NULL/free) + !mp->m_mxfs_dlm iteration guard.
