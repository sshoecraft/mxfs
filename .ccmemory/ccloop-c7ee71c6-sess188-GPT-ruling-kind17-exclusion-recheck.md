---
name: ccloop-c7ee71c6-sess188-GPT-ruling-kind17-exclusion-recheck
description: sess188 RULE-5 ruling: kind-17 recheck APPROVED w/ corrections — validate desc tuple vs cached auth BEFORE branching fence_kind; sole-live-slot ident…
metadata:
  type: project
---

# sess188 RULE-5 ruling — kind-17 leg of v5_exclusion_recheck (gpt-5.6-sol)

Fix for the P239-EXCL-LAPSED blocker (D-SHUTDOWN-UMOUNT-CLEAN-RELEASE-DIRTY-SLICE remount arm): APPROVED with corrections.

## Requirements
1. **Never branch on a bare reread `desc.fence_kind`.** Read ONE strict-validated descriptor image, match it against cached `recov_auth` (victim node/epoch/slot, recovery_gen, owner_term, stage valid for the op) FIRST, then branch on that matched descriptor's fence_kind. Tuple mismatch = LOST/STALE AUTHORITY (distinct refusal, not "fence lapse of the successor's descriptor"). Any read/csum/stage/tuple failure → fail closed.
2. **kind-17 "exclusion still holds" =** single_node_exclusive param still asserted AND *our own slot is live and NO other slot is live/admitted* (identity, not cardinality — "exactly one live slot" is wrong if it's not ours). SNLOCAL marker is NOT part of this predicate (it stays at the untagged-replay authority decision).
3. **Membership growth mid-recovery → terminal fail-closed**, same as PR lapse: no further destructive steps, no publish/thaw, descriptor left incomplete, manifest frozen, blocked-state set, lease dropped. NEVER resume the same kind-17 recovery when membership drops back to one — observed lapse breaks the continuous-exclusion proof; resumption needs a NEW authority (new gen/re-claim, joining node proven quiescent or PR-backed fence).
4. **Recheck is a lapse DETECTOR, not enforcement.** Safety needs a join/admission interlock: a joining node must be unable to issue FS I/O while a claimed kind-17 recovery descriptor exists (the sess58 item-6A settle-residue mount-abort gate is the candidate mechanism — VERIFY it refuses on a claimed-in-progress descriptor, not just on unfenceable death residue). Alternatively a monotonic membership/admission epoch captured at cert and required unchanged.
5. recovery_complete site: same checks; keep admission blocked through the durable completion commit; on gate failure DO NOT publish even with replay writes done — leave as incomplete recovery, no rollback, keep frozen/blocked.
6. Once FENCED, fence_kind is immutable for that recovery generation; kind-17→PR-backed transition requires new gen/re-claim, never in-place rewrite.

## Implementation note (this session)
Plan: extend the disklock layer so the recheck can get a TUPLE-VALIDATED fence_kind (reuse mxfs_disklock_recovery_replay_authorized's validation on one descriptor image, out-param the kind) rather than a second unvalidated read; then in v5_exclusion_recheck branch: kind-17 → param + sole-live-slot check (distinct P239-...-SN refusal name), else PR check as today.
