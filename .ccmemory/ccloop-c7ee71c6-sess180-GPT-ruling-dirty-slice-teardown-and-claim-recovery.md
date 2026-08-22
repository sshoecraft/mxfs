---
name: ccloop-c7ee71c6-sess180-GPT-ruling-dirty-slice-teardown-and-claim-recovery
description: sess180 RULE-5 ruling (dirty-slice defect + #10): WITHDRAWN=non-claimable, claim-triggered guarded recovery via SAME survivor engine, sync withdraw i…
metadata:
  type: project
---

# sess180 RULE-5 ruling — dirty-slice teardown + who replays

Consult: gpt-5.6-sol, sess180. Covers D-SHUTDOWN-UMOUNT-CLEAN-RELEASE-DIRTY-SLICE
(both arms) and D-OWN-CRASH-RECLAIM-PATH-UNREACHABLE item 1.

## Measurements that fed it (test32 loop, 0.11.464)
- Arm A = RACE: GOINGDOWN queues withdraw work; immediate umount cancels it
  (put_super m_mxfs_dlm=NULL + cancel_work_sync at xfs_super.c:1564-5 runs
  before v5_shutdown:1577) → withdrawn=false → "clean teardown" release of
  dirty slice. With sleep 3, withdraw runs and stamps WITHDRAWN correctly.
- Arm B: even WITHDRAWN-stamped, remount pass-2 claims the sector
  (disklock.c:4683 treats any non-ACTIVE non-GUARD as claimable) → ADOPTED →
  untagged=7 wskip=7 → fsync'd file GONE. #10's no-survivor case now MEASURED
  as deterministic data loss.
- Arm C (code-read): v5_shutdown zeroes slot BEFORE xfs_unmountfs writes the
  unmount record (xfs_super.c 1577 vs 1601) — crash window.

## Rulings
1. State machine: ACTIVE → WITHDRAWN → RECOVERY_GUARD → recovery-durably-
   complete → CONSUMABLE. NO WITHDRAWN→adopted shortcut. WITHDRAWN means
   "owner stopped participating, slice NOT yet recovered" — make claimers
   refuse it (preferred over a new state: old kernels would consume an
   unknown state; deploy claim-fix fleet-wide, keep WITHDRAWN).
   Clean unmount: retain ACTIVE until unmount record durable → then zero.
2. WHO replays: claim-triggered recovery, reusing the SAME survivor engine:
   CAS WITHDRAWN→GUARD{claimant incarnation} → fence (where required) →
   recover slice → durable completion → zero → SEPARATE ordinary claim.
   Survivor and next-mounter = two initiators of one engine; GUARD is the
   mutex. Persistent node identity (#10 item 1) = defense-in-depth ONLY,
   never the recovery/liveness authority ("same node" ≠ fencing authority).
   LIMIT: PR fence + completion stamp is NOT lineage authority for untagged
   images — claim-triggered replay is acceptable only to the same extent the
   survivor foreign-replay path already accepts it (i.e. inherits #1 status;
   do not expand the assumption).
3. Arm A: depart_clean must directly include !xfs_is_shutdown + log-clean,
   not just ctx->withdrawn. put_super synchronously+idempotently persists
   WITHDRAWN before DLM teardown; on stamp failure fail closed (retain
   ACTIVE, never zero). Refactor into a common helper with bounded waits;
   audit joins vs s_umount/workqueue deadlocks; safety must not require the
   join to succeed.
4. Arm C: slot zero only AFTER unmount record + all prior FS writes durable
   (storage ordering, not call ordering; flush/FUA). On unmount-record
   failure: slot stays ACTIVE or recovery-required. CONSUMABLE redefined:
   "recovery completed durably OR clean unmount completed durably".
5. single_node/no-PR: recovery without fencing OK only as HARD enforced
   exclusivity (exclusive bdev open, no shared path) with explicit flag
   (e.g. FENCE_NOT_REQUIRED_SINGLE_NODE) — never infer from "PR unsupported".

## Flagged hazards
- Abandoned GUARD takeover (crashed recoverer): defined prover-fence-prover
  takeover; never abandoned-GUARD→CONSUMABLE directly.
- ABA/incarnation on guard ownership: CAS + generation ids required.
- Owner must not write after WITHDRAWN visible (quiesce-before-stamp).
- Whole-cluster restart with MULTIPLE dirty slices: may need a coordinated
  recovery barrier before normal mutation (cross-slice ordering unproven
  until lineage gen4).
- Mixed-version fleet: interpretation change of on-disk states — old
  kernels must not mount once new semantics emitted (proto-gen machinery).
- GOINGDOWN NOLOGFLUSH is crash-equivalent for slot disposition, always.

## Implementation order chosen (sess180)
Fix 1 Arm A sync-withdraw fail-closed (small, verify via immediate-umount
repro expecting P163-WITHDRAW-STAMP). Fix 3 Arm B claim-path (needed for
vergate mixed_build PASS; claim-time guarded recovery must sit AFTER the
envelope proto-gen admission refusal so the refusal legs stay
zero-recovery). Fix 2 Arm C release-after-unmountfs (structural,
pr_late_key already models the split). Verify: mixed_build arm full PASS
then 32/caw board (fence_during_write + crash_consistency watch).
