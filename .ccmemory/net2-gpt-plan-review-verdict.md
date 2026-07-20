---
name: net2-gpt-plan-review-verdict
description: GPT NET2 verdict (07-17): build it, but NO one-pass. Stage 1 = reliable midcomms over DIRECT mesh + fence-before-reclaim. Defer overlay/shards/delega…
metadata:
  type: project
tags: [net2, gpt-consult, dlm-plan, verdict, staging]
---

# GPT verification of DLM_PLAN.md / new_dlm.md (2026-07-17, gpt-5.6-sol)

Full reply of record: **/src/mxfs/DLM_PLAN_REVIEW.md** (committed alongside the plan). Input = both docs verbatim + the 15-item errata from [[net2-plan-rescan-errata-0.10.120]].

## Verdict
Safety model sound; **no-go as a one-pass executable plan** — it bundles five hard distributed-systems projects (midcomms, overlay, membership/fencing, 1024×3-replica sharded logs, CAW envelope). Approve NET2 as a direction; build the SMALLEST version that fixes the proven defect: **reliable, incarnation-qualified, effect-idempotent midcomms over DIRECT peer links (keep full mesh), mandatory fence-before-reclaim, XFS drain pipeline unchanged.**

## Cut order (defer, in order)
1. CAW envelope mode (indefinitely; current envelope record already stale vs real slot semantics — yield_to/yield_set_ms/ex_grant_streak/waiters_ex/dir_block0/tombstone/is_free reset).
2. Renewable PR delegations + hot-shard migration.
3. Routed overlay ("walls at ~16" unproven; real defects = lost transitions + wholesale purge; attack thread count via socket multiplexing first if needed).
4. 1024-shard 3-replica election service (HRW remap ≠ safe consensus reconfiguration — old and new groups can both get 2-of-3; keep hash-master + gen-qualified idempotent ops + fencing; wholesale purge-after-fence acceptable initially if within budget).
5. CAW-written epoch ledger (contradicts the CAW-unreliable product case — A14).

## Staged plan (each stage RULE-0 gated)
- **Stage 0**: protocol spec + observability (wire constants/endian, identity defs, counters, fault-injection controls, port registry, golden vectors + fuzz, dual-build green).
- **Stage 1**: reliable midcomms over existing direct mesh + effect-idempotent ops + nonzero gen tokens + both BAST families; keep hash mastership; gate = 1-32 nodes 100% suite incl. injected loss/dup/reorder, zero overlapping grants, zero silent discard.
- **Stage 2**: NET2-owned SUSPECT/freeze/fence state machine; eliminate timeout-alone DEAD; one committed recovery view integrating foreign-slice replay; gate = kill-mid-drain/partition-with-LUN-access/no-fence matrix with trace order fence < exclusion < replay < gen-advance < unfreeze.
- **Stage 3**: CAW reliable BAST wakeups (accelerator only; disk poll stays correctness fallback; gate incl. drop-all-NET2-BASTs → correctness unchanged).
- **Stage 4**: incremental recovery / replicated buckets ONLY if purge fails budgets.
- **Stage 5**: overlay ONLY if 64-node mesh measurably fails on threads/CPU.
- **Stage 6+**: delegations, migration, envelope (own feature bits, default-off soak).

## Key amendments (full A1–A24 list in DLM_PLAN_REVIEW.md)
A3 do NOT reuse inert hdr.seq as op identity — allocate NET2 request IDs; handlers retain completed-op state. A6 incarnation must NOT come from boot-relative mxfs_pal_time_ms (persistent per-slot monotonic and/or large random nonce; equality not newer/older; widen past u16). A9 flow control fully specified; queue exhaustion of BAST/RELEASE/ACK = fail-closed freeze, never silent drop; reserve capacity per subclass (RELEASE/RELEASE_ACK outrank repeated BASTs — 3.5). A11 grant_gen nonzero + wrap policy (XFS treats 0 as CAW). A14 ONE membership authority tuple {epoch, member_mask, slot→incarnation, fenced_mask}; existing lease/disklock = observers; three product configs (CAW-capable / CAW-unreliable+fence / no-fence=refuse-or-frozen-posture). A15 NET2 owns its freeze state (memb_settle plumbing is TCP-struct-local); freeze must be reason-coded, budgeted, test-visible (3.4). A16 ADD the missing recovery generation-advance step (lease_expire has none) with the 8-step ordering. A18 fencing: CAW gen-change is not a storage fence for pure NET2; PR must confirm on all multipath paths; fence callbacks incarnation-qualified. A19 ports: name LEASE_LEGACY 7602 vs LEASE_V5 7603 explicitly; don't silently change legacy. A24 dual-build/wire-lifetime section (endian, no native-struct wire, static asserts both builds, callback lifetime, no kernel pointers as identity).

## Holes flagged (§3)
Two-membership-authorities problem + bootstrap circularity (3.1); CAW-dependent epoch ledger in the CAW-unavailable case (3.2); shard-vs-replay barriers (3.3); freeze-as-outage vs RULE 0 (3.4); intra-class priority inversion (3.5); unauthenticated fencing messages / 32-bit uuid hash (3.6); volatile replica state + simultaneous restart (3.7); waiter/fairness state absent from lock record (3.8); resource lifecycle/tombstone ABA without incarnation in resource_id (3.9).

## Fault matrices (§5)
Midcomms loss/dup/reorder/delay/backpressure/restart/epoch/wrap/malformed with required counters + invariants; shard failover 12 kill-points × 8 partition patterns (if shards kept); fencing kill-mid-drain at every phase boundary, partition-with-LUN-access variants, no-fence postures, existing-infra injections (fs_gen re-mkfs, evict-ring wrap, MDS failure, ever_multi). RULE-0: freeze/fence/replay times recorded per test; "freeze forever" is safe but not testable — bounded reason-coded frozen result within budget.

## Status
Awaiting user decision on adopting the staged scope (fold A1-A24 + stages into DLM_PLAN.md, or discuss). No net2 code exists yet.
