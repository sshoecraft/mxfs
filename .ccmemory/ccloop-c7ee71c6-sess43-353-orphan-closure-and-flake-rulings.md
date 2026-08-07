---
name: ccloop-c7ee71c6-sess43-353-orphan-closure-and-flake-rulings
description: sess43: 0.11.353 guard+UBSCAN closure SHIPPED+LIVE-VERIFIED; chk orphan audit verified; user flake directives; 5 flakes attributed; 10 OPEN
metadata:
  type: project
---

# sess43 (ccloop c7ee71c6 session 25) checkpoint

## USER INTERACTION (three direct messages — directives to honor)
1. "Last week green, now half the tests DONT WORK" → root: showstat FLAKY display counted RIG failures (pre-assert/killed-run/prep-fail from the Aug1 test32-disk-full cascades) as test flakes.
2. "Set them to FLAKY and figure it out" → FLAKY label must STAY for genuine test-detected failures; do NOT relabel to PASS; infra-caused history exclusions are OK. showstat.sh now: status column = current verdict EXCEPT genuine-fail history ⇒ ⚠ FLAKY; jq filter excludes pre-assert|NO_TERMINAL_RECORD|run was killed|prep fail; prep_cluster+open_defects never flake; open_defects row shows [live ledger: N OPEN].
3. "Flaky and production don't mix" → every flake needs a ledger defect + root-cause fix; aging out is NOT closure.

## FLAKE ATTRIBUTIONS (all 5 done)
- rsync_paired 07:28Z test21 = D-RELABORT-...-SELFFENCE incident (FIXED AND VERIFIED). Recorded in ledger evidence.
- dir_reuse ×4 = PACE (checks=7*rounds+2; 51⇒7 rounds < floor 8). Same build did 6..10 rounds across one day; 32-node margin was ALWAYS ~1 round (cawd Jul25=9, cawp=9, tcp=11); Jul-28 GitHub status.md has the SAME r7 FAIL. Symptom of D-32NODE-SHARED-DIR-CREATE-PACE (OPEN); closure bar written into ledger: median ≥10 rounds @32/caw quiet rig ×10 consecutive.
- scaling_curve 16:25Z = same pace family (rate/window checks).
- cache_coherency 23:32Z + zsl 23:34Z = D-BOARD-COLLAPSE-2332-VERGATE-ARM-WINDOW (NEW, OPEN): board-active cluster collapsed (31 mounts lost, 5 preps failed) in the window where vergate hb fake-writer arm + test32 disk-full overlapped. Repro plan in ledger next_step (8-node: vergate hb arm DURING cache/zsl loop; separately root-disk-full). Safety property: fake incompatible HB writer must never fence live members.

## SHIPPED 0.11.353 (srcversion 342A1945862622094889DEC) — orphan-family closure
- disklock.h/.c: MXFS_DISKLOCK_FLAG_RECOVERY_GUARD (=3) + guard_slot/guard_refresh/unguard/slot_unclaimed (CAS from stored image; noncaw write-verify fallback; stale=62s window claimable). Claim pass-2 (both variants) skips FRESH same-gen guards. Monitor/join-gate/vergate/active_count unaffected (all key flags==ACTIVE).
- v5_mount: passthroughs mxfs_v5_dlm_{local_slot,slot_unclaimed,guard_slot,guard_refresh,unguard_slot}.
- xfs_mount.h: m_mxfs_reap_duties (MXFS_REAPF_OWN_RESCAN=0, MXFS_REAPF_UBSCAN=1).
- xfs_mxfs_dlm.c: mxfs_own_bucket_rescan (mount-settle + P87-REAP-ADD-ENOMEM re-arm); mxfs_unclaimed_bucket_scan (guard→sweep→unguard per non-empty unclaimed bucket + one orphan_scan; P99-UBSWEEP-*); duties run in reap worker, armed at defer_reap_init(+20s) and at end of foreign replay batch; orphan scan candidates now under mxfs_ag_dlm_lock (ILOCK→AG order, nests via pag_dlm_holders) fixing the >2-node membership-walk coherency hazard (GPT hazard 2).
- VERIFIED LIVE on 2-node: P99-GUARD slot=8 CAS election → P97 walked=1 → P89-REAP-DONE ino=136 (the 352-era chk-repaired leak, freed); unlinker_death 2/2 PASS on 353 (+ post-recovery UBSCAN trigger observed); orphan_audit_arm NEG+POS PASS (ino=4194435: detect exit4 → repair exit1 → recheck exit0; converged online after arm by single-node dirty-mount recovery — comm=mount P82-REM bucket=3).

## REAPER MECHANISM INVENTORY (complete, each observed live)
1. survivor sweep+orphan scan (death) 2. mount dirty-log recovery: OWN bucket only, ALL 64 iff mxfs_v5_dlm_is_single_node (sess40 F1 scoping, xfs_log_recover.c:2972) — clean/covered log ⇒ никакой pass 3. OWN_RESCAN mount-settle 4. UBSCAN guarded pass 5. chk offline audit/repair (-y inserts bucket agino%64, GPT-ruled no offline free). Open-defer/gen/nlink gates protect live opens everywhere. Durable-bucket-until-free invariant verified: xfs_inode_uninit does difree+iunlink_remove same trans; xfs_inode.c:4691 standalone remove only for peer-already-freed.

## GPT RULING (this session, on the cold-side design) — key points implemented
Option A guard (not inode-EX-only, not quiesce); triggers = formation-settle + recovery-batch + takeover-by-rediscovery; chk repair stays bucket-insert agino%64; no reap-list persistence needed given durable-bucket invariant; two-bucket moves must be single-trans (NOT implemented — adoption uses insert-only on bucketless, which is safe); own-bucket rescan for lost reap entries (done: ENOMEM re-arm).

## STATE / NEXT
- Rig: 2/caw on 353 (test1 slot4, test2 slot5); marker stale (claims 2/caw 73507B) — re-prep before run.sh use. Tree VERSION=0.11.353. showstat.sh reworked. Ledger: 30 entries, 10 OPEN (added D-BOARD-COLLAPSE-2332; D-DESTAGE-TEAR still OPEN pending 32-node board).
- NEXT (order): (1) 8/caw prep → D-BOARD-COLLAPSE-2332 repro (vergate hb arm DURING cache_coherency+zsl loop; then root-disk-full arm) (2) 32/caw prep → full board on 353 + opener_death + matrix → then D-DESTAGE-TEAR → FIXED AND VERIFIED with the whole evidence chain (3) pace arc D-32NODE-SHARED-DIR-CREATE-PACE (protocol-IO decomposition; closure bar in ledger) (4) C9 TCP open tracking; certified-replay arc; remaining OPEN defects.
- Residual noted: joiner-vs-guard race arm not built (CAS-arbitrated, same geometry as verified P130 claim race); guard >62s-stall-inside-one-AG loss window accepted (four independent free gates below it) — documented here per RULE 6 honesty, both are verification debts not known defects.
