---
name: ccloop-c7ee71c6-sess36-dstale-exemption-removed-terminal-leak-closed
description: sess36: FIX-A self-disarm root = dss=5 (release's OWN cache mark); 306 removed dstale exemption; P244=306 P241=0 P220-terminal=0 verified
metadata:
  type: project
---

# sess36: dstale exemption removal — terminal-store obligation leak closed (0.11.305/306)

## Root (instrumented, RULE 4 complete)
FIX-A (303, P244-REL-TERMINAL-DEFER) never fired because its gate exempted `ip->i_dlm_stale` — and the release pipeline ITSELF sets `i_dlm_stale=true` (src=5) at xfs_mxfs_dlm.c:14275 (mxfs_dlm_bast_process cache-invalidate step, mid-pipeline, before the terminal store). 305 added `dss=` (i_dlm_stale_src) to P220-EPOCH-LEDGER-OPEN: census 459/459 leak events = dss=5. Category error: i_dlm_stale = next-tenure READ-cache staleness; says nothing about whether OUR committed writes landed.

## Fix (306, srcversion C281B7DF)
Removed `!ip->i_dlm_stale` from the terminal gate. Kept exemptions: S_ISDIR, XFS_ISTALE, dead_incarn_gen (dinc), shutdown. GPT review verdict: ship it; do NOT source-gate (provenance != contract); safe default for unexplained open obligation = retain grant.

Safety valves verified before shipping:
- strikeout (17604): >=2500 strikes -> 1s downshift, ~30min cap, then stops re-arming but KEEPS the grant + bast_pending — never force-releases past the gate.
- defer-retry cannot reload stale disk over the unlanded change: P184 reload_oblig_keep guard (mxfs_reload_oblig_keep, ~23230) refuses reload over open obligation when platter not newer (sets stale src=26).

## Verification (dir_reuse + crash_consistency @ 32/caw on 306)
- P244 defers = 306; P241-BLIND = 0; P220 terminal-store (line 14938 in 306) = 0. All realns-window-filtered (fresh >= 1785529458e9). CRITICAL LESSON: dmesg persists across module reloads — raw counts mixed 303/304/305 residue (epsrc=14919/14925/14926 = those builds' terminal-store lines). Filter by realns or dmesg -C at deploy.
- crash_consistency 32/32 PASS 82s/90s — defer latency did not damage the budget.
- dir_reuse still pace-FAIL only (rounds 4-7 vs >=8; host load 12-18 confound; residual = per-release wire-unlock protocol IO — ledger D-DIR-REUSE-COHERENCY-32-FLAKY).

## Remaining on D-RELEASE-BARRIER-OPEN
Terminal-gate instance closed. P219 class-X instance (xfsaild writes FREED inode images at NL) = D-INODE-CLUSTER-PUBLISH-WITHOUT-AUTHORITY mechanism — separate. If full board is clean with P241=0, re-scope the entry.

## Session-17 carryover still pending
- Board on 306: A-remainder (cache_coherency, zero_silent_loss) + B (rsync_paired, fence_during_write, fault_netpartition, soak, dirent_durability) + C (strong_consistency, posix_multi, mmap_coherency, dlm_fairness, dlm_membership, dlm_lock_correctness) + D (node_responsive, kernel_health, ag_strand_repair, sustained_load, dirent_publish_integrity, dirent_type_integrity).
- 303's board chunk A was green except dir_reuse pace; chunks B-D not run since ~302-303 era.
- Relocation of the src=5 mark to the terminal store (aborted releases leave live tenures spuriously stale): DEFERRED pending full release-exit audit (GPT concurs). Watch reload churn instead.
- 17 OPEN defects total; criteria = NOT production ready.
