---
name: AAA-ccloop7251-sess7-mht-quietgate-wedge-chain-fixed
description: sess7: cc@32 79s->~60-62s via MHT quiet-age gate (grace=40) + clock/lie fixes; 470s ABBA wedge chain (4 defects) diagnosed+fixed; builds 0.11.22-26
metadata:
  type: project
---

# sess7 (ccloop 72513a13) — cc@32 pace + the ABBA wedge chain

## Landed builds (all deployed+validated at 32/cawd)
- **0.11.22 FIX1**: resource-scoped orphan/starve clocks cleared after a completed
  wire unlock (~14240). Killed 72 spurious gen-blind P15H forces/run (they fired
  every 3s per hot ino per node; proven force 0.4s after successful EXIT=full).
- **0.11.23 FIX2**: MHT quiet-age gate. `i_dlm_tenure_lastop_ns` stamped at every
  ilock_end; `mht_defer_bast` arms dwork in GRACE SLICES (was full 300ms window
  → idle grants slept the whole floor; ilock_end 25ms arms hit already-armed);
  dwork releases young-window tenure once quiet ≥ grace (one-shot 15ms).
  **dir_ex_batch_grace_ms: 25=68s 40=61/56s 60=78s → default 40 (0.11.26).**
- **0.11.24-26 FIX3/4/5** (GPT RULE-5 consult, full ruling in sess7 transcript):
  - FIX3 honest `mxfs_iclus_unlock` rc (int now: 0 cleared/no-op, -EBUSY declined,
    urc fail). Pipeline: decline → `p_iclus_declined` → SKIP the FIX1 clock clear
    (keeps 3s rescue armed) but complete pipeline normally (mapping decline to
    -ESTALE/stranded retry-stormed 1000+ P6G/node = 82s run — reverted).
  - FIX4 both `p135_gg` consultations TCP-only (GRANTWIN-PARK + ORPHAN-RELEASE
    gg==0 gate): CAW grant_seq freezes in the lossy bucket (gg=1533 parked 1500
    BASTs forever); CAW's mid-completion signal is `i_dlm_acq_inflight`.
  - FIX5 `mxfs_iclus_pi_reconcile`: entry-orphan pipelines ONLY (p_held_mode==NL
    — gating it that way matters: unconditional cost a wire read per routed
    release = +10-15s on cc). Clears a sticky-routed inode's orphaned per-ino
    holder bit post-drain (mode-0-shell-era leak; conversion's mode!=NL gate).

## The captured 470s ABBA wedge (WHY cc@32 wedged ~p1/3 at grace40 on 0.11.23)
test5 held dir EX + waited per-ino EX on recycled file (nested create, mode-0
shell routes PER-INO); test29 held that file's per-ino EX bit orphaned (in-core
NL, sticky routed=TRUE) + waited for the dir; 30 nodes queued. test29 couldn't
release: release routes cluster-ward (sticky) → release_check declines
(covered_active) → hardcoded p6u_rc=0 lie → FIX1 cleared rescue clocks → 3s force
never armed; P135-GRANTWIN-PARK (frozen gg) parked all BASTs. 4 defects, all fixed.
0 wedges in 6 subsequent runs.

## GPT ruling essentials (for later phases)
- Routing must be deterministic from persistent state; mode-0-shell window is the
  split-brain source (nodes disagree per-ino vs cluster for same ino) — remaining
  KNOWN HOLE: mode-0 per-ino winner vs peer's cluster coverage (double-EX class,
  guarded by old coresident-clobber guards; future fix = acquire-side re-route
  validation after dinode read).
- Never rely on timeout-force as steady-state; dir/child ordering fix
  (try/drop/reacquire/revalidate) is the real ABBA cure if it recurs.
- Raw unlock of an orphan needs drain proof — pi_reconcile is safe ONLY because
  the pipeline just ran the full drain (invariant #1).

## State @ session end
- cc@32 on 0.11.26 (D1AA15A0): 60s, 70s, 62s (bar 60; functional 3021/3021 every
  run). close_release=0 RUNTIME still required (module default 1 — TTL design
  pending). Remaining cc excess: run variance (stall outliers) + verify-phase
  per-op cost (rv-verify ~12s) + write-phase rotation floor.
- Next: variance hunt on slow runs; then 8/16 regression check (quiet-age gate
  changed handoff timing at ALL scales — MUST re-run 8/cawd + 16/cawd boards);
  then drc/fairness@32; then close_release TTL; then tcp/cawp/caw ladders.
