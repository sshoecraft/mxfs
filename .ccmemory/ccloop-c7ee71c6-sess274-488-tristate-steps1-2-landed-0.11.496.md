---
name: ccloop-c7ee71c6-sess274-488-tristate-steps1-2-landed-0.11.496
description: sess274: D-488 tri-state unlock steps 1+2 LANDED+BUILT 0.11.496 sv 00117B42 (enum, caw body classification, AG deadline, v5 wrapper verify); steps 3-…
metadata:
  type: project
---

# sess274 — D-488 birth fix: steps 1+2 of the sess273 ruling landed

Build: **0.11.496 srcversion 00117B428686D1FE460BD29** — clean `make clean && make modules`, NOT deployed (rig wedged, needs full re-prep first).

## What landed
1. `enum mxfs_unlock_state { UNKNOWN=0, RELEASED, STILL_HELD }` in `include/mxfs/mxfs_dlm.h` (UNKNOWN deliberately 0 so unset out-param fails closed).
2. `dlm/dlm_caw.c caw_unlock_gen_body(+enum mxfs_unlock_state *state_out)` — every exit classified:
   - find_slot -ENOENT → RELEASED + `P274-AGUNLK-NOSLOT` (AG only, anomalous for held EX; clean own-bit read through same target IS authoritative)
   - find_slot other err → UNKNOWN + `P274-UNLK-FINDSLOT-ERR`
   - NL-no-bit early exit → RELEASED
   - CAS hard err → UNKNOWN + `P274-UNLK-CAS-ERR` (UNKNOWN even when caw_may_have_written=false — no read-back proof either way)
   - committed CAS → RELEASED
   - retry exhaustion -EIO → STILL_HELD (all miscompares = proven never wrote)
   - regrant_abort / -ESTALE gen-mismatch / lreq-dry -EIO / ENOMEM / -ESHUTDOWN gate → STILL_HELD
   - INODE/ICLUSTER deadline **type gate removed** — AG unlocks now get MXFS_CAW_UNLOCK_DEADLINE_MS (5s) wall clock under mxfs_caw_unlock_backoff, not just the 100-retry cap.
   - New public `mxfs_dlm_caw_unlock_state()` (gate + body with out-param); legacy wrappers pass NULL. Direct body caller in convert path (NL downgrade, ~10060) passes NULL.
3. `dlm/v5_mount.c mxfs_v5_dlm_ag_unlock` void → returns the enum. CAW: body UNKNOWN resolved by one `mxfs_dlm_caw_held` read-back (1→STILL_HELD, 0→RELEASED, err→UNKNOWN; `P274-AGUNLK-VERIFY`). TCP: rc==0→RELEASED else UNKNOWN + `P274-AGUNLK-TCP-ERR`. `v5_mount.h:427` updated. All 4 xfs_mxfs_dlm.c callers (42216 worker, 42274 force_release_all, 43781 release_work_fn, 43883 iodone fallback) still discard the return — compiles; step 3 wires the worker.

## Remaining (steps 3-8) — full detail in .ccloop/handoff.md sess274
Worker outcome machine (STILL_HELD re-arm via real acquire path — note COMMIT at 41883 CLEARS bast_pending so the re-arm must re-set it; lineage_open closed at 42203 so re-acquire fires no P130), rx stuck-latch watchdog, caller logging, re-prep + deploy, fault-injection verify, ledger updates incl. ruling leg v (fence-confirmed dead-holder purge decoupled from replay freeze).
