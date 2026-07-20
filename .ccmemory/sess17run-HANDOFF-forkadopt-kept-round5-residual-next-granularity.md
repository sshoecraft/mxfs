---
name: sess17run-HANDOFF-forkadopt-kept-round5-residual-next-granularity
description: sess17(ccloop) HANDOFF: KEEP build 9AF854E6 (fork-adopt, dir_reuse 8/tcp round1 fixed). Residual=round-5 data-block revert. Core wall=signal granular…
metadata:
  type: project
---

## sess17 (ccloop) HANDOFF — dir_reuse 8/tcp

### State: build 9AF854E62C318B799F513FB (in /src/mxfs/mxfs.ko, ready to deploy). KEEP.
- Carries the **fork-adopt handoff fix** [[sess17run-FIX-forkadopt-handoff-round1-fixed-round5-residual]]: fast-path dir reload uses post_release=dir_ex_handoff (true only on grant_gen-change/epoch-advance handoff). **dir_reuse 8/tcp failure moved ROUND 1 → ROUND 5.** No timeouts/corruption. This is the only stable gain; everything else this session was refuted+reverted.
- Default config == fork-adopt only. 8/tcp full suite: 12 PASS, dir_reuse FAIL(0/8) + cascades (fence_during_write/soak/tcp_dlm_scaling — all cascade from dir_reuse wedging). 2/tcp & 4/tcp dir_reuse PASS. **dir_reuse_coherency is the SOLE 8/tcp blocker.**

### Residual: round-5 single-entry DATA-BLOCK revert
After rm-rf+recreate, one first-dirent (e.g. node3_f1) lost. P13-STALEREAD: a node RMWs a near-EMPTY stale REUSED-daddr block over a peer's committed dirent. sameincarn=1 (same-owner, same-incarnation, stale-TENURE content). Round 1 (fresh-dir sf→block conversion) is FIXED; round 5 (reuse-churn data block) is not.

### THE CORE WALL (proven this session): signal GRANULARITY mismatch
- Any PER-MODIFY staleness signal (master dir_epoch, i_dlm_dir_gen — both bumped by note_dir_modified on EVERY create) over-fires under the 8-node storm → invalidate→cold-read storm → ~1900 DLM acquire timeouts (RULE-0 fail). REFUTED both acquire-side evict and read-side xfs_da_read_buf epoch check [[sess17run-REFUTED-epoch-invalidation-both-sides-causes-dlm-timeouts]].
- The PER-HANDOFF signal (grant_gen tenure token) is the right granularity (won't storm) but is edge-triggered and under-fires ~80% on TCP (sess61).
- Blanket force-evict drops CURRENT-tenure un-drained blocks (round 5→3, 24 entries). Release-invalidate (dir_release_invalidate=1) fired 0× (keep-guard skips all release-time blocks).

### NEXT DIRECTIONS (untried, for fresh session):
1. **Make grant_gen reliable on TCP** (dlm/dlm.c grant path — fix the edge-loss so the per-handoff token is delivered on every grant). Then a per-handoff (not per-modify) data-block refresh becomes possible without the storm. This is a DLM-transport fix, distinct from all buffer-layer attempts.
2. **Targeted single-block refresh**: refresh ONLY the specific block being RMW'd at modify-time if its tenure token lags — but gate on per-HANDOFF token (not per-modify gen/epoch) to avoid the storm.
3. Do NOT retry: per-modify epoch/gen invalidation (timeouts), blanket evict (drops current work), the existing release_invalidate param (doesn't fire).

### Diagnosis infra: tests/suite/dir_reuse_coherency.sh streams dmesg to /src/mxfs/tests/tcp/drc_cap/stream_rankN.log (NFS, survives node reboot) when DRC_STREAM=1 — set it for capture. Reboot ALL 8 clean (virsh destroy+start) before every run. Criterion NOT met; marker NOT written.</body>
