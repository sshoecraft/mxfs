---
name: sess16run-SYNTHESIS-next-target-PRtoEX-upgrade-grant-bypasses-drain
description: sess16(ccloop) SYNTHESIS/next-target: bast_process drain-before-unlock ordering is CORRECT (Inv-1 holds on the main handoff). So the dir_reuse clobbe…
metadata:
  type: project
---

## sess16 (ccloop) — SYNTHESIS: the unrefuted root is the PR→EX upgrade grant path

### Code fact established (cheap read, no run)
mxfs_dlm_bast_process (xfs_mxfs_dlm.c:5592) orders correctly per Invariant 1: drain (log_force + targeted AIL/alloc drain + mxfs_dir_data_durable/flush_data_blocks, ~5759+) happens BEFORE the final mxfs_v5_dlm_inode_unlock. So when a node RELEASES EX on a BAST (full acquire→NL→reacquire handoff), the peer is granted only after our drain → that path serializes correctly.

### Therefore the clobber is NOT on the release-BAST path — it's the DIRECT GRANT path
dlm/dlm.c:512-527 (sess35) documents: a DIRECT grant that KEEPS the grantee holding — a **PR→EX UPGRADE** (dlm_lock_impl / process_remote_request conv_compat) or a remote **REAFFIRM** — is decided ONLY against conflicting GRANTED holders and fires NO BAST / does NOT route through bast_process. [[sess51-ROOT-tcp-dlm-scaling-is-symmetric-PR-EX-dir-upgrade-livelock]]: bash open(O_CREAT) does lookup(dir PR) then create(dir EX); mxfs CACHES the PR, so create is a PR→EX UPGRADE on the hot shared dir.

### Why this unifies EVERY refutation this session
The node upgrading PR→EX held ≥PR continuously (never went NL) → NO handoff/epoch/grant_gen transition is detected → the reload-on-acquire never runs → the dir block buffer read under the prior PR (possibly stale if the PR itself was served stale, or if the upgrade races a peer's just-released EX) is carried into the EX tenure and RMW'd. This is why ALL of: read re-read (gen/grant/epoch needs a handoff signal), force_coherent (keep-guard keeps the buffer), dir_release_fua_write, and dir_release_invalidate (only fires on the bast_process RELEASE path, which the upgrade bypasses) — FAILED. None of them touch the upgrade path's stale base.

### NEXT SESSION — decisive plan (RULE 4)
1. INSTRUMENT: in dlm/dlm.c at the PR→EX upgrade / REAFFIRM direct-grant sites, log (ino, old_mode, new_mode, grantee, grant_gen) always-on for dir inodes. AND in the XFS upgrade path (mxfs_dlm_ilock_begin when going PR→EX without a fresh acquire), log whether a reload/evict runs. Reproduce dir_reuse mht=50; confirm block0 modifies happen under a PR→EX-upgraded EX with NO reload.
2. FIX candidates: (a) on a PR→EX upgrade of a DIR inode, FORCE the full reload+dir-buffer-evict pipeline (treat upgrade like a fresh acquire — adopt disk superset, invalidate cached blocks) before granting the modify; (b) make the upgrade go PR→NL→EX (clean reacquire through the reload path) instead of a direct upgrade, for DIR inodes only; (c) on the master, route PR→EX upgrades on a contended dir through the BAST/drain path so peers serialize. Lever (b) is closest to GPT's "drop below PR ends the tenure" model [[sess16run-GPT-design-tenure-scoped-dirbuf-coherency-FIX]].
3. VALIDATE: P-DIRWR daddr=120 count monotonic at mht=50; dir_reuse 8/tcp PASS; tcp_dlm ≤60s; 17/17; 1/2/4. Canaries unlink/rename_visibility/crash_consistency PASS.

### Build 42178C17 (new logic gated off at default; mht=300 dir_reuse PASS unregressed). Criterion NOT met.</body>
