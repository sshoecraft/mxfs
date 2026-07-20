---
name: sess63-residual-root-crossnode-gen-divergence-reused-dir
description: sess63 PROVEN residual root: dir_reuse 4/tcp loses 1 dirent ~1-2/24 = pin-tailed stale prior-tenure dir buffer reused across EX handoff (all peers SA…
metadata:
  type: project
---

## sess63 — dir_reuse 4/tcp RESIDUAL: PROVEN root + acquire-side fix is a RULE-0 dead-end

### Validated baseline (build 5E78DEE0, KEEP): 1/tcp 16/16, 2/tcp 17/17 (re-verified after the experiments below — NOT broken), 4/tcp dir_reuse ~1-2/24 rounds lose exactly ONE dirent.

### PROVEN ROOT (RULE 4, decisive)
- DIRID probe (stat -c %i of the dir, every round): on a failing round ALL peers resolve the SAME dir inode (e.g. dirino=138). => NOT cross-incarnation divergence (the transient disjoint-gen shortforms seen in SF2BLK DO converge via the handoff reload). It is an INTRA-INODE single-dirent lost-update.
- P-DE-ENTER probe: `mxfs_dir_drain_evict_data_blocks` runs with gen==loaded on EVERY call (the lossy DIR_MODIFY evict-ring never bumps the gen for a peer mod on TCP, AND the handoff reload sets loaded=gen). So the coherence-forcing `xfs_log_force` (gated `any_pinned || gen!=loaded`, xfs_mxfs_dlm.c ~3960) NEVER fires on a handoff.
- Mechanism: node C re-acquires EX (handoff). Its cached copy of dir block B is a STALE prior-tenure buffer that is PIN-tailed (CIL unpin pending). drain_evict cannot evict a pinned buffer (clearing XBF_DONE on pinned corrupts, sess64) and the any_pinned TRYLOCK scan misses a momentarily-locked B, so no log_force -> the bounded per-block drain (50 iters/100ms) times out -> B is SKIPPED -> C RMWs stale B -> clobbers a peer's just-committed dirent. rank1 (dir creator) never loses (its own block wins).

### ACQUIRE-SIDE FIX = CORRECT BUT RULE-0 DEAD-END (tested, reverted)
Forcing the CIL on a genuine handoff (mxfs_v5_dlm_inode_grant_handoff signal) in drain_evict:
- SYNC log_force on handoff: ELIMINATED the loss (rounds 1-18 clean) BUT under the create storm the SYNC stall slowed rank1 ~2 rounds behind -> barrier timeout -> cascade EIO wedge (build A32F3152). Targeted SYNC (only pin-skipped blocks) still TIMED OUT at round 17 (build E682E45E) — pin-tails on handoff are COMMON not rare, so SYNC fires too often.
- ASYNC log_force(mp,0) on handoff: no wedge but the push doesn't complete within the 100ms per-block wait under log congestion -> loss returns (build 678BC4AF).
- Conclusion: you cannot cheaply distinguish the rare harmful pin from common benign ones at acquire, and CIL-pinned (not in AIL) has no LSN-targeted force shortcut. Acquire-side log_force is the wrong layer. ALL reverted to 5E78DEE0.

### NEXT DIRECTION (release-side, next session)
The pin-tail is C's OWN prior-tenure buffer. The fix: at C's EX RELEASE (bast path), ensure C's dir data buffers are fully UNPINNED (not just data-published) before granting away, so the next owner never inherits a pin-tail it must drain. Must be cost-bounded (RULE 0) — a blanket SYNC force at every release will have the same slowdown. Candidates: (a) only force-unpin dir buffers that are actually pin-tailed at release (rare); (b) make publish-before-notify also wait the CIL unpin for the dir's blocks; (c) a non-log-force way to let the next owner read the durable disk image over a pinned-but-already-published buffer (the DATA is durable via publish-before-notify; only the buffer struct is pin-locked). Entry: mxfs_dlm_dir_inode_durable + the dir data drain in the bast/release path (xfs_mxfs_dlm.c ~4858+). Probes in tree: P-DE-ENTER/P-DE-BLK (drain_evict), P62-SF2BLK names, mxfs-drc-DIRID (test). Handoff infra (sess63) KEEP. Repro: ./run.sh 4 tcp dir_reuse_coherency (clean virsh reboot test1-4). See [[sess63-handoff-signal-works-1of24-residual-writeside-block0]].</body>
