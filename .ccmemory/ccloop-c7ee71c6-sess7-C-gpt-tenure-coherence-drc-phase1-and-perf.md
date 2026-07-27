---
name: ccloop-c7ee71c6-sess7-C-gpt-tenure-coherence-drc-phase1-and-perf
description: sess7-C: GPT tenure-coherence ruling (grants≠coherence; gen0=unknown; LVB cookie phase-2); drc phase-1 landed unverified; dlm_scaling@16 fixed 39→55/s
metadata:
  type: project
tags: [gpt-design, tenure-coherence, readdir, drc, dlm-scaling, grant-episode]
---

# sess7 part C — GPT coherence ruling, drc phase-1, unlink-probe perf fix

## GPT RULE-5 consult (full text in sess7 transcript, search "Executive diagnosis")
Core ruling: **DLM acquisition establishes ordering/exclusion, NOT cache
coherence.** State is valid only if loaded under the current uninterrupted
PR/EX tenure or an authoritative modification cookie. Async evict-ring events
must be optimizations, never correctness inputs. gen==0 must mean
UNKNOWN→refresh, not no-refresh. `mode!=EX` refresh exclusion is wrong — EX is
exclusion, not validity; an EX holder mutating after a grant gap can relog a
stale base (candidate producer for drc Shape 2). drop_caches does NOT purge
xfs_buf metadata buffers — "pureLUN" probes don't disprove cached-stale-leaf.
Phase 2 design: per-dir modification cookie in DLM LVB (advance at EX release
after drain; compare at grant; unknown⇒refresh) + per-buffer cookie validation
at xfs_da_read_buf covering node/leaf/free/data + inode-cluster; capture
cookie at I/O submit, discard if tenure changed during I/O; never retag a
cache hit. EX-acquire must refresh after gap before first mutation.

## drc family status (RULE-6 OPEN, the last correctness defect standing)
- Shape 1 (round-1 identical first-view undercount 112/128, self-heals):
  root per GPT = fork loaded before final EX tenure survives revoke+regrant;
  gen==0 gate skips reload. **Phase-1 fix landed v0.11.101**: per-inode
  `i_mxfs_rd_vgg` grant-episode latch (xfs_inode.h) + trigger
  `rd_gg != vgg` in xfs_readdir (rd_gg = mxfs_v5_dlm_inode_grant_gen; TCP arm
  returns per-lock grant_gen, 0 unheld — verified live code path); reload once
  per grant episode; dir_gen bump ONLY when reload proves fork delta
  (nx/size) so solo dirs stay zero-cost; vgg latched on any landed reload,
  not on bail. Plus 200×1ms bail retry (earlier). **UNVERIFIED**: ×3 green
  but P60-RDVGG=0 P48-RETRY=0 — the race not yet re-hit. Verification =
  batch dir_reuse@16 until failure (refutes) or P60-RDVGG catches a stale
  fork (proves). Pre-fix repro ≈ 1-in-3 batches of 3.
- Shape 2 (lookup_fail=3 persistent, readdir complete, cluster-wide,
  survives all probes; run 20260725T203759Z round 13): merged leaf timeline
  CLEAN (116→129 strictly increasing under EX; final durable count=129 ≥
  needed; all sub-EX republishes suppressed identical-crc dups) — so failure
  is stale cached DA-path buffer OR semantically-wrong-but-complete leaf
  (stale dataptr from EX stale-base relog). Next: GPT's per-name DA-walk
  trace instrumentation + at-failure cached-vs-raw-vs-P-DIRWR image compare.

## dlm_scaling@16/tcp rate-floor FIXED (v0.11.99)
P137-INACT fua stage = 17-47ms/unlink under 16-way = THREE raw target reads
per multi-node inactivation: FUA di_mode read + P103 divergence detector
plain read (detector-only by contract → now instr-gated) + coherent-nlink
plain read (consumed ONLY by !local_unlink guards B3/B4 → skipped under
LOCAL_UNLINK, sentinel 0xFFFFFFFF = the guards' own do-not-skip unknown).
39-40/s → 55-56/s (floor 50) PASS. DO-NOT-DO: skipping the di_mode/gen read
under clean-EX+local_unlink — b2 gen-mismatch skip deliberately fires even
then (tree refused the i_dlm_mode gate: "SILENT DISK CORRUPTION" comment);
sess37 leaked-LOCAL_UNLINK history. 32/caw dlm_scaling FAIL (6/7) likely same
class — re-run on ≥0.11.99.

## Version/board state at handoff
v0.11.101 (89303634BC49D202172AABD) on 16/tcp. 8/tcp board green 20/20 at
v0.11.98; 16/tcp rows mixed 99/100/101 — full single-srcver re-run needed
once drc closes. See state.md for the priority list.
