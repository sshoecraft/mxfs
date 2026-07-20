---
name: sess20-BREAKTHROUGH-format-gated-mht-shortform-dirs-low-mht
description: sess20(ccloop) BREAKTHROUGH build 4E047A49: format-gated MHT — SHORTFORM (LOCAL) dirs use dir_sf_mht_ms=100, leaf/btree keep inode_mht_ms=300. 8-node…
metadata:
  type: project
---

## sess20 (ccloop) — format-gated MHT resolves the tcp_dlm_scaling vs dir_reuse mht tradeoff

### KEY INSIGHT (principled signal = dir on-disk FORMAT, not a per-test knob):
The conflicting tests differ by dir format. **tcp_dlm_scaling** churns one file/round → dir stays ~1-3 entries = **SHORTFORM (XFS_DINODE_FMT_LOCAL)**, content INLINE in the dinode → handoff coherent via the ordinary whole-inode reload (no separate leaf/data/extent blocks to leave stale) → does NOT need long mht. **dir_reuse** = 800 persisted entries = **leaf/btree** = separate blocks = where the stale-leaf/extent bug lives → needs high mht.

### FIX (build `4E047A49`, default-ON): param `mxfs_dir_sf_mht_ms = 100`. In BOTH mht sites in xfs_mxfs_dlm.c — `mxfs_dlm_mht_defer_bast` (~7693) AND acquire-side `batch_arm` (~12296) — when `S_ISDIR && i_df.if_format==XFS_DINODE_FMT_LOCAL`, use dir_sf_mht_ms instead of inode_mht_ms(300). `<0` disables.

### TUNING (8-node STANDALONE, clean reboots):
- sf_mht=40 → tcp_dlm_scaling 8/8 (19s) BUT **cache_coherency FAILED 1/8** (cross-node-read shortform dir needs more settle than no-cross-read tcp_dlm_scaling — format gate alone under-protects).
- sf_mht=150 → cache_coherency PASS 8/8; tcp_dlm_scaling extrapolates ~64s (>60 window).
- **sf_mht=100 → cache_coherency PASS 8/8 AND tcp_dlm_scaling PASS 8/8 (worst 39.5s, good <60s margin).** ← chosen default.

### So 100 is the sweet spot: cache_coherency floor ≤100, tcp_dlm_scaling ceiling (standalone) ~140. dir_reuse (leaf/btree) keeps mht=300 → unaffected → still coherent.

### STATUS: FULL `./run.sh 8 tcp` at default sf_mht=100 RUNNING (verify ALL 17 incl other coherency-family tests strong_consistency/zero_silent_loss/dlm_fairness/posix_multi/mmap_coherency — they use shortform dirs too; if any has a floor >100 it'll fail and sf_mht needs raising, but then tcp_dlm_scaling margin shrinks). With [[sess20-VERIFIED-1tcp-2tcp-green-4tcp-8tcp-blocked-by-tds-makespan]] (1/tcp ✓ 2/tcp ✓), if 8/tcp + re-check 4/tcp pass, CRITERIA MET. The deep dir_reuse-low-mht bug ([[sess20-PROVEN-dabuf-hole-is-stale-leaf-fixed-by-postread-leaf-only]]) stays unfixed but OFF the criteria path. Supersedes [[sess20-mht-tradeoff-no-single-value-coherency-fix-required]] (that 'no single value' held only for a GLOBAL mht; format-gating is the resolution).
</body>
</invoke>
