---
name: ccloop-c7ee71c6-sess32-adopted-slice-suppression-shipped
description: 0.11.274: mount-time arm shipped — pass-2 disklock claim marks slice ADOPTED, recovery suppresses untagged images+intents (P223 adopted/P226); rejoin…
metadata:
  type: project
---

# sess32 — mount-time adopted-slice suppression (0.11.274, C05C5DC0D73EB7E9749B1ED)

## Mechanism
- disklock claim (BOTH variants: CAW + non-CAW fallback) records which pass
  won: pass-1 = own ACTIVE stamp reclaim (nobody replayed us — full recovery
  REQUIRED and safe, grants quarantined); pass-2 = fresh claim
  (`ctx->slice_adopted`, claim log prints "fresh claim — slice ADOPTED").
- Plumbing: mxfs_disklock_slice_adopted → mxfs_v5_dlm_slice_adopted →
  mp->m_mxfs_slice_adopted (set in xfs_super after v5_dlm_init) →
  xfs_log_mount sets XLOG_MXFS_ADOPTED_SLICE (bit 6) before xlog_recover.
- New predicate xlog_is_mxfs_untrusted_replay = foreign || adopted. Pass2
  item loop: intents skipped (P226-UNTRUSTED-INTENT-SKIP, xfs_warn — for
  adopted this abandons the dead incarnation's incomplete intents for good,
  counted leak chosen over late unsynchronized intent processing);
  buf/dquot/quotaoff/icreate skipped (P223 with src=foreign|adopted);
  inode records cc-gated (xfs_inode_item_recover now uses untrusted).
  FOREIGN-only behavior unchanged for the finish steps (adopted IS the real
  mount log — tail assignment, sb reread, percpu reinit still run).
- Knob mxfs.adopted_slice_full_replay (default 0; 1 = legacy full replay).

## Why pass-1/pass-2 is the right predicate (no false suppression)
- Whole-cluster crash restart: every node reclaims its own surviving stamp
  (pass-1) → full recovery ✓. Fast reboot before death detection (the
  crash_consistency shape): stamp survives → pass-1 ✓. Single node: ✓.
- Pass-2 with live cluster: my old stamp was ZEROED (replayer finished) or I
  am new — slice dirt is an already-recovered incarnation's → suppress ✓.
- mkfs-fresh first mounts: pass-2 + clean slice → suppression no-op (one
  xfs_notice line per fresh-claim mount, harmless).

## Rejoin A/B (same build, real kills via tests/foreign_replay_ab.sh)
- test11 killed → live replay (7 P223 skips at survivor) → VM restart → NFS
  mount by hand (fresh boot has no /src!) → prep_node.sh caw → claim says
  ADOPTED, mount notice, **7 XFS_LI_BUF images suppressed (src=adopted)**,
  "Ending recovery" clean, node sees its full pre-death acked data 40/40/40.
- test12 same flow with MXFS_EXTRA_MODARGS='adopted_slice_full_replay=1' →
  ADOPTED still detected, NO suppression (legacy full replay), knob reads 1.
- Guard board 0.11.274 after full re-prep: cache_coherency 26s,
  crash_consistency 77s, dirent_durability 66s, dir_reuse_coherency 112s —
  all PASS 32/32.

## Rig facts worth keeping
- A freshly booted test VM has NO /src (NFS) — mount it manually before
  invoking prep_node.sh directly (prep_node mounts NFS only if the script is
  already reachable, chicken-and-egg).
- prep_node.sh without prep_fs.sh = module reload + mount, NO mkfs — the
  exact rejoin flow; MXFS_EXTRA_MODARGS feeds insmod args (knob control at
  module load).
- After every mkfs/prep, ALL nodes are pass-2 "ADOPTED" with clean slices —
  expected, no-op.

## Still OPEN on this defect (D-FOREIGN-REPLAY-UNGATED-IMAGES)
Residuals: held-at-death unlanded records of skipped types now applied by
NOBODY (bounded durability gap); adopted-intent skip leaks incomplete
extent-frees (P226-counted). Close via the full GPT protocol: authority
tokens {resource, grant incarnation, tenure} in log records + durable
held-set manifest + IMAGE_REPLAY_DONE marker. Prereq: task-4 root fix
(released ⇒ landed invariant) per GPT ordering.
