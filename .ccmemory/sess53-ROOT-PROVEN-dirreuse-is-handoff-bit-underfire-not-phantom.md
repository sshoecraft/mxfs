---
name: sess53-ROOT-PROVEN-dirreuse-is-handoff-bit-underfire-not-phantom
description: sess53(ccloop) RULE-4 PROVEN: 8/tcp dir_reuse single-loss is READ-staleness from handoff-BIT under-fire (P42=0, P51-UF>0), NOT phantom. Fix=grantgen…
metadata:
  type: project
---

## sess53 — 8/tcp dir_reuse_coherency ROOT decisively re-classified (RULE 4)

### Clean baseline (build 2A9ACF1E, no probes): round 11/18, ALL 8 nodes (incl creator)
durably miss ONE dirent (node7_f29.md5 / node1_f44.md5 — consistently an **.md5 sidecar**,
2nd create-wave, larger leaf-format dir). Count-preserving single-entry loss = stale-base RMW.

### DECISIVE diagnosis (tests/tcp/drc_phantom_diag.sh — clean reboot, full fail-dmesg grep):
- **P42-STALEEX-SERVE = 0 on ALL nodes** ⇒ NOT a phantom / mutual-exclusion break. The
  fast-path NEVER serves a dir-EX with held=0. This REFUTES the sess50/52 "phantom-EX"
  framing for the current build (that was the OLD broken TCP held-check era).
- **P51-HANDOFF-UNDERFIRE fires** (test1 4×, test3 1×): `ino=131 hgg=1003 cached_gg=808
  acted=808 — grant token advanced (lock changed hands) but handoff bit FALSE; fast-path EX
  serve on un-refreshed base`. ⇒ ROOT = READ-staleness: the master's edge-triggered handoff
  BIT under-fires, so the fast-path EX serve skips the base refresh and RMWs a STALE cached
  dir DATA block → durable clobber.
- MX-DOUBLEGRANT=0, P-STALEMASTER-GRANT=0 (master FIFO/compat serialization intact), NO
  membership flap (drc_cap8 flap-grep empty) ⇒ not master-divergence/table-purge.

### Mechanism: handoff bit = dg_grant_ex() `handoff=(last_owner!=0 && last_owner!=owner)`
(dlm.c ~2762). Under-fires for the hot shared dir even after the sess44 downgrade-promote
dg_grant_ex fix. The downstream chain (dir_gen_per_handoff=1 → read-path bgen<dir_gen
invalidation) WORKS but only when handoff is DETECTED — so the break is purely detection.

### Refuted THIS session (RULE 4):
- `dir_evict_prior_tenure=1` (aggressive read-side epoch-evict): did NOT fix the loss AND
  caused WORSE corruption (round 19 readdir=863/800, DUPLICATE dirents) — keep-guard bypass.
- `dir_epoch_adopt=1`: OUT — sess49 PROVEN 8/tcp 0/8 SHUTDOWN (post_release fork-adopt shrinks
  the in-core fork → DABUF_MAP_HOLE + AG double-free). The epoch ALSO derives from the same
  under-firing `handoff`, so it can't be the fix anyway.
- (dirwr=1 probe perturbation faked a DABUF_MAP_HOLE flood — IGNORE; not in clean baseline.)

### FIX (build 994CF57B, default-OFF flag `dir_ex_grantgen_refresh`, UNDER TEST):
At the fast-path dir-EX serve, when `hgg != i_dlm_cached_grant_gen && !ho` (the P51-UF
condition), arm `dir_ex_stale_refresh` (drain_evict re-reads DATA blocks + reload
post_release=FALSE [keeps in-flight dirty fork → no own-delete resurrection] + dir_gen bump)
with `dir_ex_handoff=FALSE` (NO fork adopt → avoids the sess49 shutdown). Over-fire on benign
same-node re-grant is harmless (re-reads own durable blocks, perf-only). xfs_mxfs_dlm.c
~14475 + param ~5316. NEXT: A/B 8/tcp dir_reuse (must be 0 loss) THEN unlink/rename for
resurrection regression THEN full 1/2/4/8 suite; if clean, make default and verify perf (RULE 0).
See [[sess52-ROOT-node-addname-stale-epoch-datablock-readgate-miss]].</body>
