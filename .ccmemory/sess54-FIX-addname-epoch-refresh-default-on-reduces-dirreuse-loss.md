---
name: sess54-FIX-addname-epoch-refresh-default-on-reduces-dirreuse-loss
description: sess54(ccloop) FIX build 88F00076/A204997E: dir_addname_epoch_refresh=1 (was 0) consumes the RELIABLE master dir epoch via SAFE data-block-only refre…
metadata:
  type: project
---

## sess54 — 8/tcp dir_reuse: enable safe level-triggered epoch consumption

### RULE-4 DIAGNOSIS (drc_phantom_diag, build 9473C7AD, clean reboot):
- **P42-STALEEX-SERVE=0** (not phantom), **P64-MASTER-HANDOFF=93x, epoch monotone
  131→172→211→328** ⇒ the master dir epoch is RELIABLE.
- **P-FASTEX-EPOCH=0** ⇒ the level-triggered epoch was NEVER consumed (dir_epoch_adopt=0
  [fork-adopt → sess49 shutdown], dir_addname_epoch_refresh=0).
- Under-fire mechanism PINNED: P-DGEX handoff=0 samples ALL show `owner==last_owner,
  active_b4=0` = the **A→B→A→A re-grant pattern**. The EDGE-triggered handoff bit
  (`last_owner != owner`) reads false because last_owner only tracks the IMMEDIATELY-prior
  owner, but the grantee's grant_gen jumped ~19 (lock DID change hands via other nodes).
  The bit can't see it; the LEVEL-triggered epoch can (and does advance).
- Failure was a MASS loss: node3's whole f2..f50 batch clobbered (readdir=750/800).

### FIX (build 88F00076): `int mxfs_dir_addname_epoch_refresh = 1` (was 0),
xfs_mxfs_dlm.c:5424. Consumes the epoch at the addname modify site (xfs_dir2_node.c:2034)
with the SAFE data-block-only refresh: drop XBF_DONE + restart on the ONE chosen block;
keep-guard (never dirty/in-AIL/pinned/DELWRI); NO fork adopt (avoids sess49 shutdown), NO
i_dlm_dir_gen bump (avoids sess53 DABUF_MAP_HOLE). RESULT run1: loss 50→4 (.md5 sidecars:
node5_f15.md5 node7_f28/34/35.md5 — first fail round 7, readdir=796/800).

### RESIDUAL probe (build A204997E): added P54-KEEPGUARD-STALE (block detected stale
b_epoch<valid but keep-guard blocked refresh = dirty/in-AIL mid-tenure RMW on stale base)
and P54-MEPZERO (grant delivered epoch=0 → refresh inert) at xfs_dir2_node.c:2110. Also
fixed drc_phantom_diag.sh snapshot pick (was lexical sort r19<r7 → captured wrong round;
now numeric-min) + added P54/P28-ADDNAME-EPOCHSTALE/P22 grep. run2 (with probes) PASSED
8/8 — but ONE pass ≠ 100% (intermittent; probes may shift timing/mask, sess39). 5-run
pass-rate IN FLIGHT (drc_passrate2.sh 5).

### NEXT: read pass-rate. If <5/5, read P54 counts on the loss-round node to pin the
residual (keepguard-dirty → GPT flush-then-reread; or mep==0 → fail-closed; or neither →
stamped-coherent-but-stale = per-buffer validated_epoch). If 5/5 WITH probes, rebuild
WITHOUT P54 probes, re-confirm 5/5 (rule out masking), then run FULL ./run.sh 8 tcp suite
(criterion = full suite per [[sess49-criterion-scope-is-full-suite-and-verification-plan]])
AND 1/2/4 tcp. See [[sess53-HANDOFF-gpt-design-reliable-epoch-plus-safe-writeset-refresh]].</body>
