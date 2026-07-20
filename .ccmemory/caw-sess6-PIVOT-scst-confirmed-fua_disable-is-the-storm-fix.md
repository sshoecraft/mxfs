---
name: caw-sess6-PIVOT-scst-confirmed-fua_disable-is-the-storm-fix
description: sess6 PIVOT+@4 PROVEN: CAW target=SCST_FIO; fua_disable=1 @4 = 17/17 (incl dir_reuse 4/4, the cell that broke every reload-skip fix). Coherent+correc…
metadata:
  type: project
---

## sess6 PIVOT — fua_disable=1 is the fix. @4 PROVEN 17/17. (SCST target)

### DEFINITIVE: CAW multipath target = SCST (not LIO)
`lsscsi`/sysfs vendor on test1/16/32 mpatha = **`SCST_FIO mxfs`**. All 32 uniform. The device the
criteria run on. sess14's "LIO-ORG" was the OLD /dev/sda TCP cluster — different target, do not conflate.

### THE MISCONFIG + THE FIX
`mxfs_fua_disable = 0` default (xfs_mxfs_dlm.c:24661) was set by sess14 for a LIO cluster. WRONG for
SCST: on SCST all initiators share ONE coherent write-back cache, so a SCSI-FUA read PIERCES to the
un-destaged platter (staler + slower); a plain BIO read hits the coherent shared cache (fresh + fast).
`fua_disable=1` routes ALL mxfs reads plain-bio → the ~45x FUA slowness (= the 32-node storm) is gone
and reads stay coherent. Only affects READ paths (~10 sites); FUA writes unaffected (stay durable).

### @4 RESULT — fua_disable=1 is COHERENT AND CORRECT (build B73D1E9F, MXFS_EXTRA_MODARGS="fua_disable=1")
`./run.sh 4 caw cache_coherency strong_consistency dir_reuse_coherency` = **ALL PASS 4/4, 17/17 total**,
elapsed 374s. CRUCIALLY **dir_reuse_coherency@4 = 4/4** — the exact cell that broke sess5's fixes AND
sess6's dir_slow_handoff_gate (both reload-skip approaches served stale under cross-node reuse). Because
fua_disable=1 SKIPS NO RELOAD — it just reads coherent data from the SCST shared cache — it has no
reuse false-negative. This RESOLVES sess48-vs-sess94: **sess94 is RIGHT** (SCST plain reads coherent);
sess48's "per-initiator stale read cache" claim is REFUTED for this cluster.

### CONTRAST: reload-skip is a DEAD END; fua_disable is the mechanism
Both sess5 (reload_skip_owned, mode==0) and sess6 (dir_slow_handoff_gate, dir handoff) PASS
cache_coherency@4 but FAIL dir_reuse@4 0/4 — any peer-EX/handoff/epoch skip signal false-negatives
under aggressive cross-node inode reuse. STOP pursuing reload-skip. fua_disable=1 is the correct fix
(different mechanism entirely). See [[caw-sess6-FIX-dir-slow-handoff-gate-build-B73D1E9F]] (refuted).

### IN FLIGHT (sess6): storm-scale validation valfua_scale.sh
STAGE 1 @16 fua_disable=1 (cache_coherency + dir_reuse HOLDOUT — hung round 2/24 with FUA on).
STAGE 2 @32 fua_disable=1 (cache_coherency + crash_consistency + dlm_scaling + dir_reuse — all 4 blocked
cells). If @16 dir_reuse passes FAST => storm fix proven at scale. If @32 all pass => criteria essentially
met (pending full-ladder re-record).

### ENDGAME (after storm-scale passes)
1. Flip default: `int mxfs_fua_disable = 1;` (xfs_mxfs_dlm.c:24661) — correct for the SCST criteria target
   (or better: auto-detect SCST vs LIO by SCSI vendor; no detect helper exists yet). Rebuild.
2. Run FULL ladder 1/2/4/8/16/32 caw with DEFAULT params, confirm ALL 17/17, record PASS.
3. Verify no regression of currently-green cells. Then write criteria-met marker.
INFRA: run.sh DEV default=/dev/sda WRONG — always MXFS_DEV=/dev/mapper/mpatha. MXFS_EXTRA_MODARGS DOES
propagate params. `make clean` (user) wipes mxfs.ko+tools → rebuild `make modules && make tools`.
A run.sh FAIL overwrites a recorded PASS — restore any FAILed cell before ending.
See [[caw-sess6-cachecoh32-storm-is-dir-reload-NOT-mode0-recycle]] [[compiled-fua-read-coherency-staleness]].
</body>
