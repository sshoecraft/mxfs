---
name: trap-a-harness-that-matches-transport-caw-exactly-puts-a-cawd-node-back-on-tcp
description: TRAP (0.90.4): rig transport names are caw|cawd|cawp; `[ "$MXFS_TRANSPORT" = caw ]` read cawd as TCP, the reload mount was refused, lap graded VACUOU…
metadata:
  type: feedback
---

The rig's transport axis has three CAW names: `caw` (dm-multipath), `cawd` (direct in-guest iSCSI, the SCST 2-node rig) and `cawp` (passthrough). A harness that means "any CAW rig" must match `caw*`.

What happened: tests/lib/rig.sh mxfs_rig_modargs chose force_transport=0 only for `caw` exactly. When tests/bootstrap_takeover_2n.sh moved to the SCST rig (MXFS_TRANSPORT=cawd), every module reload after the whole-cluster outage came back with force_transport=1, and the first mount died at DLM init with P-TRANSPORT-MISMATCH-REFUSED forced=tcp platter=caw. The harness graded that VACUOUS ("A never claimed the bootstrap term"), which hid a setup failure as a non-measurement (tests/evidence/20260926T160431Z_btk_preempt_foreign_s6b). Fixed in 0.90.5 (case caw*), and the harness now grades a DLM-init refusal ABORT.

The same bug had already been fixed once for `caw` vs always-TCP (20260926T065606Z_btk_btk_caw_s1) — renaming the rig re-broke it. When a rig/transport name set changes, grep every exact comparison against the old name (run.sh's own `caw)` arms mean the multipath rig specifically and are correct).
