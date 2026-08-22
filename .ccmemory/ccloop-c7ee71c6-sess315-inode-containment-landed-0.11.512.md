---
name: ccloop-c7ee71c6-sess315-inode-containment-landed-0.11.512
description: sess315: INODE-class defer containment FULLY LANDED+BUILT 0.11.512 sv DF5630A9C55F783FB6B8E56 — all 10 sess312 ruling items; NOT deployed
metadata:
  type: project
tags: [step6-F1, inode-containment, 0.11.512, relgate-fault]
---

# sess315 — INODE containment pipeline surgery landed (0.11.512)

Build: 0.11.512, srcversion DF5630A9C55F783FB6B8E56 (make clean && make
modules; `make tools` NOT yet run). NOT deployed to the rig.

Implements all 10 items of the sess312 ruling (see
ccloop-c7ee71c6-sess312-GPT-ruling-inode-reldefer-containment-design) on
top of the sess314 foundation. Key shapes:

- Episode: enter/extend at both relbar arm-site defers via
  mxfs_inode_defer_arm; NO worker of its own — the existing stranded
  re-arm/dwork owns retries, with episode-aware backoff (25ms<<tries cap
  1s + jitter, clamped to remaining min(progress+60s, started+300s)).
- Close ONLY on cas_result==0 in mxfs_inode_relcert_finish (build-1
  choice; proved-only flip is build 2), wakes i_dlm_wait.
- Wedge (mxfs_inode_wedge): one-shot relwedge_shot, WEDGED terminal,
  mxfs_v5_dlm_inode_pin, WEDGE cert, P-INODE-WEDGE, shutdown unless
  (teardown && pin ok). Fired from arm sites on expired bounds and from
  dwork entry (covers BUSY parking). Teardown no-arm branch wedges
  pin-only when a defer happened (p_rb_deferred || started_j).
- Pre-CAS WEDGED re-check in both arms (emit WEDGE cert, no submit;
  anchored uses -EIO so no strand/re-arm).
- Admission: P-INODE-WEDGE-FENCE terminal gate in ilock_begin (mirrors
  P-SHUTDOWN-FENCE); open episode diverts NEW EX (any file class,
  pin==0) off the fast path into the 29655 wait loop, whose while+
  wait_event predicates now park on the episode; postwait EX re-admit
  gated; in-loop WEDGED refuse. P79 nested-admit arms deliberately NOT
  gated (proven self-deadlock breaker; joins an already-held tenure,
  bounded by the 300s wedge).
- Fault legs: cert->fault_forced field; stage 7 OBLIG_ZERO at the proof
  body's final ledger recheck (forced→defer); stage 9 FLUSH_DONE fails
  the first ticket check (transient — direct flush usually recovers);
  stage 10 PROOF fails the post-flush recheck (persistent proof_failed).
  Cause derivation attributes forced failures to OBLIG_OPEN instead of
  tripping P-INODE-DEFER-NOCAUSE.

Next: make tools, deploy, prep_cluster, then the sess312 option-c 5-item
campaign (knob-on full board, ICLUS fault legs, INODE fault legs with
relgate_fault_force=1 — driver tests/relgate_fault_inject.sh needs
INODE-mode additions — wedge legs oneshot=0, production re-board).
