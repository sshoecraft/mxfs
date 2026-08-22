---
name: ccloop-c7ee71c6-sess198-steps1-2-LANDED-0.11.469-gate-prereqs-and-certs
description: sess198: tenure-release build-order steps 1+2 LANDED on 0.11.469 (sv 370EDCD41B269B450151CA7), NOT deployed. Fail-closed gate knobs + release-cert/fa…
metadata:
  type: project
---

# sess198 — sess197-ruling build-order steps 1+2 landed (0.11.469)

Both steps build clean (incremental after step-1 clean build; sv
370EDCD41B269B450151CA7). NOT deployed — fleet still on 0.11.467.
Behavior UNCHANGED by design: observation only.

## Step 1 (gate prerequisites fail closed)
xfs_mxfs_dlm.c after the adopted_slice_full_replay block (~38264):
- `mxfs_target_cache_protected` (int 0644, default 0) — operator
  declares target write cache power-protected (F2 domain knob; ruled
  separate, never overload fua_disable).
- `mxfs_replay_gate_enforce` — per-class bitmask bit0=AG bit1=inode
  bit2=ICLUS bit3=dir, module_param_cb setter REFUSES (-EINVAL, one
  pr_err per unmet prereq): F2 (fua_disable=1 && !target_cache_
  protected) and compile-time consts MXFS_RELGATE_F1_ICLUS_DEFERRED_
  RELEASE_READY / F3_COMPLETION_PROOF_READY / F4_OBLIGATION_REGISTRY_
  READY (all 0; flip as steps 6/5/4 land).
- `mxfs_replay_gate_mode()` read helper. Decls in xfs_mxfs_dlm.h.

## Step 2 (certificates + counters + fault hooks)
Header: enum mxfs_relgate_class, enum mxfs_relgate_fault_stage
(MXFS_RGF_* 1-18, stable IDs from the ruling), struct
mxfs_release_cert (all ruling fields; unmeasurable ones stay 0 until
steps 3-5), DECLARE_STATIC_KEY_FALSE(mxfs_relgate_fault_key) + inline
mxfs_relgate_fault(stage,res).
.c: counters (attempts, success, defer_oblig/io/pincil/flush,
tripwire_retries, drain_timeouts, wedges, cas_invalid_proof, plus
split cas_dirty=F1-signal / cas_noticket=F2-signal); emit feeds
counters always, prints P280-RELEASE-CERT only under
release_cert_log=1; P281-RELCERT-INVALID-PROOF pr_err_ratelimited on
dirty-at-CAS only (F2-only case never prints — domain-wide, would
flood). Dump via release_cert_dump (P280-RELEASE-CERT-TOTAL).
Fault engine: relgate_fault_stage (setter validates 0-18, flips
static key), relgate_fault_res (0=any), relgate_fault_delay_ms
(default 100), relgate_fault_oneshot (default 1, cmpxchg disarm),
P282-RELGATE-FAULT hit line, msleep — sleepable sites only.
mxfs_relcert_count_tripwire_retry() exists, NOT yet called (wire at
relbar in step-2 residue).

## ICLUS wiring (F1 site, the choke point)
- mxfs_iclus_make_durable: now returns 1 when the 125x2ms settle
  timed out with the cluster buffer still dirty (P-ICLUS-DUR-TIMEOUT
  path), else 0; fault stages LOGFORCED, OBLIG_ZERO (clean only),
  FLUSH_DONE placed inside.
- mxfs_iclus_disk_release: emits one cert per attempt — old_epoch
  from ic->auth_epoch; publish-open-bits failure => defer OBLIG cert,
  no CAS; oblig_cas=timeout=make_durable rc; drain_ns measured;
  ticket_required=1, ticket_completed=!fua_disable||target_cache_
  protected; fault stages DEMOTING, PRE_CAS, POST_HANDOFF.
So after any board: cas_dirty counts REAL F1 occurrences;
cas_noticket≈attempts is EXPECTED under default fua_disable=1 (that
is the F2 domain fact, not a regression).

## Ledger
D-FOREIGN-REPLAY-UNGATED-IMAGES next-step item 2 rewritten: cites the
sess197 ruling + both landings + next steps (relbar counter wiring,
then step 3 common release-proof helper).

## Next session
1. make clean && make modules (confirm sv), prep_cluster, regression
   board 32/caw (expect 27/27 applicable — observation-only change),
   then release_cert_dump totals.
2. Step-2 residue: relbar defers/tripwire into new aggregates.
3. Step 3 per ruling.
