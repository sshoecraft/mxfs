---
name: ccloop-c7ee71c6-sess201-470-board-green-relstate-machine-471-built
description: sess201: 0.11.470 knob=0 full board 27/27 PASS + cert counters clean; step-3 release-state machine landed as 0.11.471 (sv CCB3BC58C73A719218DEFEC), b…
metadata:
  type: project
---

# sess201 — board verify on .470 + release-state machine landing (.471)

## Board (0.11.470, sv 4382FAEFA146D50E90DF775, 32/caw, knob=0)
27/27 PASS 2026-08-10T12:00-12:14Z, open_defects red by policy only.
5 foreground chunks, all in RULE-0 budgets. Tightest: crash_consistency
85s/90s, dir_reuse_coherency 104s/120s (no pace marginality this run).

## Cert telemetry after board (release_cert_dump is WRITE-triggered)
test1 attempts=6523, test16=4117, test32=4172; cas_dirty=0,
tripwire_retries=0, drain_timeouts=0, wedges=0, all defers=0.
cas_invalid_proof==cas_noticket==attempts is EXPECTED: F2 domain-wide
noticket under fua_disable=1 without target_cache_protected; `success`
only counts fully-proven CAS, so success=0 is also expected. The F1
hazard signal is cas_dirty and it is ZERO.

## Ledger
D-INODE-CLUSTER-PUBLISH-WITHOUT-AUTHORITY next-item 1 marked DONE
(sess199 knob=1 + knob=0 pair on .469, both 2026-08-10, + this board).

## Landed: 0.11.471 (sv CCB3BC58C73A719218DEFEC) — NOT deployed
Step-3 second increment (sess197 ruling instrumentation): per-resource
release state machine, observation-only.
- enum mxfs_release_state (ACTIVE/DEMOTING/DRAINING/PROVED/RELEASING/
  WEDGED) in xfs_mxfs_dlm.h; cert field rel_state_cas; new counter
  cas_unproved in P280-TOTAL; P283-RELCERT-CAS-UNPROVED probe.
- xfs_inode.h i_mxfs_rel_state (uint8_t, WRITE_ONCE, per-inode release
  serialization makes races telemetry-only).
- mxfs_relbar_close_or_defer: DRAINING at entry, PROVED on close (both
  the early-return and post-pass), DEMOTING on defer.
- Both class-1 arms (anchored+noanchor): capture rel_state_cas,
  set RELEASING immediately pre-CAS; relcert_finish → ACTIVE post-CAS.
- ICLUS choke point mxfs_iclus_disk_release: DEMOTING (under ic->lock at
  epoch snapshot) → DRAINING pre-settle → PROVED iff settle clean
  (oblig_cas==0) → RELEASING → ACTIVE. Publish-fail defer stays
  DEMOTING. ic deref after CAS is safe: iclus objects freed only in
  mxfs_iclus_purge_all at umount.
- Semantics: cas_unproved>0 ⇔ CAS from state != PROVED ⇔ proof body
  skipped/raced/timed out. Must be ZERO before gate enable (steps 9-10).
  relbar_enforce=1 default ⇒ expected 0 in normal operation; an ICLUS
  settle timeout shows in BOTH cas_dirty and cas_unproved.

## Next
Deploy .471 (MXFS_FORCE_PREP=1 ./run.sh 32 caw prep_cluster), smoke,
assert cas_unproved=0 + no P283, board, then step 4 (F4 obligation
registry, dir first).
