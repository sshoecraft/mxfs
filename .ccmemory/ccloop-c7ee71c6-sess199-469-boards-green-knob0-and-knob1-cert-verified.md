---
name: ccloop-c7ee71c6-sess199-469-boards-green-knob0-and-knob1-cert-verified
description: sess199: 0.11.469 DEPLOYED, boards 27/27 PASS at BOTH icluster_dlm=0 and =1. Step-2 certs VERIFIED at knob=1: ~23.2k attempts, cas_dirty=0, noticket=…
metadata:
  type: project
---

# sess199 — 0.11.469 deployed; both boards green; step-2 certs verified

## Facts
- Clean build reproduces sv 370EDCD41B269B450151CA7. `make clean` also
  deletes tools/ binaries — run `make tools` before prep_cluster.
- knob=0 regression board 32/caw: 27/27 applicable PASS.
  - dir_reuse_coherency FIRST ran FAIL: pace check "rounds_done>=8 got
    7 in 105s" on all 32 nodes (faildist 1x32). Rerun alone: PASS
    79 checks/105s at HIGHER hostload (24 vs 19.5). Attribution to
    469 DISPROVEN by counters: the sess198 code executed ZERO times
    during that board (release_cert attempts=0 fleet-wide). This is
    an occurrence of the known marginal dir-pace family (#23/#24).
- VACUITY ROOT: icluster_dlm=0 (default, load-time 0444) makes the
  whole ICLUS layer "inert scaffolding" — mxfs_iclus_disk_release can
  NEVER run at knob=0. Cross-node dinode chmod ping-pong confirmed:
  attempts stayed 0 both directions. sess198's expectation
  "cas_noticket≈attempts after a board" is impossible at knob=0.
- knob=1 deploy line (from sess33): MXFS_FORCE_PREP=1
  MXFS_EXTRA_MODARGS='icluster_dlm=1' ./run.sh 32 caw prep_cluster.
- knob=1 FULL BOARD on 469: 27/27 applicable PASS (dir_reuse 79
  checks/105s — same pace as knob=0).
- Step-2 certificate instrumentation FIRST EXECUTION + VERIFIED:
  - Single cross-node chmod → exactly one P280-RELEASE-CERT (class=2
    ICLUS, path=iclus_disk_release, cas=1 rc=0, oldep=1, tkt=1/0).
  - Fleet totals after board: attempts 696-1010/node (~23.2k total),
    cas_dirty=0 → ZERO real F1 occurrences this board,
    cas_noticket==attempts on every node (F2 domain fact under
    fua_disable=1, exactly as sess197 ruling predicted),
    success=0 (definitional: noticket ⇒ invalid_proof),
    defers/tripwire/drain_timeouts/wedges all 0.
    No P281 (P281 fires only on dirty-at-CAS), no P-ICLUS-DUR-TIMEOUT.

## Consequences for the campaign (ledger #1 item 2)
- Step-2 wiring is CORRECT and proven live, but its F1 site is inert
  in the shipped default config. Step 3 (common release-proof helper)
  must convert the PER-INODE release path first — that is where the
  default config's releases actually happen — or the gate campaign
  observes nothing in production mode.
- Ledger #2 (D-INODE-CLUSTER-PUBLISH-WITHOUT-AUTHORITY): its next-step
  "knob=1 full board + knob=0 regression board" now BOTH exist on
  0.11.469 same day, both 27/27. Soak laps still outstanding.

## Rig state at session end
Fleet 32/32 on 0.11.469 sv 370EDCD **WITH icluster_dlm=1** — re-prep
knob=0 before any default-config work.
