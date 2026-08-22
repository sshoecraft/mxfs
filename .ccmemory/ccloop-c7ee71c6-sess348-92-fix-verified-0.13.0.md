---
name: ccloop-c7ee71c6-sess348-92-fix-verified-0.13.0
description: sess348: #92 clean-departure fix COMPLETE+DEPLOYED 0.13.0 sv F191408004F380B726E4887 — mass-unmount PASS (31x P163-CLEAN-DEPART, 0 false death), rejo…
metadata:
  type: project
---

# sess348 — #92 D-CLEAN-RELEASE-TREATED-AS-DEATH-PHANTOM-RECOVERY-526: fix verified

Build 0.13.0 sv F191408004F380B726E4887 (PROTO_GEN bumped; re-mkfs required).
Edits 4-6 landed this session: v5_clean_depart_cb (recovered_cb minus note_dead,
registered both mount paths), mxfs_v5_dlm_set_clean_depart_notify plumbing,
xfs_mxfs_dlm.c mxfs_dlm_clean_depart_notify (clears torn bit, test_and_clear dead
bit, requeues foreign_replay_work only if a dead latch was dropped — work-fn tail
runs deferred sweeps), registered in mxfs_dlm_cache_init.

## Verification (all on freshly prepped 32/caw, 0.13.0)
1. **tests/clean_depart_mass_umount.sh 32 test1** (NEW harness) — PASS:
   31-way concurrent umount (wall 122s — #93 serialize still present), 120s
   observe window; ZERO "no longer responding" on all 32 nodes, ZERO
   P163-RECOVERY-PENDING on survivor, 31× P163-CLEAN-DEPART (FUA confirmed),
   survivor writable, no shutdown/withdraw. Before fix (sess342): peers
   false-declared live nodes dead + fenced + latched phantom recovery.
2. **Rejoin after clean departure**: test2 remounted against live survivor,
   cross-node write visible, ZERO P164-DEAD-REJECT (clean depart skips
   note_dead by design).
3. **Real-death regression**: dirty create load on test2 + virsh destroy →
   test1 declared death (~87s), P164-DEAD-NOTE, P163-RECOVERY-PENDING,
   P238-RECOV-LEASE, foreign replay ran. Death machinery intact.
   Replay REFUSED rc=-117 (P227-FR-ATOMIC-SKIP untagged images →
   P241-RECOV-TERMINAL, AG-MASK 0x3 quarantine) — PRE-EXISTING #1/#90
   behavior (natural refusal first seen sess319/320); sess320 containment
   worked: no suicide, survivor stayed up. NOT a #92 regression, but note:
   a plain create-workload victim's slice refuses naturally — that is #1
   D-FOREIGN-REPLAY-UNGATED-IMAGES plan-of-record territory.

## Still open for #92 full closure
GPT micro-race test list (EMPTY between read+confirm, stale cached EMPTY then
fresh ACTIVE, wrong epoch/node EMPTY, GUARD CAS race, ACTIVE→EMPTY→ACTIVE missed
lineage, multi-cycle reuse) + full 32/caw board on 0.13.0. LUN quarantined by
the real-death test — re-prep before anything else.
