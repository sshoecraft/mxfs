---
name: ccloop-c7ee71c6-sess362-closure-purge-wrong-table-stopship
description: sess362: sess361 closure purge is a NO-OP — scans disklock record table (write_grant has 0 callers); real frozen grants = CAW slot holders_ex bits; G…
metadata:
  type: project
---

# sess362 — sess361 closure purge targets the wrong table

## Proven (grep, tree-wide)
- `mxfs_disklock_write_grant` (disklock.c:2459) has ZERO callers → the
  `mxfs_disklock_record` 65536-table sess361's purge scans is ALWAYS EMPTY at
  runtime. The 0.14.2 landing would log P299-CLOSURE-PURGE purged=0 kept=0 and
  fix nothing. (`mxfs_disklock_purge_node`'s record scan is equally vestigial;
  its meaningful work is the HB-sector zero.)
- Real grant state: CAW slot table, `struct mxfs_caw_lock_slot` (dlm_caw.h:150)
  with embedded `resource` + `holders_ex/pw/...` bitmasks. sess360's stuck
  waiter was `caw_wait_for_grant` polling a CAW slot.
- Freeze mechanism: death → `mxfs_dlm_caw_purge_dead_nodes_ex(KEEP_EX)`
  retains victim EX/PW bits; success-path release lives in
  `mxfs_v5_dlm_recovery_complete` (v5_mount.c:3414); refusal path has NO
  release → defect #3.

## GPT RULE-5 review of sess361 (sess362): STOP-SHIP
Carry-over requirements for the CAW redo: (1) bind classifier mask to platter
mask (pass expect_ag_mask, -ESTALE mismatch); (2) fail closed on unreadable
gate mid-purge; (3) gate revalidate before EVERY destructive CAS, not 2s
amortized; (4) desc/outcome crc binding OK as-is (recov_auth_holds binds
recovery_gen); (5) G1/G2 need a re-purge path PRE-SHIP — candidate:
waiter-triggered single-slot leaseless revoke (waiter classifies own resource,
gate-checks victim HB, CAS-strips one slot) — needs its own RULE-5 consult;
(6) partial purge must return retry-required, not 0.

## Keep from sess361
closure_purge_gate (authority logic sound), xfs classifier
mxfs_freplay_res_out_of_closure, v5 volume shim, call-site placement
(publish→import→purge→release). Repoint the scan/strip to the CAW table.

Full plan in .ccloop/handoff.md (sess362).
