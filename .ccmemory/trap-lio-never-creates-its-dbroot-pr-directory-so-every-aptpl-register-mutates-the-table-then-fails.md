---
name: trap-lio-never-creates-its-dbroot-pr-directory-so-every-aptpl-register-mutates-the-table-then-fails
description: TRAP (s65, 0.89.73): LIO writes APTPL state to <dbroot>/pr/aptpl_<serial> with O_CREAT but never mkdirs; targetcli-fb's dbroot ships without pr/, so…
metadata:
  type: feedback
tags: [lio, aptpl, scsi-pr, bench-target, rig]
---

# LIO never creates its dbroot `pr/` directory, so an APTPL REGISTER mutates the table and then fails

Run 98c3ef65 session 65 (0.89.73), on the restartable bench target `liovm`
(tools/lio_bench_target.sh, LIO on VM test32, targetcli-fb 2.1.53 / rtslib-fb
2.1.74, kernel 6.8).

## What happened

tests/pr_aptpl_probe.sh read PTPL_C=1 but PTPL_A=0 with one registration
present and no reservation (tests/evidence/20260922T181531Z_aptpl_s160a). On
test1 the MXFS mount had aborted with P305-PR-SELF-SUCCESSION-REFUSED / "SCSI PR
register failed (-17)": a registration it never owned was on its own nexus.

## Cause, from the target's own log

`drivers/target/target_core_pr.c __core_scsi3_write_aptpl_to_file` opens
`<db_root>/pr/aptpl_<unit serial>` with O_CREAT and never creates the
directory. targetcli-fb sets db_root (`/sys/kernel/config/target/dbroot`) to
`/etc/rtslib-fb-target` on this distribution, which ships with no `pr/` or
`alua/` subdirectory. The kernel's sd layer sets APTPL on every REGISTER, so
`core_scsi3_emulate_pro_register` adds the registration, then
`core_scsi3_update_and_write_aptpl` fails ("filp_open(...) for APTPL metadata
failed", "SPC-3 PR: Could not update APTPL"), the command returns an error,
`pr_aptpl_active` stays 0 and the key stays in the table. The initiator sees a
failed REGISTER whose side effect persisted; its retry with reservation key 0
then gets RESERVATION CONFLICT ("an I_T nexus of this host already holds a
different registration"). None of this is an MXFS defect: MXFS failed closed on
a key it could not classify.

## Fix and verification

`tools/lio_bench_target.sh setup` now reads the dbroot the kernel reports and
creates `pr/` and `alua/` under it before anything else (refuses if it
cannot). Verified 2026-09-22: after the mkdir, a REGISTER with APTPL from test1
answered PTPL_A=1, the target wrote `aptpl_<serial>`, and an unregister that
emptied the table dropped PTPL_A back to 0 (LIO deactivates when nothing is
registered, which is what the probe's `keys >= 1` check is for).

## The general lesson

A target that reports a capability bit is not a target that has been
provisioned to use it. Ask the target's own kernel log why the ACTIVE bit is 0
before reading a capable-but-off answer as the target's design; and a REGISTER
can fail AFTER it changed the table, so a stale key on our nexus after a failed
mount is a symptom to clear (`sg_persist --out --register --param-rk=<key>
--param-sark=0`), not a predecessor to classify.
