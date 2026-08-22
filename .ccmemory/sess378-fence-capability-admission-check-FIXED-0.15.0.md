---
name: sess378-fence-capability-admission-check-FIXED-0.15.0
description: sess378: D-FENCE-CAPABILITY-UNVALIDATED-AT-MOUNT CLOSED in 0.15.0 — REPORT CAPABILITIES at admission, refuse by default, both arms rig-verified, boar…
metadata:
  type: project
tags: [D-FENCE-CAPABILITY-UNVALIDATED-AT-MOUNT, fencing, scsipr, sess378, 0.15.0, admission]
---

# Second closure of sess378 — fencing capability is now validated at mount

Build **0.15.0**, srcversion **4531A8D9D160E9BCC52D4CE**. Follows directly from
`sess378-dm-pr-preempt-drops-abort-upstream-kernel-bug`: that session proved a
fence can be silently broken by the platform and that NOTHING detected it for
months. This is the detector.

## What was built

1. **PAL** `mxfs_pal_scsi_pr_report_capabilities()` — PERSISTENT RESERVE IN /
   REPORT CAPABILITIES (SA 0x02), the command sess93 named as the readable
   source for most of this check and which MXFS had never issued. Decodes
   PTPL_C/PTPL_A/CRH/SIP_C/ATP_C/TMV + the type mask, and additionally reports
   `abort_capable`, which is NOT a SCSI field — it is "can a genuine 0x05 be
   issued here", a separate question on Linux because dm drops the abort flag.
   Implemented for BOTH kernel (`scsi_execute_cmd`) and user mode (SG_IO), so
   `dlm/` still builds user-mode (architectural invariant 4).
   Parameter data: `[2]` bit0 PTPL_C, bit2 ATP_C, bit3 SIP_C, bit4 CRH;
   `[3]` bit0 PTPL_A, bit7 TMV; `[4..5]` type mask, WR_EX_RO = byte4 bit5.
2. **`dlm/scsipr.c`** `mxfs_scsipr_validate_admission()` — typed
   `P303-FENCECAP-*` verdicts: NOCAPS, ERROR, NOABORT, NOWERO, NOPERSIST,
   RESVERR, NORESV, TRUNCATED, KEYSERR, SELFABSENT, UNREGISTERED, or OK.
   Reuses `mxfs_scsipr_read_reservation()` and the static
   `mxfs_scsipr_probe_keys()` rather than duplicating them.
3. **`dlm/v5_mount.c`** — called after register+reserve, BEFORE the disklock
   claim, so a device that cannot fence never becomes a member. Default:
   **refuse the mount**. `mxfs.fence_capability_override=1` is the operator's
   explicit "this rig cannot fence" statement; it admits the mount and logs
   P303-FENCECAP-OVERRIDE naming the weaker semantics.

The knob needed a field in BOTH `struct mxfs_v5_dlm_opts` (v5_mount.h) and
`struct mxfs_v5_dlm` (defined in v5_mount.c ~line 178), plus the copy at
`ctx->single_node_exclusive = opts->...`. Adding it to only the header is a
compile error — that is the file's two-struct convention.

## Verified

- **Positive**: all 32 nodes log `P303-FENCECAP ... ptpl_c=1 ptpl_a=1 crh=1
  sip_c=1 atp_c=1 tmv=1 type_mask=0xea01 we_ro=1 abort_capable=1` then
  `P303-FENCECAP-OK`, and mount. Matches the capabilities sess93 recorded by
  hand — independent corroboration of the decode.
- **Negative** — `tests/fence_capability_admission.sh` (new). Builds a device
  with NO SCSI PR at all (loop device) — stronger than the "no reservation
  held" the ledger asked for — puts a real mkfs_mxfs on it, runs both arms:
  ARM 1 default → mount REFUSED, `P303-FENCECAP-NOCAPS` + `CAW mount REFUSED
  (-95)`, mounted=0. **That device used to come up read-write silently.**
  ARM 2 `fence_capability_override=1` → mounted=1 with the OVERRIDE warning.
- **Regression**: full 32/caw board on 0.15.0 = 23 PASS, 4 FLAKY (all passing),
  0 FAIL, 1 POLICY. The mount path changed for every node, so the whole board
  is the regression check.

## Not claimed

Admission-time ONLY. A capability that disappears while mounted (target
reconfigured, reservation released by a third party, all paths lost) is still
undetected until a fence is attempted — belongs with
D-FENCE-BLOCKED-STATE-UNOBSERVABLE. Of the legs, only NOCAPS is exercised on
real hardware; NOWERO/NOPERSIST/TRUNCATED/SELFABSENT are code-reviewed only.

## Rig note

`mkfs_mxfs` PROMPTS for confirmation — scripts must pass `-f`.
