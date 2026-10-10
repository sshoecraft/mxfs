---
name: compiled-sg-persist-capture-traps-wrong-rig-device-defaults-and-transient-qnap-mkfs-verify-fail
description: Harness evidence traps: case-sensitive filters drop sg_persist's "NO reservation", wrong-rig device defaults report error text as findings, QNAP mkfs…
metadata:
  type: feedback
tags: [compiled, harness, measurement-integrity, scsi-pr, rig, qnap]
---

# sg_persist capture traps, wrong-rig device defaults, and a transient QNAP mkfs verify failure

Three notes share one theme: a harness reported a verdict about MXFS or the rig from a capture that observed nothing, or observed something other than what the predicate assumed. The third is a one-off rig anomaly kept for its recurrence procedure.

## 1. A pre-filter is part of the instrument ([[trap-sg-persist-says-no-reservation-held-in-capitals-and-a-case-sensitive-filter-throws-the-decisive-line-away]])

- `sg_persist -i -r <dev>` reports an unreserved LUN as `PR generation=0x16d2, there is NO reservation held` (NO capitalised).
- A remote-side `grep -a 'Key=\|type:\|no reservation'` discards that line. The downstream `resv_none()` predicate, even case-insensitive, then inspects a file with the evidence already removed. Case-folding at the predicate cannot repair a case-sensitive capture.
- Cost: lap s87b (fence_late_detection) polled 120 s, never saw the string, exited VACUOUS on a lap where the condition had in fact been reached. About 5 minutes plus a VM boot.
- Rule: grep case-insensitively (`grep -ai`), match on the noun (`reservation held`), and confirm against the tool's real output once rather than what it "would" print.

## 2. Defaults written on another rig report error text as an observation ([[trap-a-harness-hardcoding-one-rigs-device-parses-the-error-text-and-reports-it-as-an-mxfs-observation]])

- `tests/resv_health_detect.sh` and `tests/pr_reservation_ownership_probe.sh` defaulted to `/dev/mapper/mpatha` (CAW multipath rig). On the 2-node TCP rig MXFS is on `/dev/sda`; every `sg_persist` errored.
- The parser found no reservation stanza in the error text and printed `RESERVATION: NONE HELD keys=0 distinct=0`. That asserted MXFS fencing state from a capture of an error message, failed two assertions on a cluster whose reservation was healthy WE-AR with 2 registrants, and the remount step on the same absent device silently left a node unmounted for the rest of the run.
- Non-empty is not the test. The capture was a valid capture of an error. The discriminator must be a shape the tool emits only on success: for `sg_persist`, the `PR generation=` header. Absent header means report `UNKNOWN` and exit non-zero, never `NONE HELD`.
- Scale over 734 scripts in `tests/` and `scripts/`: 101 mention `mpatha`; 21 hardcode `DEV=/dev/mapper/mpatha` with no override; 28 use `${MXFS_DEV:-/dev/mapper/mpatha}`; 39 default to the condition-3 QNAP by-path. 67 are wrong by default on 2/tcp, 21 cannot be pointed at it.
- `run.sh` already resolves per condition (tcp -> `/dev/sda`, caw -> `/dev/mapper/mpatha`, `MXFS_DEV` always overrides); harnesses diverge from it.
- Fix in a harness: take the device from a node's live mount, from the node that stays up when another is unmounted mid-run:
  `DEV="${MXFS_DEV:-}"; [ -n "$DEV" ] || DEV=$(ssh_helper "$OBS" "awk '\$3==\"mxfs\" {print \$1; exit}' /proc/mounts")`, then FATAL exit 2 if still empty.
- General rule: for any default device/path/host, ask which rig it was written on. A default right on one of four rig conditions fails by reporting, not by erroring.

## 3. QNAP mkfs zero_region verify FAIL right after fleet unmount ([[trap-qnap-mkfs-zero-region-verify-fail-transient-right-after-fleet-unmount]])

- Chain s513b prep failed in 13 s: `mkfs.mxfs: zero_region verify FAIL @67119616 byte 2560 = 0x4b`, one second after test1's clean unmount (test2 had shut down on an EDEADLK-NL livelock minutes earlier).
- `sg_persist -k/-r` afterwards: no keys, no reservation, so not the stale-PR-blocks-mkfs shape. Rerun 90 s later prepped fine.
- Offset 0x4001000 lies in the tauth ledger zero_region (`tools/mkfs_mxfs.c:732`). Candidate causes: a ledger write landing after the zero, or a stale read from the QNAP target cache. Not root-caused; one occurrence.
- If it recurs: capture mkfs timestamps against the last node's teardown lines, `dd` the 4 KiB page before the rerun overwrites it, and treat a second occurrence as a ledger-worthy rig defect (silently dropped or reordered writes on the shared LUN threaten integrity of every result on it).

## Common discipline

Never derive a verdict from a capture not proven to contain the tool's success shape; filter case-insensitively on nouns; never let a default encode one rig's device.
