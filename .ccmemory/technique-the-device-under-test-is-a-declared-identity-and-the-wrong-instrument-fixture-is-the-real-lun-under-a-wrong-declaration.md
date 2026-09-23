---
name: technique-the-device-under-test-is-a-declared-identity-and-the-wrong-instrument-fixture-is-the-real-lun-under-a-wrong-declaration
description: TECHNIQUE (D-A-HARNESS-CAN-MEASURE-THE-WRONG-DEVICE, 0.87.20): data/rigs.json declares the LUN WWID per rig tag; mxfs_dev_resolve verifies WWID+fsid+…
metadata:
  type: feedback
---

# The device under test is a declared identity, not a path

**The hazard (measured s41):** two PR probes pointed at `/dev/mapper/mpatha` on the TCP rig parsed
sg_persist's error text and FAILed a healthy cluster. Worse than the absent path: a path that
names another valid device (each node's `/dev/vda` root disk) answers every probe with well-formed
output, so the acquisition-status check and the shape check both pass and the verdict is about the
wrong instrument. 203 sites in 159 scripts chose a device by a rig-specific spelling.

**The shape that closed it (0.87.20, Astra ruling 2026-09-18):**
- `data/rigs.json` declares each rig's LUN by SCSI NAA WWID under the tag `tools/mxfs_rig_tag.sh`
  prints. An undeclared rig resolves nothing. A marker filled from whatever device prep selected is
  circular: it certifies the wrong disk after formatting it.
- `tests/setup/dev_identity.sh` on the node: readlink, major:minor, WWID (sysfs; dm uuid for a
  multipath map; parent for a partition), the MXFS envelope fsid by a direct 4 KiB read of sector 0
  (magic `MXFS` LE at byte 0, uuid at byte 16), the node's live mxfs mount. Shipped inline over
  ssh via base64 so a node without /src answers.
- `mxfs_dev_resolve` (tests/lib/rig.sh): candidate = MXFS_DEV | live mount | by-id wwn of the
  declared WWID | explicit transport default; then WWID must equal the declaration, and on a node
  with a live mxfs mount the candidate must BE it by major:minor. `mxfs_dev_check` before a
  device-consuming step after a restart/re-login/foreign format; `mxfs_dev_same` for one generation.
- A device with no WWID is refused for absence of evidence. Never fall back to path, size, model.

**The rejection fixture that actually proves the comparison exists:** `/dev/vda` alone rejects
for a MISSING WWID, which would pass with no comparison at all. `MXFS_LUN_WWID=naa.000…dead
mxfs_dev_resolve test1` makes the real LUN a well-formed device with a valid WWID and fsid that is
not the declared one — and `mxfs_dev_same test1 test2` under it shows both nodes agreeing on the
wrong LUN is still not identity. tests/rig_lib_contract.sh cases 12c/12d.

**Also:** rig-specific `/dev/sda` is the same class seen from the other rig (a path member of
the multipath map there); the lint counts `/dev/sd[a-z]`. tcpmp session chains must NAME the LUN,
not be rewritten to the TCP default: transport and storage profile are independent.
