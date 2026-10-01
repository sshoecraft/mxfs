# MXFS Roadmap

Work that is wanted and not yet built. An item leaves this file when it is
done, and the `CHANGELOG.md` entry for that version records it. Nothing here is
done, dated or in progress. Design lives in `docs/`, broken things live in the
defect queue (`tools/defects.py`), and the platform roadmap lives in
`data/platforms.json` (`tools/platforms.py`).

## Lock methods

A configuration's `<method>` field has room for more than `net/mesh` and
`disk/caw`. What each would be is in `docs/attachment-methods.md`.

- **`net/server`**: lock state is kept by a lock server rather than a mesh of
  peers.
- **`disk/reserve`**: SCSI-2 RESERVE/RELEASE around a lock-block update, the way
  VMFS worked before ATS.
- **`disk/pr`**: SCSI persistent reservations used as the lock, or as the
  mutual-exclusion step around a plain write.
- **`disk/fused`**: NVMe fused Compare+Write, the NVMe counterpart of COMPARE
  AND WRITE.
- **`disk/paxos`**: Disk Paxos / disk leases. Consensus on plain reads and
  writes to per-node blocks, so it needs no atomic command. It works on any
  shared disk at the cost of more I/O per lock.

## Fencing

- **A pluggable fencing module.** Fencing is hardwired to SCSI persistent
  reservations (`dlm/scsipr.c`). The design, `docs/fencing.md`, gives the method
  interface (arm, fence, evidence) and the methods `scsipr`, `drbd`, `power`,
  `hypervisor`, `cloud` and `nvmepr`. A design consult comes before any
  implementation, because this changes recovery semantics.
- **Death thresholds validated at 16 nodes and above.** The heartbeat and lease
  death thresholds have not been measured at 16+ nodes, where iSCSI congestion
  can make a live node look dead.

## Attachments and storage

- **DRBD dual-primary (`drbd` attach).** Two nodes, each with a local disk
  replicated by DRBD, mounted as one MXFS, with no separate storage server. It
  needs a fencing method that works without SCSI reservations, and a coherency
  read path that does not rely on SCSI commands.
- **NVMe.** Three separate pieces: the `disk/fused` lock method, `nvmepr`
  fencing, and NVMe-oF as a fabric. Whether the rig can emulate NVMe well enough
  to test these is itself open.
- **TCP over multipath and passthrough.** `net/mesh/mpath` and `net/mesh/pass`
  have never been run. TCP fences through the LUN exactly as CAW does, so both
  attachments apply to it.
- **Multipath and passthrough in the release matrix.** `disk/caw/mpath` and
  `disk/caw/pass` run on the rig, but no release has been graded on either.
