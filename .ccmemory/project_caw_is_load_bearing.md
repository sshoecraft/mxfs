---
name: CAW DLM is load-bearing for scale, not a design mistake
description: CAW is the primary DLM transport because TCP DLM is performance-limited above 16 nodes (serial lock-master-per-resource bottleneck + 120-connection congestion). Documented in mxfs.1/2/3 prior art. Do not propose replacing CAW with TCP/kernel-DLM as an "architectural fix."
type: project
originSessionId: 577f8f30-2496-458a-8b8e-8c2966f4ae36
---
CAW (SCSI Compare-And-Write) is MXFS's primary DLM coordination transport.
This is a deliberate, hard-won scaling choice — supported by extensive
benchmark and bug-fix history in `~/src/mxfs.1/` (and continued in mxfs.2/3).

**Why (per documented evidence in mxfs.1 prior art):**
- `~/src/mxfs.1/README.md` and `docs/architecture.md`: TCP DLM is correct at
  32 nodes (zero crashes, zero corruption) but performance-limited above
  ~16 nodes due to single-lock-master-per-resource serial bottleneck.
  32-node test: only 27% metadata completion. 16-node test: 100% pass.
- `~/src/mxfs.1/bench.json`: TCP DLM shows 6.5x-7.7x per-node write
  imbalance at 4+ nodes; CAW DLM shows 1.01x spread on identical hardware.
- `~/src/mxfs.1/libmxfs/lease.md`: At 16+ nodes the DLM creates 120 TCP
  peer connections; heavy DLM traffic fills send buffers, blocking lease
  renewals and causing false node-death cascades. Heartbeats were moved
  off TCP onto UDP multicast specifically because of this.
- `~/src/mxfs.1/libmxfs/mount.c::check_tcp_scale_warning` already emits a
  one-shot dmesg warning recommending CAW above 16 TCP DLM nodes.
- `~/src/mxfs.1/scale_tests_session10.txt`: CAW also has scaling cost
  (BAST poll I/O at 8 nodes can saturate the iSCSI target). Addressed via
  poll-frequency reduction and BAST yield quantum (`MXFS_BAST_YIELD_QUANTUM`).

User verbal characterization: "TCP saturates and begins to lose packets,
around 24 nodes it completely falls off." Spirit is correct, mechanism is
more specific: TCP DLM is *correct* at 32 nodes (no data loss) but
unusable for production due to (a) serial lock-master bottleneck and
(b) TCP send-buffer congestion causing cascading false-death disconnects.

**How to apply:**
- When debugging a CAW bug, fix CAW. Do NOT propose "switch to kernel TCP
  DLM for the lock-coordination critical path" as an architectural cure-all.
  The prior-art evidence is unambiguous that TCP doesn't substitute for CAW
  on production-scale clusters.
- TCP DLM (`dlm/v5_mount.c`, `mxfs.force_transport=1` in v5) is a
  legitimate fallback for hardware that lacks CAW support and for small
  clusters (<16 nodes), and must keep working — but it is not a substitute
  for CAW on production-scale clusters.
- When comparing MXFS to GFS2/OCFS2, separate two axes:
  (a) DLM transport — GFS2/OCFS2 use kernel TCP DLM and don't aim at >24-
      node shared filesystems; their transport is not a model for MXFS.
  (b) Cache-coherency contract on lock release/demote — GFS2/OCFS2 ARE good
      references here (see project_gfs2_coherency_pattern.md). The contract is
      independent of transport.
- The kernel `scsi_execute_cmd` non-persistence bug (sess26 P49-INSTR
  finding) is a real kernel SCSI passthrough bug worth root-causing, not
  evidence that CAW is the wrong primitive.
