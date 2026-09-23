---
name: trap-a-coverage-floor-ruled-from-the-harness-shape-alone-can-demand-what-the-module-is-designed-to-forbid
description: TRAP (s72→s73, audit-gate witness): three ruled floors (same-AG carving by both nodes, its overlap, ≥1 chunk release) demanded the allocator's forbid…
metadata:
  type: feedback
---

# A coverage floor ruled from the harness shape alone can demand what the module is designed to forbid

**What happened (s71 ruling → s72 measurement → s73 re-ruling, D-THE-CLUSTERED-STRUCTURAL-AUDIT-GATE).**
The s71 consult was given the audit row's shape, the checker's output and the module's counters, and ruled floors for the allocation-coverage witness: (a) one AG with ≥2 committed carves from EACH node, (b) those spans overlap, (d) ≥1 committed chunk release, with "a retention policy that prevents release fails the assertion, never waives it". The witness was implemented (kernel counters, row, conjunctive verdict) and measured at 2/tcp: same_ag FAIL, overlap FAIL, release FAIL — rank 1 carved only in AG 0, rank 2 only in AG 1, releases 0 after 256 unlinks and a 30 s wait.

None of those were harness bugs. `xfs_dialloc_pick_ag` pins regular files AND directories to the node's affine AG on any multi-node mount (the inode-cluster clobber fix); `mxfs_ag_inode_owned` keeps a node inside its stride short of exhaustion (two nodes in one AG is the recorded precondition of the cross-node inobt double-alloc); `mxfs_inode_chunk_may_delete` returns false for every clustered mount (the 187-chunk sole-survivor corruption). The s72 record even guessed "directories still rotor" as the candidate path — wrong: line 3733-3735 pins directories too.

**The lesson.** Before asking for or implementing a non-vacuity floor, read the allocator/protocol path the floor exercises and list what the design FORBIDS. A floor that demands a forbidden state is a specification error, and measuring it costs a full build+deploy+row cycle (and a second consult) to discover. Bring the design facts INTO the consult prompt; a ruling written without them is confidently wrong in exactly the places the design was deliberate.

**The re-scoped floors (s73 Astra ruling, banked in docs/rulings/audit-gate-allocation-coverage-witness.md):** partition integrity (every carved AG has exactly one carving node, and that node owns it under the CONFIGURED stride, not the live-node count), per-node ≥2 carves in the affine AG, cluster-wide span overlap beyond offset error + drift, no RELAXED pass, releases == 0 as an invariant beside a positive empty→retain→reuse lifecycle observed live via `alloc_witness_chunk` (an unlink is not a free), sb icount/ifree reconciled with the inobt. Chunk deletion and owned-AG spill are outside the gate's claim and the claim says so.
