---
name: trap-reused-node-id-override-is-a-retired-identity-p164-dead-reject-peer-never-admitted
description: TRAP (sess513): a node_id_override value that already departed once in the peer's mount lifetime is RETIRED (P164-DEAD-NOTE); its rejoin is ignored (…
metadata:
  type: feedback
tags: [harness, trap, node-id, p164, sess513]
---

# Reusing a node id in a harness = a retired identity (sess513, 2026-09-05)

tests/rejoin_residue.sh arm 4 (RR_HELD_ARM=1) rejoined B with `node_id_override=$IMPORT_ID`,
the SAME id (100) arm 1 had used and departed with. On A the peer manager had logged
`P164-DEAD-NOTE node=... identity retired; its announces/connects are ignored from now on`
for every departed incarnation, so B's announces were answered
`P164-DEAD-REJECT announce node=100 — retired identity ignored` and
`heartbeat received from unknown node 100` once per second; A's DLM view stayed at
active_count=1, B's mount parked every page request (`why[prepare=60]` x3,
`P-TAUTH-HANDOFF-DEFER ... cfg_match=0 my_view=.../1`), the harness's 40 s mount bound
killed the mount, and A then fenced slot 1 and foreign-replayed it
(tests/evidence/20260905T045512Z_rejoin_residue_s513i2h, s513i2h arm 4).

Not a filesystem defect: real node ids are random 32-bit per mount incarnation and a
collision with a retired id is ~k/2^32. It IS a harness rule: **never rejoin with an id
that has already departed in the same run**. Arm 4 now uses ID_LOW+1 / ID_HIGH-1 (same
parity as the import id). Any new harness that pins ids must pick a fresh one per
rejoin, or cycle the peer's mount between reuses.
