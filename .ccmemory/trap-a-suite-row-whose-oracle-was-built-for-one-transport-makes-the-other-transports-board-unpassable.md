---
name: trap-a-suite-row-whose-oracle-was-built-for-one-transport-makes-the-other-transports-board-unpassable
description: TRAP (0.90.6/7): 2/cawd board had never graded crash_audit/alloc_witness; TCP-only oracle + single-AG affinity model made them unpassable
metadata:
  type: feedback
---

The first full `./run.sh 2 cawd` of the CAW release campaign (0.90.6, run 20260926T181939Z) failed three rows while every MXFS behaviour row passed.  All three were harness defects, and none had ever shown because `data/criteria.json` held NO 2/cawd history for them — the rows had only ever run on 2/tcp.

- `crash_audit` drives `tests/tcp_death_replay.sh`, whose gate aborted on `ft=0` ("not on TCP"); the row could never pass on CAW.  The plain arm is transport-agnostic except the TCP authority-ledger asserts (P-TAUTH-SEAL, P-RMAN-COLLECT-TAUTH, snapshot flags=0x4).
- On CAW a bare `grep 'P-RMAN-LOAD'` matched the disklock's `P-RMAN-LOADED`, which lands after the replay's load line, so `tail -1` read the wrong line.  Anchor on `P-RMAN-LOAD victim_slot=`.
- `alloc_witness` modelled a node's AG as `slot % agcount`.  A node owns its partition (`agno mod stride == slot mod stride`, stride 32 at 2 nodes); the allocator put test1's directory in AG 32, so the fill loop and the `own_ag` floor counted 0.

Lesson: before claiming "the full suite passes" on a configuration, check that every row has a recorded verdict ON THAT CONFIGURATION (`tools/criteria.py <N> <dlm>`, the `[k genuine FAIL(s) in last k runs]` / missing history).  A row graded only on the other transport is not coverage, and its first run on the new one will often find harness assumptions, not MXFS bugs — read the oracle before suspecting the kernel.
