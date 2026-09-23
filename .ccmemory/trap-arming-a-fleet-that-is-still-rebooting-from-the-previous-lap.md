---
name: trap-arming-a-fleet-that-is-still-rebooting-from-the-previous-lap
description: TRAP (sess483): chain 130 aborted twice on "armed on only 30 of 32" — its own control lap (node_death_replay) was still rebooting two nodes when it a…
metadata:
  type: feedback
tags: [sess483, rig, harness, fleet-params, node-death-replay]
---

# A chain that reboots nodes must wait for them before arming anything

`tests/sess482_chain130_affine_audit.sh` aborted on two consecutive launches
with:

```
STAGE arm rc=0 readback_ok=30/32
ABORT: knob armed on only 30 of 32 nodes — a partially-armed fleet
       produces a denominator that cannot be attributed.
  ... 30 affine_audit_pct=5   30 rc=0   2 rc=255   mounted: 0/32
```

Both times the same two nodes (test6, test7) returned ssh **rc=255**. The
obvious reading is two broken nodes. It is wrong: a direct 32-way reachability
sweep minutes later found **all 32 up and answering**, and `mounted: 0/32` in
the abort line is the tell — the *whole* fleet was unmounted at that instant.

The chain's control lap is `node_death_replay`, which **destroys and reboots
nodes by design**. The arm step ran while two of them were still coming back.
The refusal was correct; the partial fleet was the chain's own doing.

## The rule

**Any chain whose earlier stage kills, reboots, fences or unmounts nodes must
re-establish fleet readiness before the next stage touches all of them** —
setting module params, sweeping journals, counting anything per node. A row
returning PASS does not mean its nodes are back; `run.sh` scores the row, not
the fleet's recovery afterwards.

Fixed in that chain (sess483): a readiness gate before the arm step that polls
until all 32 answer ssh **and** report `/mnt/shared` mounted, ceiling 240 s
(guest boot measured at 60–90 s, plus mount and rejoin, doubled), exiting the
moment 32/32 are back. It is a **gate, not a performance budget** — the same
standing as `tests/rig_wait_free.sh`. Waiting 90 s costs 90 s; arming early
costs the whole lap, and this one cost two.

## The generalisable half

The failure looked like a hardware/node fault and was a **sequencing** fault.
Before filing "two nodes are bad", check whether something earlier in your own
chain made them bad — and prefer a positive readiness check (`mountpoint -q`,
srcversion readback) over inferring health from the previous stage's verdict.
