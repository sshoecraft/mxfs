---
name: ccloop-c7ee71c6-sess377-pr-leak-found-fixed-verified-0.14.11
description: sess377 final: PR registration leak FOUND, root-caused, FIXED AND VERIFIED on 0.14.11 (table 62->0 at 31 nodes); 2 residuals filed; open=49 of 106; r…
metadata:
  type: project
tags: [sess377, scsipr, fencing, defect-377, chk_mxfs, quarantine]
---

«sess377 second half — the PR registration leak, found by the new tooling»

## How it was found (worth repeating)

Building the offline quarantine-repair path forced me to write a REAL exclusion
proof — "no initiator may be registered on the LUN" — instead of the usual
"no heartbeat is beating". The first time it ran on a fully unmounted 32-node
cluster it REFUSED, naming a registered key. That refusal was correct and it
exposed a critical defect nothing else in the project could see.

Lesson: an honest precondition check is a defect detector. The heartbeat table
cannot answer "who can still write to this device"; only the PR registration
table can, and until this session nothing read it.

## D-CLEAN-UNMOUNT-LEAKS-PR-REGISTRATION-377 — CLOSED, FIXED AND VERIFIED

ROOT (code + measurement): register used PR_FL_IGNORE_KEY (SA 0x06), which
every dm-multipath path accepts unconditionally, so BOTH nexuses registered.
Unregister used a PLAIN REGISTER (SA 0x00, old_key=key); a path whose nexus key
does not match answers RESERVATION CONFLICT, dm's first pass runs with
fail_early, the iteration stopped, and the other nexus kept its registration.
Then `if (ret == 0x18 || ret == -EBUSY) return 0;` reported success. Every
clean unmount left the departing node able to write to the shared LUN.

FIX (0.14.11 sv 59F765EF4CFF9E513F37FE2): symmetric all-nexus unregister
(`pr_register(bdev, key, 0, PR_FL_IGNORE_KEY)`), the conflict->success mapping
deleted, plus a mandatory READ KEYS read-back that grows its buffer while the
target's reported total exceeds capacity (a truncated view can never read as
absence), bounded by BOTH 6 attempts and a 20s wall-clock deadline. The
mxfs_bdev_t form now calls the bdev form instead of open-coding a second copy —
two copies is how the bug existed on two paths. Markers P301-PR-UNREG-*,
P301-PR-AUTHORITY-NOT-RETIRED, P301-DEPARTURE-INCOMPLETE.

VERIFIED by the new `tests/pr_departure.sh` (refuses to pass on a single-path
device — the leak is a per-nexus asymmetry). 2026-08-20T02:45:51Z, 32/caw,
starting from an EMPTY table: arm A 3/3 round trips 0->2->0; arm B 31 nodes
mounted 0->62 (exactly 2 per node), all unmounted 62->0. TABLE EMPTY.
Pre-fix baseline on 0.14.10 the same session: leaked 2/2.

## Filed, because the ruling asked for more than I built

- D-PR-RETIREMENT-FAILURE-NOT-FAIL-CLOSED-377 (critical): "verify and log is
  not enough". No fail-closed action when retirement cannot be proved, no
  serialization against re-registration/multipathd replay, no AUTHORIZED
  survivor reaper for orphan keys. The ruling's two-phase departure design is
  in the entry's `next`.
- D-PR-KEY-32BIT-NODE-ID-COLLISION-RISK-377 (high): the PR key is a 32-bit
  per-incarnation node_id in a 64-bit field, with no durable
  key -> cluster/host/incarnation mapping. Keep per-incarnation (a stable
  per-host key is WORSE — a PREEMPT for the old incarnation would remove the
  new one); widen to a collision-resistant 64-bit id and add the mapping.

## Ledger: open=49 of 106

Finding real problems raises the count. 47 -> 48 (PR leak filed) -> 47 (closed)
-> 49 (two residuals).

## Also landed this session (see the earlier sess377 memories)

- `chk_mxfs --pr-keys` — read-only registration table, each key decoded as a
  node_id. THE detector for the whole PR family.
- `chk_mxfs --show-quarantine` — full terminal-verdict decode + stable digest.
- `chk_mxfs --accept-quarantine-loss <slice> --confirm <digest> --archive-to
  <path>` — steps 1-4 of the repair (validate/display, exclusion proof,
  every-other-slice-settled proof, mandatory verified off-volume archive with a
  backing-device disjointness check). It STOPS before the destructive half and
  says so; exit 3. Steps 5-9 are the next landing.
- chk_mxfs classification fixes: flags is an ENUM not a bitmask (a quarantined
  slot read as a LIVE MEMBER); a descriptor-less guard is a transient
  bucket-sweep guard, not a corrupt verdict; flags==EMPTY with MXLK magic is a
  RELEASED slot, not an "unknown record" (31 clean departures were being
  reported as 31 corrupt sectors).

## RIG STATE AT HANDOFF — read before doing anything

- Build in tree: 0.14.11 sv 59F765EF4CFF9E513F37FE2. Fleet last mounted with
  it during pr_departure arm B, now ALL 32 NODES UNMOUNTED.
- A REAL terminal quarantine still stands at heartbeat slot 2 (victim node
  3510436867, incarnation 2928541969495874252, digest 6D2B17DB2D26F20F, domain
  AG_MASK 0x4 = AG 2). 31 slots released, usable RW slices 31 of 32.
  Re-confirmed incidentally: 31 nodes mounted concurrently and NONE took slot 2.
- PR registration table is EMPTY.
- `./run.sh 32 caw prep_cluster` mkfs's and destroys the quarantine.
  tests/quarantine_admission.sh 32 test30 0x4 recreates one in ~3.5 min.
- NOT YET DONE and it is the first thing to do: a full board on 0.14.11. The PR
  change touches the unmount path on every node, so the board is the
  regression check. Board was 27 PASS / 1 FAIL (the open_defects policy cell)
  on 0.14.10 before these changes.
- clyde's host kernel is still corrupting memory (3 oopses, unchanged) and
  still needs a human reset — see
  `clyde-host-ext4-slab-corruption-kills-rig-nodes-sess377`.
