---
name: sess383-forged-record-harness-and-three-fail-open-arms
description: sess383: the sess333 pre-rig checks finally RAN — tools/recov_forge forges real GUARD records on the LUN; 3 fail-open arms measured and fixed in 0.19…
metadata:
  type: project
tags: [mxfs, d-513, recov_forge, fail-open, fs_gen, admission]
---

# sess383 — the checks that had been "NEXT" for 40 sessions, and what they found

## The blocker was tooling, not difficulty

D-513's remaining work had read "pre-rig checks 1-4 + check5" since sess337.
Nothing in the tree could produce the inputs: the kernel only ever writes
well-formed outcome records. `tools/recov_forge.c` closes that — it writes a
REAL GUARD record to a real heartbeat sector with the REAL crc binding
(crc32c over the record folded with the sector's `{fs_gen, node_id, epoch}`),
over SG_IO READ(16)/WRITE(16)+FUA.

The whole matrix took **~4 minutes** to run once the tool existed. Each shape
is ~15 s and **non-destructive**: forge into an UNUSED slot (40 on a 32-node
rig), cycle ONE node's mount, restore. The other 31 nodes stay up; no re-prep.
That property is what made a 17-shape matrix affordable at all — the earlier
plan assumed each check needed its own cluster re-prep.

`tests/d513_forged_matrix.sh` runs them all and summarises.

## Where the trigger comes from (the non-obvious part)

A forged GUARD record is picked up because
`mxfs_disklock_get_recovery_pending_slots()` masks in ANY slot with a
sub-complete recovery descriptor. So: forge → remount one node → its
admission barrier classifies the slot. No fault injection, no kill, no race.

Three constraints that make or break a forge:
- `fs_gen` must match the live filesystem or every sweep skips it as a
  pre-mkfs ghost (`hb_gen_foreign`) — `mkguard` auto-detects it from slot 0.
- `stage >= MXFS_RECOV_STAGE_GRANTS_RELEASED` makes the sweep skip the slot,
  which is how you reach the REGISTRATION path without the barrier — that is
  what exposed arm C.
- a GUARD record is `hb.flags == RECOVERY_GUARD` + `desc.magic == MRCV`;
  `recov_desc_present()` needs all of it.

## Six shapes passed, three arms failed

PASS: broken descriptor crc (-EPROTO), misplaced descriptor with an all-zero
outcome (P241-RECOV-BACKFILL-IDENT), broken outcome crc (-EBADMSG),
crc-valid `outcome=99` / `reason=99` / `AG_MASK+mask=0` / `oc.victim_slot`
mismatch (all four rejected by `mxfs_freplay_import_verdict`), legacy
backfill, valid AG-scoped verdict. Every refusing path left the sector
**byte-identical** (compared by crc32c) and nothing shut down.

FAIL — see ledger `D-TERMINAL-OUTCOME-IMPORT-UNVALIDATED-383`:
- **A** the registration scan is a 4th import site with NO validation.
- **B** `recovery_read_outcome` had no `fs_gen` gate, so a pre-mkfs ghost
  quarantined the live filesystem.
- **C** an FSWIDE quarantine found by that scan did not refuse the mount —
  `mount rc=0` with `fswide=1`. The barrier's gates run ~0.5 s earlier.

## The measurement that pinned arm C

From the `valid` shape's dmesg, one mount:
```
6318.753621  classify ... imported          <- barrier (inside xfs_mountfs)
6319.263963  P240-QUAR-REFUSE comm=mount
6319.318984  P241-RECOV-TERMINAL-SCAN       <- registration scan
```
The scan is **after** the barrier, so neither FSWIDE gate can see what it
imports. Do not re-derive this ordering from the header comments —
`xfs_mxfs_dlm.h:301` says the opposite of what the code does.

## Fixed in 0.19.6 (sv 4B6E8D0FC2DD9A2802D6049)

Per the sess383 ruling: one structural chokepoint
(`recov_outcome_structural`) with a generation gate returning a distinct
`-ESTALE` and a descriptor-identity gate; `quar_cb` returns
`enum mxfs_quar_disposition` so closure candidacy follows validation instead
of following "something got imported"; the monitor's `outcome ==
TERMINAL_REFUSED` prefilter removed (it was a bypass); and
`mxfs_dlm_admission_commit()` closing an ADMITTING→ADMITTED transition under
the same spinlock every import takes.
