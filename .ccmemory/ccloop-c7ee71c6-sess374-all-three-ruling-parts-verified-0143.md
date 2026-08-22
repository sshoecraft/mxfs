---
name: ccloop-c7ee71c6-sess374-all-three-ruling-parts-verified-0143
description: sess374 final: all 3 parts of the sess357 ruling built+rig-verified on 0.14.3 sv B0F00E729CA59423AEDDFA2; board 24 PASS; only Hazards-§7 fault tests…
metadata:
  type: project
---

# sess374 final — #3 all three ruling parts verified

Build **0.14.3 sv B0F00E729CA59423AEDDFA2**, deployed 32/caw.
Full 28-cell board: **24 PASS / 3 FLAKY(pass now) / 0 FAIL / 1 POLICY**.

## What is verified
`tests/closure_purge_scrub.sh` (new, in tree) kills test32 while it holds a
HOT root-dir EX and launches a prober genuinely blocked on that grant:

| mode | result |
|---|---|
| default | publisher purged=5, plus a natural `P299-SCRUB-STRIP ino=128 ag=0` where the blocked prober's demand beat the publisher's scan to that slot; prober rc=0 @63s |
| `SCRUB_ONLY=1` | `P299-CLOSURE-SKIP`, publisher purged=0, `P299-SCRUB-STRIP ino=128`; prober rc=0 @66s |
| `INCLOSURE=1` ag_mask=0x1 | prober rc=1 @63s — REFUSED, not timed out; purged=0 kept=6 (in-closure stays frozen, correct) |

Causal marker for part (1): `P240-QUAR-IMPORT` t=232.715s →
`P240-QUAR-WAITCANCEL type=1 ino=128 ag=0 mode=3 el_ms=64091` t=232.748s.
**33 ms**, against a measured **296 s** on the build before it.

Part (2) is satisfied by construction AND demonstrated: the refused
ag_mask is built only from AGs of refused items (xfs_log_recover.c:3252),
so an AG with no refused item is out of closure and IS revoked by part (3);
the prober then ACQUIRES and USES the released root inode.

## RULE-5 round 3 caught two real defects before ship
1. The cancel path skipped `caw_drop_own_waiter` → stranded waiter bit
   (the sess48 phantom-waiter wedge). `out:` only frees buffers; the
   TIMEOUT path is the one that drops the waiter.
2. The cancel raced a direct handoff: cancelling on top of a
   just-granted holder bit orphans it. Closed with a `!self_h` guard plus
   a post-drop re-read that owes the ADOPT arm one lap
   (`P240-QUAR-WAITCANCEL-RACE`).
GPT's lost-update worry about the quarantine map was REFUTED: writes are
already serialized under `mp->m_mxfs_quar_lock` (xfs_mxfs_dlm.c:46291).
GPT's "hold the publisher lease on partial purge" was REFUTED by the
standing sess363 ruling item C ("release lease regardless") — the retry
protocol is the leaseless survivor scrub.

## What remains before this entry can close
The sess363 ruling's **Hazards §7** fault-test list — the FIX's own
failure modes, not the defect's cause. INJECT, do not argue:
gate failure at every CAS boundary; HB sector unreadable; descriptor crc
fail; expected-vs-platter mask mismatch (-ESTALE); tombstone/slot-reuse
race; racing waiters; a slot carrying MULTIPLE victims; waiter-only and
open-holder-only slots; victim node 0; mount/adopt racing the terminal
import; CAS-exhaustion partial reporting.
Publisher-death-post-publish is DONE via `closure_skip_publisher_purge`.

## Code map for the next session
- `dlm/dlm_caw.c`: `caw_strip_node_state`, `caw_victim_state_mask`,
  `caw_closure_strip_one`, `caw_purge_victim_selective_body`,
  `caw_closure_scrub_slot`; hooks in `caw_wait_for_grant` (right after the
  magic check: quarantine cancel, then the scrub) and at the NOQUEUE
  conflict exit in `caw_lock`.
- `dlm/disklock.c`: `closure_gate_predicate` +
  `mxfs_disklock_closure_gate_snapshot` / `_gate_revalidate` /
  `mxfs_disklock_terminal_gate_check` (leaseless).
- `dlm/v5_mount.c`: `v5_closure_gate`, `v5_closure_scrub`,
  `v5_wait_refuse`, `v5_closure_note_terminal` (+ `closure_lock`).
- `xfs/xfs_mxfs_dlm.c`: `mxfs_dlm_quar_covers_cb`,
  `mxfs_dlm_closure_classify_cb`, publisher call site in
  `mxfs_freplay_publish_refusal`.
