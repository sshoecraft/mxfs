---
name: ccloop-c7ee71c6-sess70-PR-is-ACTIVE-not-advisory-and-preempt-lacks-abort
description: sess70: the sess69 "advisory PR" premise is WRONG for this rig — per-node PR is ACTIVE. Real defect: our fence issues PREEMPT (0x04), never PREEMPT A…
metadata:
  type: reference
tags: [recovery, fencing, scsipr, critical, measured-on-rig, ledger, consult-owed]
---

# sess70 — the advisory-PR premise is WRONG for this rig, and the real fence defect is PREEMPT-without-ABORT

Build unchanged at **0.11.412** (`2C85D70AD8070513B81D772`). No code written
this session. Ledger updated; discovery + measurement done.

## 1. THE CORRECTION THAT MATTERS — per-node PR is ACTIVE on this rig

sess69 concluded "on this rig every VM shares one host I_T nexus, so per-node
PR is unusable and fencing is advisory", and the whole sess69 GPT ruling was
built on that. **It is false for the CURRENT rig.** That finding came from the
old *tcm_loop* rig; the rig today is an SCST **iSCSI** target where each VM is
its own initiator. Measured directly, not inferred:

- `P-PR-PROBE 'mxfs': own key visible, N key(s) registered — per-node PR
  active` in dmesg on test1/test2/test3.
- `sg_persist -i -k /dev/mapper/mpatha` — **33 distinct keys, 64 total
  entries** at 32 nodes x 2 multipath paths. One unique key per node.
- `sg_persist -i -r` — a real reservation is held:
  **`type: Write Exclusive, registrants only`** (WE-RO).
- No stale keys accumulate, even though nodes were `virsh destroy`ed during
  the last board ⇒ the target appears to drop registrations on I_T nexus loss.

**Consequence:** the sess69 "fail closed, there is no safe automatic recovery"
conclusion does NOT apply here. Real exclusion IS obtainable. P0 stays, but it
is a *typing + gating* job, not a capitulation — and it will NOT blind the
board, because the criteria can still obtain proven exclusion.

Method note: `sg_persist` is installed on the nodes and the device is
`/dev/mapper/mpatha`. This is the cheap way to settle PR questions — do not
re-derive them from comments in the tree, which describe a rig that no longer
exists.

## 2. THE NEW SHIPPED DEFECT — PREEMPT (0x04), never PREEMPT AND ABORT (0x05)

`pal/linux/kern.c:2836-2845`:

    ret = ops->pr_preempt(dev->bdev, my_key, victim_key,
                          PR_WRITE_EXCLUSIVE_REG_ONLY,
                          false);          /* <-- the `abort` flag */

`/src/linux/include/linux/pr.h:26-27` — the prototype's last arg is
`bool abort`. `/src/linux/drivers/scsi/sd.c:2204-2209` —
`sd_pr_out_command(bdev, abort ? 0x05 : 0x04, ...)`. So `false` is literally
**PREEMPT**, not PREEMPT AND ABORT, in every build since v0.11.80.

SPC-4: PREEMPT removes the registration (so commands the target has not yet
*begun processing* are rejected with RESERVATION CONFLICT, because the
reservation is evaluated at command-processing time) but does **not** abort the
preempted I_T nexus's task set. PREEMPT AND ABORT also aborts those tasks and
does not complete until they are aborted. **The delta is exactly the in-flight
window** — and both recovery criteria kill the victim *mid-write*
(`crash_consistency.sh:69`, `fence_during_write.sh:77` — `virsh destroy`), so
the victim's task set is non-empty by construction.

**The target supports 0x05 — measured, not assumed:**

    sg_persist --out --preempt-abort --param-rk=<held key> \
               --param-sark=0xdeadbeef1 --prout-type=5 /dev/mapper/mpatha
    -> "PR out (Preempt and abort): Reservation conflict"

RESERVATION CONFLICT is the *correct* SPC answer for an unregistered SARK and
proves the service action was recognised and processed. An unsupported SA
returns ILLEGAL REQUEST / INVALID FIELD IN CDB.

## 3. Also line-proven this session

- **No heartbeat-loss self-fence exists.** `dlm/disklock.c:534-540` logs
  `heartbeat write failed ... age_since_last_ok_ms=` and **continues**. The
  only self-fences in the tree are P131 (device re-mkfs'd under a live mount,
  `v5_mount.c:1194`) and P-PR-SELFFENCE (own PR key preempted,
  `v5_mount.c:966-975` + `v5_mount.c:718-723`). A heartbeat-dead but disk-alive
  node keeps writing while peers declare it dead and replay its slice.
- **The replay chain's only exclusion predicate is `fence_node()==0`:**
  `v5_mount.c:1378` → `v5_pr_fence_dead_node()` (which is literally
  `v5_pr_fence_dead_node_rc(...) == 0`, `v5_mount.c:736-739`) →
  `v5_start_slice_recovery` → `v5_dispatch_slice_recovery` →
  `dead_node_notify_fn` → `xfs_mxfs_dlm.c:42199` set_bit + queue_work →
  `xfs_mxfs_dlm.c:42090` `mxfs_xlog_recover_foreign_slice()`.
- **The mount-barrier cohort path has NO fence predicate at all** —
  `xfs_mxfs_dlm.c:42509` replays every cohort slot; the loop contains
  invalidate/flush/durability gates but nothing about exclusion.
- **The re-election sweep re-dispatches replay for OTHER pending slots**
  (`v5_mount.c:1272-1288`, `p != dead_slot`) whose elected replayer just died —
  those victims were fenced by someone else at some other time and nothing
  re-verifies it.
- `mxfs_scsipr_fence_node()` has **four** distinct `return 0` paths:
  `-EOPNOTSUPP` from read_keys; `count < live_members` (advisory);
  `!own_present` sole-survivor; `!victim_present` (already absent). Only
  falling through all four reaches a real preempt. `v5_mount.c:686-693`
  documents conflating them as deliberate.

## 4. LEDGERED — 4 new entries (`tests/criteria/OPEN_DEFECTS.json`, now 46 total / 18 OPEN)

- `D-PR-FENCE-PREEMPT-WITHOUT-ABORT` (critical) — section 2 above.
- `D-FENCED-STAGE-WITHOUT-PROVEN-EXCLUSION` (critical) — `MXFS_RECOV_STAGE_FENCED`
  written whenever `fence_node()` returns 0, i.e. asserts a guarantee that in
  3 of 4 cases was never obtained, and no reader can tell which.
- `D-VICTIM-REPLAY-WITHOUT-PROVEN-EXCLUSION` (critical) — in-place XFS replay
  onto the shared LUN gated only on that boolean.
- `D-PURGE-NONATOMIC-PUBLICATION` (critical, FIXED in 0.11.412, verification
  owed) — the sess69 CAS fix; needs a concurrent-purger test before RULE 6
  closure.

Script that added them:
`/tmp/claude-1000/-src-mxfs/*/scratchpad/add_defects.py` (idempotent — it skips
ids already present).

## 5. THE CONSULT — RE-ISSUE IT, it was lost to the relay boundary

Fired at the boundary, exceeded the 120 s MCP window, went to background as
task `k2htwgg8y`, **does not survive the session**. The full text is in this
session's transcript; re-send it. Give GPT the corrected premise up front (PR
is ACTIVE, WE-RO reservation held, one key per node) — that is what
invalidates its sess69 ruling. Its four questions:

- **Q1** Is `HARD_PR_ABSENT_RESERVED` sound? i.e. victim key absent, but we
  positively verified (a) active per-node PR topology and (b) a held WE-RO
  reservation ⇒ the victim is not a registrant ⇒ its commands are rejected at
  processing time ⇒ exclusion proven. This matters because at 32 nodes up to
  31 survivors race to fence one victim, "already absent" is the COMMON path,
  and the elected replayer (lowest live slot) is often a loser of that race.
  If not admissible, what is the protocol — fence winner publishes drained
  evidence durably, or only the elected replayer fences?
- **Q2** Hazards of 0x05 at 32 nodes: 31 concurrent PREEMPT AND ABORTs for one
  victim key; the first wins, the rest get RESERVATION CONFLICT, which our
  code currently maps to success — still correct under 0x05, or does it now
  hide a failed abort? And with **dm-multipath (2 paths/node)**, does one 0x05
  abort BOTH of the victim's I_T nexuses, or is per-path handling required?
  (GPT's own "fence scope" point: a fence must cover the victim's whole I/O
  capability.)
- **Q3** With PR active, is a heartbeat-loss self-fence still *required* or now
  defence-in-depth? My reading: required, for the window between the victim's
  last good heartbeat and the survivor's completed preempt-and-abort. What is
  the correct timing relation between the self-fence deadline and the
  survivors' death-declaration deadline?
- **Q4** Mount-time cohort recovery replays stale-heartbeat slots with no fence
  at all. What is a *mounting* node's exclusion obligation when it cannot
  distinguish "died long ago" from "alive right now, not yet met"?

## 6. Implementation plan (drafted, pending the consult)

1. `pal/pal.h` + `pal/linux/kern.c` + `pal/linux/user.c` — plumb `bool abort`
   through `mxfs_pal_scsi_pr_preempt()`; keep the UA-retry loop (an aborted
   PREEMPT AND ABORT leaves the victim unfenced). Add
   `mxfs_pal_scsi_pr_read_reservation()` — **does not exist today**; Linux
   `pr_ops->pr_read_reservation` + `struct pr_held_reservation {key, generation,
   type}` is the backing. Needed for the class-2 verification.
2. `dlm/scsipr.{h,c}` — `enum mxfs_fence_kind` out-param; issue 0x05.
3. `dlm/disklock.{h,c}` — descriptor **v2**: `victim_exclusion_kind` /
   `owner_exclusion_kind`; rename stage `FENCED` → `VICTIM_EXCLUSION_PROVEN`;
   `recovery_begin()` takes the kind and refuses an exclusion-proven stage for
   a non-authorizing kind. Wire format is still free to change (nothing
   deployed has ever written a descriptor). NOTE: `struct mxfs_recov_desc` is
   **exactly 80 bytes and fully packed** (crc32c at offset 76) — new fields
   need the descriptor extended into the GUARD record's evict-ring space;
   check the ring size first.
4. `dlm/v5_mount.c` — `v5_pr_fence_dead_node_rc()` returns the kind; only
   authorizing kinds reach `v5_start_slice_recovery`; non-authorizing → durable
   `RECOVERY_BLOCKED_NO_IO_EXCLUSION` + loud diagnostics, slot stays frozen.
5. `xfs/xfs_mxfs_dlm.c` — gate BOTH dispatch sites (42090 live work fn, 42509
   mount barrier) and the re-election sweep on a proven kind.

## 7. Rig state

32/32 VMs running, cluster mounted (`/dev/mapper/mpatha` on `/mnt/shared`,
type `mxfs`). 0.11.412 is a green baseline: `fence_during_write` 32/32 8/8
17s/60s, `crash_consistency` 32/32 204/204 86s/90s, `dir_reuse_coherency`
32/32 93/93 107s/120s. Board before landing the descriptor change so a
regression is attributable.
