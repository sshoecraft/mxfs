---
name: ccloop-c7ee71c6-sess132-SCST-preempt-abort-code-proof-and-pr-trace-channel
description: sess132: SCST's PREEMPT AND ABORT provably waits for the victim's in-flight commands (core, handler-independent) + SCST `pr` tracing is a live on-wir…
metadata:
  type: reference
tags: [D-PR-FENCE-PREEMPT-WITHOUT-ABORT, scst, scsi-pr, fencing, rig]
---

# SCST P&A internals + the `pr` trace channel (sess132, read from /src/scst)

Context: D-PR-FENCE-PREEMPT-WITHOUT-ABORT step 4 — "prove the IN-FLIGHT WRITE is
excluded". These are CODE facts (RULE 4 step 1 hypothesis material), NOT
measurements. They must still be measured.

## The rig's target is SCST, not LIO
`/sys/kernel/scst_tgt/devices/mxfs` — handler **vdisk_fileio**, backing file
`/home/steve/disk.img` (50 GB), `o_direct=1`, `threads_num=8`, `cluster_mode=0`,
PR state persisted at `/var/lib/scst/pr/mxfs`. One iSCSI target
`iqn.2026-05.local.mxfs:shared`, LUN 0, two portals (192.168.120.1/.2),
**64 sessions = 32 nodes x 2 paths**, multipath `mpatha` per node.
LIO configfs also exists on clyde but serves nothing.

## SCST's PREEMPT AND ABORT DOES wait for the victim's outstanding commands
Chain, all in SCST **core** (`scst/src/scst_pres.c`, `scst_targ.c`):

1. `scst_pr_preempt_and_abort()` (scst_pres.c:2251) allocates `pr_abort_counter`,
   sets `pr_abort_pending_cnt=1`, `pr_aborting_cnt=1`, and **overrides
   `cmd->scst_cmd_done` with `scst_cmd_done_pr_preempt`**.
2. `scst_pr_do_preempt(..., abort=true)` calls `scst_pr_abort_reg()`
   (scst_pres.c:558) for EVERY preempted registrant, which issues
   `scst_rx_mgmt_fn_lun(sess, SCST_PR_ABORT_ALL, ...)`.
   `scst_alloc_mgmt_cmd` (scst_targ.c:6721-6722) bumps BOTH counters per mcmd.
3. Back in `scst_pr_preempt_and_abort`:
   `if (!atomic_dec_and_test(&pr_aborting_cnt)) wait_for_completion(&pr_aborting_cmpl);`
   — released at scst_targ.c:5583 inside `scst_abort_task_set()`, i.e. after
   `__scst_abort_task_set()` has marked every one of the victim's commands aborted.
4. The P&A's own SCSI status is deferred further: `scst_cmd_done_pr_preempt`
   only calls the saved done when `pr_abort_pending_cnt` hits 0, and that is
   decremented from `scst_mgmt_cmd_send_done()` (scst_targ.c:6520,
   `mcmd->origin_pr_cmd->scst_cmd_done(...)`), reached only after the TM state
   machine passes **`SCST_MCMD_STATE_WAITING_AFFECTED_CMDS_DONE`** and
   **`SCST_MCMD_STATE_WAITING_AFFECTED_CMDS_FINISHED`** (scst_targ.c:5288-5305).

**Consequence (hypothesis to measure):** the P&A response is not sent until the
victim's already-submitted commands have completed or failed. So a held victim
write is expected to LAND, but strictly BEFORE the P&A returns. No SCSI target
can un-submit a bio; literal "bytes never on the platter" is not achievable by
any implementation, which is why the ledger's step-4 wording is a shape
suggestion, not the invariant. Measure BOTH properties and report both.

## The handler difference is NIL for this property
`vdisk_file_devtype` (scst_vdisk.c:9574) and `vdisk_blk_devtype` (:9663) BOTH
use the same `.task_mgmt_fn_done = vdisk_task_mgmt_fn_done` and NEITHER defines
`task_mgmt_fn_received`. The abort/wait machinery is entirely core. This
directly answers the RULE-5 blocker "blockio does not establish fileio's
behaviour" at the code level — but a same-handler measurement is still stronger.

## `pr` TRACING IS A LIVE ON-WIRE EVIDENCE CHANNEL — ENABLED THIS SESSION
`echo "add pr" > /sys/kernel/scst_tgt/trace_level` (verified: level is now
`out_of_mem | minor | pid | line | function | special | mgmt | mgmt_dbg | pr | retry`).
Turn off with `echo "del pr" > .../trace_level`.

Measured cost at rig idle: **0 extra dmesg lines in 20 s** — safe to leave on.
It is verbose only while PR commands are actually issued (a READ KEYS prints one
line per key = 64 lines here). LEFT ON deliberately so the next real fence is captured.

What it yields, from the TARGET's own parser (clyde `dmesg`):
- `scst_pr_do_preempt`: `"Preempt and abort: initiator <iqn>/<rel_tgt_id> ...,
  key %016llx, action_key %016llx, scope %x type %x"` — the literal string
  `" and abort"` is printed only for service action **0x05**. This is on-wire
  proof of the service action MXFS's OWN kernel fence path emitted, on the
  SHIPPED LUN, with no sg_persist involved. It closes the RULE-5 blocker
  "sg_persist does not exercise the patched MXFS call chain".
- `scst_pr_abort_reg`: `"Aborting %d commands for %s/%d (reg %p, key ..., tgt_dev %p, sess %p)"`
  — **N = the size of the victim's task set at the instant of the abort.**
  This is the direct observation of target-side in-flight state that the RULE-5
  ruling demands instead of "sleep 1 second and assume".

Verified working: a `sg_persist --in --read-keys` from test31 produced
`scst: scst_pr_read_keys:2446:Read Keys (dev mxfs): key 0x...` lines in clyde dmesg.

## Multipath / nexus scope — resolved for the production LUN
READ KEYS shows each node's key **twice** (once per path). SCST's
`scst_pr_find_registrants_list_key()` collects ALL registrants holding the action
key, and `scst_pr_abort_reg` runs per registrant, so one P&A of a node's key
aborts the task sets of BOTH of that node's sessions. The RULE-5 "which path was
preempted?" ambiguity therefore does not apply to MXFS's production topology —
but it DOES apply to any purpose-built test LUN, which should be single-path.

## Other facts banked
- No module knob triggers `mxfs_scsipr_fence_node()`; the kernel fence path runs
  only from real peer-death detection (`v5_mount.c:788`, `:1097` via
  `v5_lease_expire_cb`). Driving it means actually killing a node.
- `dlm/scsipr.c:465` issues `mxfs_scsipr_preempt(ctx, victim_key, true)` and the
  common 32-node outcome is `MXFS_FENCE_KIND_KEY_ABSENT_UNPROVEN` (30 of 31
  survivors find the key already gone) — so a fence capture must identify the
  WINNER's node, not any survivor.
- Prereqs verified present on clyde: `dm-delay` module (loads, target v1.4.0),
  `vdisk_blockio` + `vdisk_fileio` handlers, 547 G free. Nodes have
  `sg_persist` 0.67, `sg_raw`, `iscsiadm`.
