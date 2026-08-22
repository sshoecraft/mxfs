---
name: sess378-dm-pr-preempt-drops-abort-upstream-kernel-bug
description: ROOT CAUSE PROVEN sess378: Linux dm_pr_preempt() never sets pr.abort, so PREEMPT AND ABORT is silently downgraded to PREEMPT on every dm-multipath de…
metadata:
  type: project
tags: [D-PR-FENCE-PREEMPT-WITHOUT-ABORT, fencing, scsipr, kernel-bug, dm-multipath, sess378]
---

# The MXFS fence has never issued PREEMPT AND ABORT on this rig

Measured 2026-08-20 (sess378), 0.14.11, 32/caw, on the SHIPPED production LUN.

## The measurement (stage iii, `tests/fence_stage3_real.sh`)

Hard-killed test30 with `virsh destroy`. test29 fenced it 104 s later. Captured
BOTH sides:

TARGET side — SCST's own CDB parser, under the `pr` trace flag:

    scst_pr_do_preempt:2097:Preempt: initiator
      iqn.2004-10.com.ubuntu:01:test29-mxfs-node,i,0x100003d0200/2,
      key 00000000a59a3bbb, action_key 000000007ef9f9d3, scope 0 type 5

`Preempt:` — **not** `Preempt and abort:`. That substring appears ONLY for
service action 0x05 (`scst_pr_preempt_and_abort` -> `scst_pr_do_preempt(abort=true)`).
0 "and abort" lines; 1 plain "Preempt:" line.

MXFS side, same instant:

    P236-FENCEKIND node=2130311635 kind=PREEMPT_ABORT_DONE(16) proves_excl=1 rc=0
    P236-FENCE-CERTIFIED slot=7 ... kind=PREEMPT_ABORT_DONE resv=0x05 ...
      exclusion is PROVED and durable

**MXFS certifies exclusion as PROVED, durably, on the strength of a service
action that does not abort anything.** The certificate is false.

## ROOT CAUSE — an upstream Linux kernel bug, not an MXFS bug

`/src/linux/drivers/md/dm.c` (6.19.0-rc0; same behaviour on the running
6.8.0-101):

    static int dm_pr_preempt(struct block_device *bdev, u64 old_key,
                             u64 new_key, enum pr_type type, bool abort)
    {
        struct dm_pr pr = {
            .new_key    = new_key,
            .old_key    = old_key,
            .type       = type,
            .fail_early = false,          /* <-- .abort is NEVER set */
        };
        ret = dm_call_pr(bdev, __dm_pr_preempt, &pr);

`struct dm_pr` HAS a `bool abort` field (dm.c:3465). The only READ of it is
`__dm_pr_preempt()` passing `pr->abort` down (dm.c:3658). **There is no
assignment to it anywhere in dm.c** — verified by `grep -n abort dm.c`, which
returns exactly four hits: an unrelated comment, the field declaration, the
read, and the dropped parameter.

The designated initializer zero-fills it, so `abort` is always false, and
`sd_pr_preempt()` does `sd_pr_out_command(bdev, abort ? 0x05 : 0x04, ...)`
(sd.c:2207). Result: **on ANY dm device, PREEMPT AND ABORT is silently
downgraded to PREEMPT.** Every dm user is affected, not just MXFS.

MXFS's own layers are correct and are NOT where it is lost:
- `dlm/scsipr.c:466` calls `mxfs_scsipr_preempt(ctx, victim_key, true)`
- `dlm/scsipr.c:196` forwards `abort` to `mxfs_pal_scsi_pr_preempt`
- `pal/linux/kern.c:2930` forwards it to `ops->pr_preempt(..., abort)`
- `ops` is dm's, because MXFS opens `/dev/mapper/mpatha` — and dm drops it.

## Why 15 sessions of green boards never caught it

**The SCSI-PR fence has ZERO board coverage.** Measured the same session: a
full 32/caw board (fence_during_write, crash_consistency, fault_netpartition,
dlm_membership) produced **zero** fence markers on all 32 nodes — dmesg ring
verified to span the whole window, and the prints are `MXFS_LOG_WARN`, ungated.

- `fence_during_write` is a NEGATIVE test. It runs a write storm and asserts
  `ckeq "no fence/shutdown in window" 0 "$hits"`. It never kills anything.
  The ledger's plan said to use it "because it already kills the victim
  mid-write" — that is simply wrong about what the test does.
- `crash_consistency` says so itself in its header: "a true node-KILL +
  survivor foreign-log-replay needs host-side orchestration the in-guest
  run_coord harness doesn't have".

So sess93's step 3 ("fence_during_write and crash_consistency re-boarded with
the certificate live and CONSUMED — both PASS 32/32") did not exercise the
fence at all. `tests/fence_stage3_real.sh` (new, sess378) is the only thing in
the tree that does.

## Why it matters, quantified (stage ii, same session)

The A/B on the SHIPPED vdisk_fileio handler measured what the two service
actions actually do to a held victim write, all three runs VALID:

| arm | SA | margin (land - PR completion) | (B) LINEARIZATION |
|---|---|---|---|
| 1 | 0x04 | **+12.000413 s** | FAIL — landed AFTER |
| 2 | 0x05 | **-0.000126 s** | PASS — landed BEFORE |
| 3 | 0x04 | **+12.476141 s** | FAIL — landed AFTER |

0x05 blocks in `wait_for_completion(&pr_aborting_cmpl)` until the victim's
command drains (measured 12.3-12.5 s of PROUT duration), so the write is
strictly ordered before the fence completes. 0x04 returns in ~0.2 ms and the
write lands 12 s later — after the survivor has certified exclusion and may
have begun replaying the victim's slice in place.

## The fix cannot be "patch the kernel"

RULE 6: another system's defect is never permission for MXFS to keep one, and
MXFS cannot dictate the customer's kernel. MXFS already has everything needed
to bypass dm: full SCSI CDB passthrough (`scsi_execute_cmd`, both
`REQ_OP_DRV_IN` and `REQ_OP_DRV_OUT`, `pal/linux/kern.c:1085`) and a
stacked-device resolver `mxfs_bdev_to_sdev()` (kern.c:673) that already walks a
dm bdev to an underlying `scsi_device` with caching and path-death
re-resolution.

Relevant SCST fact (ruling, sess133): `scst_pr_find_registrants_list_key()`
collects ALL registrants holding the action key and `scst_pr_abort_reg` runs
per registrant — so ONE P&A of a victim's key aborts BOTH of its multipath
nexuses. A single raw issuance is therefore sufficient for the victim.
