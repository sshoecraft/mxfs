---
name: sess378-fence-preempt-abort-FIXED-VERIFIED-0.14.12
description: sess378: dm's dropped-abort bug FIXED in 0.14.12 (raw PROUT 0x05 + fail-closed) and VERIFIED on the wire — target logged 'Preempt and abort', 0 plain…
metadata:
  type: project
tags: [D-PR-FENCE-PREEMPT-WITHOUT-ABORT, fencing, scsipr, sess378, 0.14.12]
---

# The fix, and the A/B that proves it

Companion to `sess378-dm-pr-preempt-drops-abort-upstream-kernel-bug` (the root
cause). Build **0.14.12**, srcversion **BC7EF240AD75534328B5504**.

## What changed — `pal/linux/kern.c`

`mxfs_pal_scsi_pr_preempt()` now SPLITS on the `abort` flag:

- **abort == true** never touches `ops->pr_preempt` again. It resolves an
  underlying `scsi_device` with the existing `mxfs_bdev_to_sdev()` and issues
  PERSISTENT RESERVE OUT / PREEMPT AND ABORT as a raw CDB through
  `scsi_execute_cmd(REQ_OP_DRV_OUT)` (new `mxfs_pal_prout_preempt_abort()`).
  The CDB and 24-byte parameter list are byte-for-byte what
  `sd_pr_out_command()` builds — opcode 0x5F, `cdb[1]=0x05`,
  `cdb[2]=SCSI_PR_WRITE_EXCLUSIVE_REG_ONLY` (scope 0 | type 5), our key at
  `data[0..7]`, the victim's at `data[8..15]` — so the ONLY difference from
  the in-tree path is that the service action survives.
- **No sdev resolvable** (all dm paths down, non-SCSI transport) → returns
  `-EOPNOTSUPP` and logs `P302-PROUT-NO-SDEV`. It deliberately does NOT fall
  back to `ops->pr_preempt`: that would issue the non-aborting 0x04 and hand
  the caller a success it would mint into a PREEMPT_ABORT_DONE certificate.
  `-EOPNOTSUPP` maps to `MXFS_FENCE_KIND_UNSUPPORTED`, which
  `mxfs_fence_kind_proves_exclusion()` rejects, so the slice stays blocked
  rather than being replayed under a false proof. FAIL CLOSED.
- **abort == false** keeps the generic path — plain PREEMPT is the only thing
  dm can express, so it is correct for that case.
- 60 s command timeout (a conforming target does not complete 0x05 until the
  victim's affected commands have drained; SCST blocks in
  `wait_for_completion(&pr_aborting_cmpl)`, measured 12.3-12.5 s under load).
  Bounded UA reissue, `P302-PROUT-UA-RETRY`.

NOTE for the next session: the P302 markers are FAILURE-ONLY. A successful
0x05 prints nothing, so `grep -c P302` == 0 does NOT mean the path did not run.
If you need positive confirmation, use the target-side capture below.

## Verification — same test, same rig, only the build differs

`tests/fence_stage3_real.sh` (new; see the root-cause memory for why
fence_during_write cannot do this). Hard-kills a node, waits for a survivor to
fence, and reads the service action off the TARGET.

| build | target-side line | 0x05 lines | 0x04 lines |
|---|---|---|---|
| 0.14.11 (before) | `scst_pr_do_preempt:2097:Preempt: initiator ...test29...` | **0** | **1** |
| 0.14.12 (after)  | `scst_pr_do_preempt:2097:Preempt and abort: initiator ...test15...` | **1** | **0** |

An exact inversion. The " and abort" substring is produced ONLY by
`scst_pr_preempt_and_abort()` -> `scst_pr_do_preempt(abort=true)`, so this is
on-wire proof of what MXFS's own kernel emitted, with no sg_persist in the path.

MXFS's own side on 0.14.12, now honest rather than merely optimistic:

    P236-FENCEKIND node=2967304681 kind=PREEMPT_ABORT_DONE(16) proves_excl=1 rc=0
    P236-FENCE-CERTIFIED slot=27 ... kind=PREEMPT_ABORT_DONE resv=0x05 pr_gen=13380

## (C3) replay-gate ordering — code-path proof

The ruling permits a code-path proof instead of tracepoints.
`dlm/v5_mount.c:1328-1355`: `mxfs_fence_kind_proves_exclusion(fres.kind)` gates
the call to `mxfs_disklock_recovery_fence_certify()`, and ONLY `rc == 0` (the
certificate is durable) runs `v5_blocked_clear()` and returns 0. Every other
path leaves the slice BLOCKED (`MXFS_RBLK_CERT_UNRECORDED`) and returns
non-zero. `proves_exclusion()` is true only for `PREEMPT_ABORT_DONE` and
`SINGLE_NODE_EXCLUSIVE`. So replay cannot be authorised without a durable
certificate, and after this fix that certificate can only be minted on a
genuine 0x05.

## Beware: cross-node event ordering

`dmesg -T` and `btime + uptime` were measured ~5 s apart between two nodes and
led me to the WRONG causal conclusion once. MXFS prints `realns=` (CLOCK_REALTIME
nanoseconds) on many lines; take a `uptime <-> realns` pair per node, derive
that node's boot_ns, and convert. That resolved a fence-vs-EIO ordering to
472 ms (EIO first) that btime arithmetic had inverted.
