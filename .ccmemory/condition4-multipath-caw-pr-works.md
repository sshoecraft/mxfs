---
name: condition4-multipath-caw-pr-works
description: Condition 4 (CAW over dm-multipath) BUILT + verified 2026-07-05: CAW AND PR both WORK through /dev/mapper/mpathX. Kernel handoff pointers for Fable's…
metadata:
  type: project
tags: [caw, multipath, dm-multipath, pr, scst, test-infra, condition4, verified, handoff]
---

## Condition 4 — CAW over dm-multipath: BUILT + VERIFIED (2026-07-05)

The #1 real deployment (enterprise SAN, FC or iSCSI, ≥2 paths + multipathd,
mounting /dev/mapper/mpathX). Condition 4 characterises whether CAW + PR work
through dm-multipath at the raw storage layer (SG_IO + sg_persist, NO mxfs — infra).

### RESULT — both work; earlier scare was WRONG
- **CAW through dm-multipath: PASS** cross-node, no-retry AND retry-aware. The
  earlier "CAW fails / UNIT ATTENTION 0x29" was ONE transient first-command UA +
  caw_verify not retrying. Does NOT reproduce. No CAW-multipath bug.
- **PR/fencing through dm-multipath: PASS (N=2)** — nodeA reserves WE-RO
  (sg_persist `--param-alltgpt`); nodeB SEES reservation+key thru its OWN mpath;
  nodeB non-registrant write BLOCKED. Fencing works across paths.
- **Presentation scales 32/32** — 2-path /dev/mapper/mpathX each, same LUN.
  32-node PR sub-check false-failed only from test1's degraded paths (i/o pending,
  prio=0) after session churn — fresh boot clears it. Not a scale defect.

### What was built (in tree)
- `tools/caw_verify.c` `--retry-ua` (retry sense key 0x06). NOT in `make tools` —
  compile: `cd tools && cc -Wall -Wextra -O2 -o caw_verify caw_verify.c`.
- `scripts/scst_setup.sh` PORTAL_IP = space-sep LIST; allowed_portal reset each setup.
- `scripts/verify_infra.sh multipath` mode (2nd br0 alias 192.168.120.2,
  find_multipaths yes, dual-portal login → 2-path mpatha, retry-CAW + PR-across-paths).
- Docs: `docs/condition4_multipath_scope.md` (scope+RESULTS+HANDOFF); test_infra_scst_caw.md.

### HANDOFF — mxfs KERNEL multipath work (Fable's first task). Confirmed code map:
1. **CAW UA-retry (most likely needed):** `pal/linux/kern.c :: mxfs_pal_bdev_compare_and_write`
   (~2600-2860, opcode 0x89 @2638/2753). Handles MISCOMPARE (~2844) + ILLEGAL_REQUEST
   (~612/654) but NOT UNIT ATTENTION. Add bounded UA (key 0x06) retry — mirror
   caw_verify --retry-ua. Also check read path mxfs_pal_scsi_read_fua_bdev /
   mxfs_pal_bdev_read_prio (dlm/dlm_caw.c uses ctx->dev).
2. **PR on multipath — VERIFY before changing:** mxfs kernel PR uses kernel `pr_ops`
   (`pal/linux/kern.c :: mxfs_pal_scsi_pr_register` → get_pr_ops @2345 →
   bdev->bd_disk->fops->pr_ops; dlm/scsipr.c on top). dm-multipath's pr_ops REPLICATES
   PR to all paths, so mxfs kernel PR MAY work UNCHANGED on mpath — test first. The
   ALL_TG_PT / --param-alltgpt concern is for the RAW userspace SG_IO PROUT path
   (pal/linux/user.c 0x5F), NOT necessarily the kernel pr_ops path.
3. **Device:** mount mxfs on /dev/mapper/mpathX; CAW (blk_execute_rq) + PR (pr_ops)
   ride the dm queue.
4. **Test loop:** `scripts/verify_infra.sh multipath 2` presents the 2-path dev
   (storage GREEN). Then mount mxfs on /dev/mapper/mpatha, run FS ops, watch dmesg for
   UA / reservation conflict / shutdown. N=2, single-path control first.

### gotchas
- sg_persist ALL_TG_PT = `--param-alltgpt` NOT `--all-tg-pt`.
- dm-multipath device size: `blockdev --getsz` (not /sys/block/<name>/size).
- find_multipaths yes + clean wwids: single path stays raw sda; 2-path → mpatha.

### Still deferred: real 2-network (2nd bridge+NIC) for path-FAILOVER testing.
See [[caw-scripts-all-3-conditions-proven]], [[caw-test-3-conditions-and-script-inventory]].
