---
name: physrig-fixes-v74-76-landed-and-verified
description: v0.11.74-76 LANDED+VERIFIED on phys rig: D1a late PR unregister (unmount-record loss fixed, 5-cycle proof), D2 abort-on-register-fail (injection-veri…
metadata:
  type: project
tags: [physical-rig, fix-verified, v0.11.76, scsi-pr, disklock, d7-open]
---

# Fix wave 1 on the physical rig (all verified live on pve1/pve2 + QNAP)

## v0.11.74 — D1a: deferred PR unregister (srcver 6C48989E)
- put_super: `mxfs_v5_dlm_detach_pr_key()` before v5 shutdown; `mxfs_pal_scsi_pr_unregister_bdev(mp->m_ddev_targp->bt_bdev, key)` AFTER xfs_unmountfs. New: scsipr_key/scsipr_abandon; v5_mount.h detach decl; kern.c bdev unregister (+local redecl for -Wmissing-prototypes).
- VERIFIED: repro (non-holder umount under peer WE-RO) was 3/3 log-error shutdowns → now 0/7; recovery_on_mount drained to 0 across all 4 slices ×5 cycles; PR keys cleaned.

## v0.11.75 — D2: TCP-branch abort on PR register failure (srcver 786CF06D)
- v5_mount.c TCP PR block: register failure → ERR + unwind (peer_shutdown, dlm_destroy, goto err_free). -EOPNOTSUPP (no PR device) still proceeds.
- New one-shot injection `mxfs.dbg_pr_register_fail` in kern.c pal register.
- VERIFIED: armed → mount fails w/ "aborting mount"; disarmed → normal mount; no unwind crash.

## v0.11.76 — D3+D5 (srcver DAE09A36)
- D3: `mxfs_disklock_release_slot()` (read, verify magic+own node_id, flags=0, write_sector_fua) called from v5_shutdown when !ctx->withdrawn, after stop_heartbeat. Withdraw keeps record ACTIVE (peers must detect death + recover slice).
- D5: both settle gates (TCP+CAW): if not settled after 2s, ONE liveness rescan (get_stale_slot_mask threshold=5000, early-exit) discounts frozen slots from `want` → P-MEMB-GATE-GHOSTS. All-live joins never pay it.
- VERIFIED: released record flags=0 on platter; planted ghost + 11 legacy = 12 discounted, mount 7.7s (was 15+); racy-join regression: settled 0ms, both files both ways (root-#8 intact); fresh mkfs cleared ghost region.

## D7 RE-SCOPED (open, next priority): 20s join latency
- With gate at 0ms the join STILL took 20.4s → the old "15s gate + 4.7s acquire" decomposition is WRONG. P34-ACQ-SLOW dur=20070 attempts=1 on joiner; joiner is MASTER for ino=128 (pve1's PR request later arrives at pve2); pve1 shows ZERO bast/demote in the window; P4L record alloc happens at END of wait; P11-ACQSTALE-SELFBAST stale=1 src=7 fires at grant.
- Samples: 20070ms, 19765ms, 4681ms, 4676ms — event-driven variable wait, joiner-side, pre-grant, self-mastered path.
- Next: request-ID + boottime stamps inside the inode-EX acquire wait (entry, what-it-waits-on, wakeup source, grant) per GPT plan (see physrig-qnap-PR-reconstruction-CLOSED).

## Remaining open (RULE 6): D6 40s goodbye-less umount (survivor stall, "lock request retrying" storm), D4 preempt hygiene (READ KEYS first; self-fence on own-key-missing), D8 periodic PR self-check + provisioning conformance probe (QTS purges keys on session events silently, unregister doesn't bump gen), D7 above. Suite subset + sysrq-b dead-peer finale pending. Rig: v0.11.76 loaded both nodes, fresh mkfs, r1_seed/r1_join present.
