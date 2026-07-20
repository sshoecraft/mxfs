---
name: pr-ua-register-fence-out-rootcause
description: PROVEN: PROUT REGISTER eats pending UA (from prep_fs stale-PR CLEAR) → CHECK CONDITION rc=2 → mxfs drops PR → node unregistered under WE-RO → all wri…
metadata:
  type: project
---

# PR UA-consumed REGISTER fences a node out of the whole suite (4/caw, 2026-07-05)

## Symptom
`./run.sh 4 caw` (mpath): cluster converges 4/4, then EVERY test fails.
precond_readiness "write/read back got=" empty; cache_coherency 0/4 — all
writes on ONE node (test1) return EIO. Kernel log on that node: hundreds of
`reservation conflict` (sd + dm-1), `disklock: heartbeat write failed: -52`
(EBADE). `sg_persist -in -k` shows 3 nodes' keys ×2 paths (6) — the failing
node's key ABSENT; reservation holder = another node (WE-RO).

## Proven chain (RULE 4)
1. prep_fs.sh stale-PR clear: `register-ignore 0x5eed` (via /dev/mapper →
   dm pr_ops registers BOTH of node1's nexuses) then `clear` → per SPC-4,
   CLEAR pends UA **"Reservations preempted"** on every OTHER registered
   I_T nexus — including node1's other path. Self-inflicted EVERY run.
2. mount → `mxfs_scsipr_register` → dm pr_register iterates both paths →
   the PROUT on the UA-pending nexus CONSUMES the UA and fails CHECK
   CONDITION (positive SAM status **2** — seen as `mxfs: SCSI PR not
   available (2)` in v5_mount).
3. Old code: register failure ⇒ warn + destroy scsipr ⇒ node continues
   UNREGISTERED and never reserves; a peer then wins WE-RO.
4. Every write from the unregistered node → reservation conflict → EBADE
   (-52 heartbeats) / EIO (page cache) with the FS still mounted = a
   zombie member that poisons the entire suite.
Flaky because mkfs I/O usually consumes the UA first (path-selector
dependent). Also explains session-1 "2+2 split-brain" run most likely
(fenced nodes can't lease/heartbeat).

## Fix (v0.6.1, build 4616E73C+)
- `pal/linux/kern.c`: bounded retry (5×, 2<<n ms) on
  SAM_STAT_CHECK_CONDITION in pr_register / pr_reserve / pr_preempt /
  pr_unregister / pr_read_keys (UA is consumed by the failed command, so
  first retry is deterministic). Preempt retry is fencing-critical (an
  aborted preempt leaves a dead node unfenced).
- `dlm/v5_mount.c` CAW path: register FAILURE now aborts the mount
  ("refusing to join unfenced") — visible at mount time instead of
  unattributable EIO. -EOPNOTSUPP (no PR support) keeps best-effort.

## Related ops facts
- rc=2 from pr ops = SAM_STAT_CHECK_CONDITION (positive SCSI status
  passes through sd/dm pr_ops); 0x18/24 = RESERVATION CONFLICT status.
- P-EVICT-AUTOMON log line = "auto-MONITOR started" (sess82 self-heal),
  NOT an eviction — don't misread it during fence forensics.
- A PR-fenced mxfs mount unmounts SLOWLY (quiesce EIO) — run.sh step-1's
  umount+rmmod retry can time out ⇒ next run's mkfs "device is busy".
  Nodes were clean ~30s later; re-attempt before recycling VMs.
- Wedged rmmod after a killed run = the srcversion prep gate catches the
  stale module ("build=OLD!=NEW") — recycle VMs, don't debug phantom
  split-brains from mixed builds. [[caw-multipath-matrix-progress]]
