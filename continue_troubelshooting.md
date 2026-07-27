# Session State — MXFS

**Saved**: 2026-07-21, interactive session (Proxmox 2/tcp — AGI umount-wedge)
**Session Goal**: Fix the AGI-buffer umount wedge to FIXED-AND-VERIFIED (RULE 6).
**DONE.** Next chosen target (user pick): the cross-node **stale-inode dialloc
corruption** (the separate defect that TRIGGERS the shutdown).

> state.md = FRESH per-handoff snapshot ONLY — history → CHANGELOG.md, not here
> (ccmemory `convention-statemd-fresh-history-in-changelog`).

---

## What was accomplished — AGI umount-wedge FIXED AND VERIFIED

Root cause PROVEN, fix implemented + verified with a deterministic causal A/B.
Full detail in ccmemory `pve-agi-wedge-FIXED-AND-VERIFIED-agmeta-reclaim` (and the
earlier `...-ROOT-agmeta-track-hold-leak-FIX-and-pve1-hung`). Summary:

- **Root cause**: `mxfs_ag_meta_track` (xfs/xfs_mxfs_dlm.c) takes an extra
  `xfs_buf_hold` on every logged AG-meta buffer; its ONLY releaser is
  `mxfs_dlm_ag_meta_iodone` (installed as `bp->b_iodone`, invoked at exactly one
  site — `__xfs_buf_ioend`, WRITE branch only). A forced shutdown aborts the dirty
  AG-meta buffers WITHOUT writeback (`xfs_buf_item_release`'s `(aborted ||
  xlog_is_shutdown)` branch → `xfs_buf_item_done`, no ioend) → iodone never fires
  → hold + `pag_dlm_meta_pending` leak → `xfs_buftarg_drain` spins (LRU_SKIP for
  b_hold>1) → D-state umount. Proven via a NEW per-buffer hold-ring (dumped
  P-HOLDRING showing 3 stuck buffers: xfs_agi, xfs_inobt, xfs_finobt).
- **Fix (one-shot token)**: `atomic_t b_mxfs_agmeta_hold` (xfs/xfs_buf.h) armed by
  track (CHECKED `cmpxchg(0,1)` + WARN + rollback), consumed by exactly one of
  iodone (writeback) or the new `mxfs_ag_meta_reclaim_abort(bp)` — called from
  `pal/linux/xfs_buf_item.c`'s abort branch. Logs **P-AGMETA-RECLAIM**.
- **Verified**: 5/5 clean instances (1 natural + 4 deterministic, pve1 AND pve2):
  reclaim fires exactly 3× (agi/inobt/finobt), umount completes ~2s,
  P-DRAINSTUCK=0, P-HOLDRING=0, module rc→0. Old build wedged on the same 3
  buffers. Dossier `tests/logs/pve1_agi_FIX_verified_20260721_113033Z/`.
- **Files changed**: `xfs/xfs_buf.h`, `xfs/xfs_mxfs_dlm.{c,h}`,
  `pal/linux/xfs_buf.c` (hold-ring + drain `agmeta_hold=` field),
  `pal/linux/xfs_buf_item.c` (reclaim at abort branch), `xfs/xfs_inode.c` (debug
  injection). Awareness docs `pal.md` + `xfs.md` updated.

Also this session: had to `make tools` (mkfs_mxfs/chk_mxfs/etc were unbuilt →
prep failed with "mkfs tool not found"). New harnesses in `scripts/` (RULE 3).

## Current state of the code

- **Builds clean.** Both nodes on DKMS **23B0BC005A6A94612A4BFFF** (installed +
  loaded). pve1 mounted (rc=1), pve2 unmounted (rc=0) — half-state after the last
  verify cycle. Re-prep to get a clean 2-node cluster (see invocation below).
- **NOTHING COMMITTED** — this session's AGI fix + instrumentation + harnesses, AND
  the prior Proxmox-port session. Large uncommitted tree. User has NOT directed a
  commit yet. Clean stray build artifacts before committing (`*.deb`, tool binaries
  are fine to keep, `pal/linux/.*.o.d`, `tests/net2/net2_harness`).
- Debug injection `mxfs.dbg_dialloc_shutdown` is one-shot + **default 0** (disarmed
  on both nodes; module reload resets it). Harmless when 0.

## Next target — cross-node stale-inode dialloc corruption (user-chosen)

This is the SEPARATE defect that TRIGGERS the forced shutdown (the AGI wedge was
its downstream consequence). It is a real data-coherency bug, still OPEN.

- **Symptom**: under concurrent 2-node create/mkdir/rm in a shared dir, a create's
  `xfs_dialloc` finds an inode the free-inode btree says is free but whose in-core
  inode-cluster image still shows ALLOCATED → `Corruption detected! Free inode 0xNNN
  not marked free! (mode 0x...)` → `err=-117` (-EFSCORRUPTED) → **dirty**
  `xfs_trans_cancel` (xfs/xfs_trans.c:1068/1069) → shutdown. Caller
  `xfs_create.cold`. A variant fires at `mxfs_dlm_ilock_begin` (xfs_mxfs_dlm.c:22694).
- **Existing diagnostics** (already in-tree, look for these in dmesg):
  `P-CR62 ... verdict=DISK-FREE=>incore-struct-stale` (disk_di_mode=00, incore
  MISS/stale), `P-CR3-CANCEL error=-117 trans_dirty=1`, `P7-INSTR`/`P9-INSTR`
  corruption-buf/corruption-disk (shows `dlm_stale=1`), `P-DIALLOC`.
- **Leading hypothesis (NOT yet RULE-4 proven)**: peer freed the inode; this node
  holds a STALE cached inode-cluster buffer (dlm_stale=1) showing the inode
  allocated. dialloc reads the stale cluster → sees a "free" inode still marked
  used → EFSCORRUPTED. Same family as ccmemory `compiled-agi-unlinked-list-
  corruption`, `sess123-tenure-id-*`, `compiled-ccloop-cache-coherency-visibility`.
  The inode-cluster read-side coherency (invalidate-on-acquire / tenure_id) is the
  place to look — a stale inode-cluster buffer must be re-read on acquire.
- **Repro**: `scripts/agi_wedge_repro.sh 180 24` (heavy 2-node shared-dir churn) —
  PROBABILISTIC (narrow race; fired at ~45s on old builds, but ~960s produced 0 on
  the fix build in one run — it's timing-sensitive, NOT suppressed by the AGI fix
  which is a no-op in normal op). Start by RULE-4 instrumenting the stale-cluster
  read path, not by guessing. `mxfs.dbg_ialloc_dblcheck=1` (default 0) adds a
  same-chunk double-alloc check at the alloc site — may help diagnose.
- **CAUTION — the injection param does NOT reproduce this bug.**
  `mxfs.dbg_dialloc_shutdown` synthetically injects `err=-117` at the dialloc site
  to exercise the umount reclaim; it does NOT create the real stale-cluster
  condition. For the corruption you need the natural race (or build a deterministic
  repro of the STALE inode-cluster state).

## Other OPEN items (RULE 6 — not dropped)

1. **AGI fix Phase-B completeness** (GPT-reviewed, deferred): the STALE detach
   branches (`xfs_buf_item_release` stale-branch + `xfs_buf_item_unpin` stale-branch
   → `finish_stale`) are also terminal no-iodone paths; a tracked AG-meta btree
   block that gets `xfs_trans_binval`'d (e.g. `xfs/libxfs/xfs_alloc.c:1401`) could
   leak there. NOT hooked (unproven/narrow). GPT's plan: a reason-aware completion
   helper `mxfs_ag_meta_complete(bp, why)` with IO_DONE / STALE_DONE (do the
   deferred-AG-unlock decision — stale happens in NORMAL op, must NOT skip unlock) /
   SHUTDOWN_ABORT (skip unlock; force_release_all owns it); hook the stale branches;
   per-mount accounting counters (assert acquire==sum(claims), outstanding==0,
   sum(pending)==0 at clean unmount); wrap the MXFS direct `xfs_buf_item_done(dbp)`
   drain calls (all dir buffers today = no token = no-op, wrap for future-proofing).
2. **pve2 flush_workqueue umount wedge** — SEPARATE cross-node teardown wedge
   (`xfs_fs_put_super → __flush_workqueue`; DLM work `P73-WAITSTALL` stalled on a
   shut-down peer). Did NOT recur in the AGI verify cycles but not proven fixed.
   Dossier `tests/logs/pve_messystate_*/`.
3. **dir_reuse create-visibility race** (original handoff bug #2, UNTOUCHED this
   session) — P-IGET-ENOENT dead-shell: reader iget-hits a stale reclaimable mode-0
   reused inode and ENOENTs. Rare, timing-sensitive; needs a deterministic repro.
   Dossier ccmemory `pve-timestamp-update-ex-iflush-breaks-create-visibility`.

## Next steps (priority order)

1. **Stale-inode dialloc corruption (user pick).** RULE 4: instrument the inode-
   cluster read/acquire path to PROVE the stale-cluster hypothesis (who wrote the
   stale image, was it re-read on acquire, what's the tenure_id/dlm_stale state at
   the failing dialloc). Reproduce via `scripts/agi_wedge_repro.sh` (be patient —
   probabilistic). Then fix the read-side invalidate-on-acquire. Consult GPT (RULE
   5) if the loop stalls. Do NOT use the injection param as the repro (see caution).
2. AGI Phase-B completeness (STALE-branch reclaim) — low-risk, GPT plan above.
3. pve2 flush_workqueue teardown wedge; dir_reuse race.
4. Commit when the user directs (includes the prior Proxmox port).

## Important context / gotchas

- **Nodes**: pve1=192.168.1.80 (HP Z400, Xeon W3520, **NO iLO/IPMI**),
  pve2=192.168.1.81. Login root, password from the lab secrets store. Passfile
  `/tmp/.proxmox_pass` (ephemeral — recreate with
  `tools/mxfs_secrets.sh passfile /tmp/.proxmox_pass`).
  Kernel 6.17.2-1-pve. clyde (dev host) = 192.168.1.166; QNAP NFS/iSCSI = .4.
- **SHARED LUN IS ALWAYS `/dev/sdb`** (`/dev/sda` = pve boot disk). QNAP iSCSI has
  no real SCSI CAW → force TCP (`/etc/modprobe.d/mxfs.conf` = `options mxfs
  force_transport=1` on both, already set).
- **⚠️ DO NOT `sysrq-b` pve1** — it HUNG it hard once (~10 min, needed a manual
  physical reset; no OOB). Recover a SHUT-DOWN (EIO, not D-state-wedged) node with
  `umount /mnt/shared` (the AGI fix makes it complete) + `rmmod mxfs` + reload — the
  fix eliminated the umount wedge, so reboots are rarely needed now. Only a genuine
  D-state wedge needs a reboot; if pve1 needs one, ASK the user.
- **Invocation**: `MXFS_CRIT=/src/mxfs/criteria.pve.json
  MXFS_NODE_LIST="192.168.1.80,192.168.1.81" MXFS_DEV=/dev/sdb
  MXFS_PASS=/tmp/.proxmox_pass ./run.sh 2 tcp [tests...]`. Force-prep:
  prepend `MXFS_FORCE_PREP=1`, arg `prep_cluster`.
- **Fast rebuild both nodes** (parallel): `tools/mxfs_sshpass.sh <node>
  /tmp/.proxmox_pass "bash /src/mxfs/scripts/pve_dkms_rebuild.sh"`. Purges+builds+
  installs DKMS (~1.5 min/node). Header changes → full clean rebuild automatically.
- **AGI-wedge harnesses** (RULE 3, `scripts/`): `agi_wedge_verify_inject.sh`
  (DETERMINISTIC, preferred — arms `mxfs.dbg_dialloc_shutdown`, one create, asserts
  clean umount + P-AGMETA-RECLAIM>0); `agi_wedge_repro.sh` (natural 2-node churn,
  monitors both nodes, exit 42 on escalation); `agi_wedge_verify.sh` (natural churn
  → umount-verify). `agi_wedge_verify_det.sh` is DEAD (xfs_io GOINGDOWN — mxfs does
  NOT dispatch XFS_IOC_GOINGDOWN, FSGEOMETRY ENOTTYs).
- **`make tools`** if any `tools/*` binary is missing (mkfs_mxfs etc.) — prep needs
  them and they were unbuilt at session start.
- GPT consults preserved (RULE 5 — keep consulting when a RULE-4 loop stalls). The
  AGI fix + verification design came from a GPT consult; its full Phase-B plan is in
  the FIXED-AND-VERIFIED ccmemory dossier.
- Reference kernel tree at `/src/linux` (RULE 1: never download; read from there).
