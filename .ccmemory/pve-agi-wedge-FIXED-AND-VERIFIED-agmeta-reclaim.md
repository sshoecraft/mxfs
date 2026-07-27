---
name: pve-agi-wedge-FIXED-AND-VERIFIED-agmeta-reclaim
description: AGI umount-wedge FIXED AND VERIFIED (RULE 6): AG-meta track-hold reclaim on shutdown-abort; deterministic fault-injection (mxfs.dbg_dialloc_shutdown)…
metadata:
  type: project
---

# AGI umount-wedge: FIXED AND VERIFIED (RULE 6)

Resolves the OPEN item in [[pve-agi-wedge-ROOT-agmeta-track-hold-leak-FIX-and-pve1-hung]]
and the original [[pve-agi-buf-hold-leak-umount-wedge-not-sess76-readahead]]. 2026-07-21,
PVE rig (pve1=192.168.1.80 / pve2=192.168.1.81, kernel 6.17.2-1-pve). Build `23B0BC…`.

## Disposition: FIXED AND VERIFIED (release-832 / shutdown-abort path)

Root cause (already PROVEN via the hold-ring): `mxfs_ag_meta_track` takes an
`xfs_buf_hold` on every logged AG-meta buffer, released ONLY by
`mxfs_dlm_ag_meta_iodone` (b_iodone, fires only on WRITE completion in
`__xfs_buf_ioend`). A forced shutdown aborts the dirty AG-meta buffers WITHOUT
writeback (`xfs_buf_item_release`'s `(aborted||xlog_is_shutdown)` branch →
`xfs_buf_item_done`, no ioend) → iodone never fires → hold + `pag_dlm_meta_pending`
leak → `xfs_buftarg_drain` (LRU_SKIP for hold>1) spins → D-state umount.

Fix = one-shot `atomic_t b_mxfs_agmeta_hold` armed by track (CHECKED cmpxchg 0→1 +
WARN + rollback), consumed by exactly one of iodone (writeback) or the new
`mxfs_ag_meta_reclaim_abort(bp)` — called from `xfs_buf_item_release`'s abort branch.
Logs **P-AGMETA-RECLAIM**. Files: `xfs/xfs_buf.h`, `xfs/xfs_mxfs_dlm.{c,h}`,
`pal/linux/xfs_buf_item.c`. Self-review: iodone is installed at exactly one site (in
track), b_iodone is WRITE-branch only → the token-guard is a no-op in normal op.

## Verification (the causal A/B GPT required)

**Deterministic trigger** = new gated one-shot fault injection `mxfs.dbg_dialloc_shutdown`
(xfs_inode.c, in xfs_create right after xfs_dialloc has logged+tracked AGI/inobt/finobt):
arm=1 → next multi-node create forces a DIRTY `xfs_trans_cancel` — reproducing the exact
natural signature (`P-CR3-CANCEL error=-117 trans_dirty=1` → `xfs_trans.c:1069 Shutting
down`). Harness: `scripts/agi_wedge_verify_inject.sh` (arm → touch → assert umount
completes + P-AGMETA-RECLAIM>0 + zero P-DRAINSTUCK/P-HOLDRING).

Result — **5/5 clean instances** (1 natural churn-triggered + 4 deterministic; pve1 AND
pve2): every one reclaimed EXACTLY 3 buffers — **xfs_agi + xfs_inobt + xfs_finobt** (the
same three metadata types the OLD build wedged on, P-HOLDRING daddr 2/24/32) — umount
completed in ~2s, `P-DRAINSTUCK=0`, `P-HOLDRING=0`, module released `rc=0`. Old build
under the same leak condition wedged; fix build reclaims the 3 holds and unmounts clean.
Dossier: `tests/logs/pve1_agi_FIX_verified_20260721_113033Z/`.

Bonus: the fix makes a shut-down node's umount CLEAN, so `prep_cluster` teardown no longer
stalls on a withdrawn node (earlier "did not release mxfs" prep failures are gone).

## STILL OPEN (do NOT treat this as project-done)

1. **Phase-B completeness** (GPT review): the STALE detach branches
   (`xfs_buf_item_release`:~820 and `xfs_buf_item_unpin`:~528 → `finish_stale`) are also
   terminal no-iodone paths. A tracked AG-meta btree block that gets `xfs_trans_binval`'d
   (e.g. `xfs_alloc.c:1401` on a freed free-space/AGFL block) could leak there. NOT yet
   hooked. Needs a reason-aware completion helper: IO_DONE / STALE_DONE (do the deferred
   AG-unlock decision — stale can happen during NORMAL operation, so must NOT skip unlock)
   / SHUTDOWN_ABORT (skip unlock; force_release_all owns it). Also: replace `atomic_set(1)`
   done; add per-mount accounting counters (acquire/iodone_claim/stale_claim/shutdown_claim/
   miss/dup, assert `acquire==sum(claims)` + `outstanding==0` + `sum(pending)==0` at clean
   unmount); wrap the MXFS direct `xfs_buf_item_done(dbp)` drain calls (all dir buffers today
   = no token, so a no-op, but wrap for future-proofing). GPT full plan in the consult.
2. **Cross-node stale-inode dialloc corruption** (the natural shutdown TRIGGER itself:
   "Corruption detected! Free inode not marked free", err=-117, incore-struct-stale; also
   seen at `mxfs_dlm_ilock_begin` xfs_mxfs_dlm.c:22694) — a SEPARATE real coherency defect.
   The AGI fix does NOT address it (fix is a no-op in normal op). Still OPEN.
3. **pve2 flush_workqueue umount wedge** — separate cross-node teardown wedge
   (`xfs_fs_put_super → __flush_workqueue`, DLM work `P73-WAITSTALL` stalled on a shut-down
   peer). Did NOT recur in the 3 verify cycles but not proven fixed. Dossier
   `tests/logs/pve_messystate_*/`. Still OPEN.

## Ops notes
- pve1 = HP Z400 workstation (Xeon W3520), NO iLO/IPMI. `sysrq-b` HUNG it once (needed a
  manual reset). Recover a SHUT-DOWN (not D-state-wedged) node with the umount+rmmod+reload
  the fix now enables — do NOT sysrq-b.
- Injection is one-shot + default 0 (module reload resets it); harmless when disarmed.
- New harnesses (RULE 3): `scripts/agi_wedge_verify_inject.sh` (deterministic, preferred),
  `agi_wedge_repro.sh` / `agi_wedge_verify.sh` (natural churn), `agi_wedge_verify_det.sh`
  (GOINGDOWN — DEAD, mxfs doesn't dispatch XFS_IOC_GOINGDOWN). Nothing committed.
