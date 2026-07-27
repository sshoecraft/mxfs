---
name: pve-agi-wedge-ROOT-agmeta-track-hold-leak-FIX-and-pve1-hung
description: AGI umount-wedge ROOT CAUSE PROVEN = mxfs_ag_meta_track hold leaked on shutdown-abort (no writeback -> iodone never fires); one-shot-token FIX built…
metadata:
  type: project
---

# AGI umount-wedge: ROOT CAUSE PROVEN + FIX built; verification blocked by pve1 hang

Continues [[pve-agi-buf-hold-leak-umount-wedge-not-sess76-readahead]]. 2026-07-21, PVE rig
(pve1=192.168.1.80 / pve2=192.168.1.81, kernel 6.17.2-1-pve).

## ROOT CAUSE — PROVEN (RULE 4, via reason-tagged hold-ring)

Added a per-buffer HOLD/RELE ring (`MXFS_HOLD_TRACE` in `xfs/xfs_buf.h`; recorder
`mxfs_hold_ev()` + `b_mxfs_hold_ring[32]` in `pal/linux/xfs_buf.c`, dumped as **P-HOLDRING**
at the P-DRAINSTUCK drain-stuck site). Reproduced the wedge and dumped it. **3 AG-meta
buffers stuck at hold=2**: `xfs_agi daddr=2`, `xfs_inobt daddr=24`, `xfs_finobt daddr=32`
(AG0) — exactly the buffers `xfs_create -> xfs_dialloc` touches.

Ring + state (`pin=0 has_bli=0 delwri=0`) **eliminated** leaked pin / bli / delwri. The
one recurring MXFS hold with no matching release was **`mxfs_ag_meta_track+0xb2`** (+1),
whose only releaser is **`mxfs_dlm_ag_meta_iodone`** (drops the extra hold + decrements
`pag_dlm_meta_pending`) — and iodone runs **only on writeback completion** (`b_iodone` is
invoked at exactly one site, `pal/linux/xfs_buf.c:2507`, inside `__xfs_buf_ioend`).

**The leak:** on a forced shutdown the dirty AG-meta buffers logged by the in-flight
dialloc tx are aborted **without writeback** — `xfs_buf_item_release`'s
`(aborted || xlog_is_shutdown)` branch (`pal/linux/xfs_buf_item.c:832`) detaches the bli
via `xfs_buf_item_done`, which never runs ioend, so `b_iodone` (iodone) never fires. The
`xfs_buf_hold` + `pag_dlm_meta_pending++` that `mxfs_ag_meta_track` took leak forever →
buffer pinned at hold=2 → `xfs_buftarg_drain` (LRU_SKIP for hold>1) spins → D-state umount.
`XFS_BLI_MXFS_AGMETA_TRACKED` is only ever SET (never cleared); pending is only dec'd in
iodone — so there was NO non-writeback release path. GPT's a-priori "xfs_trans_bhold"
guess was close-but-wrong; the instrument pinned the real culprit (`mxfs_ag_meta_track`).

## FIX (one-shot ownership token — GPT's "consumed once by completion-OR-abort")

- `struct xfs_buf`: new `atomic_t b_mxfs_agmeta_hold` (0 at zalloc).
- `mxfs_ag_meta_track`: `atomic_set(&bp->b_mxfs_agmeta_hold,1)` when taking the hold.
- `mxfs_dlm_ag_meta_iodone`: `if (atomic_cmpxchg(&bp->b_mxfs_agmeta_hold,1,0)!=1) return;`
  at top — only drop hold/pending if it owns the token (also fixes latent spurious-iodone
  underflow/double-rele).
- new `mxfs_ag_meta_reclaim_abort(bp)`: cmpxchg-consume the token, dec pending, `xfs_buf_rele`
  (no deferred DLM unlock — shutdown path; force_release_all does the final release). Logs
  **P-AGMETA-RECLAIM** when it fires.
- called from `xfs_buf_item_release`'s abort branch (`xfs_buf_item.c:832`, the PROVEN leak
  path). (Stale branches 820/528 NOT hooked yet — unproven, deferred per RULE 4.)

Files: `xfs/xfs_buf.h`, `xfs/xfs_mxfs_dlm.{c,h}`, `pal/linux/xfs_buf_item.c`.
Builds clean on 6.17.2. srcversions: `DE00DC…`=fix, `D1DA64…`=fix+P-AGMETA-RECLAIM log.

## REPRO (new harnesses, RULE 3, in scripts/)

`scripts/agi_wedge_repro.sh` — heavy 2-node shared-dir mkdir/create/rm churn. Triggers a
cross-node **stale-inode dialloc corruption** (`P-CR62 … verdict=DISK-FREE=>incore-struct-stale`,
`Corruption detected! Free inode … not marked free`, err=-117) → **dirty** `xfs_trans_cancel`
line 1068 (`xfs_create.cold`) → shutdown. fence_during_write alone = 0/10 (too weak).
`scripts/agi_wedge_verify.sh` (natural) + `scripts/agi_wedge_verify_det.sh` (deterministic:
`xfs_io -x -c 'shutdown -f'` mid-churn — GOINGDOWN NOLOGFLUSH). Had to `make tools` first
(mkfs_mxfs etc. were unbuilt).

## VERIFICATION STATUS — encouraging but NOT definitive; BLOCKED

- OLD build (A6C515, no fix): corruption-shutdown → umount **WEDGED**, P-HOLDRING showed the
  3 leaked AG-meta holds. (the A side)
- FIX build (D1DA64): ONE natural corruption-shutdown on pve1 → umount **COMPLETED in ~2s,
  0 P-DRAINSTUCK/P-HOLDRING**. BUT `P-AGMETA-RECLAIM=0` that instance → that shutdown's abort
  didn't traverse the release-832 path (path/timing-dependent), so it did NOT conclusively
  exercise the leak. **Need the deterministic A/B (many GOINGDOWN-mid-churn cycles, expect
  P-AGMETA-RECLAIM>0 + clean umount every time).**

## BLOCKER (the reason this is a handoff, not a closure)

**pve1 hung after `sysrq-b` and will not come back (~10 min, no ping/ssh).** pve1 is an
**HP Z400 workstation (Xeon W3520) with NO iLO/IPMI** — no remote power control exists.
It needs a **MANUAL physical reset** (user's call). pve2 rebooted fine (~30s).
Lesson: pve1 was only *shut-down* (cleanly umounted), NOT wedged — it did NOT need a reboot;
rebooting it "for a clean baseline" is what hung it. Next time, recover a shut-down (not
D-state-wedged) node with rmmod+reload, not sysrq-b.

## ALSO SURFACED (open, RULE 6 — do not drop)

1. **pve2 flush_workqueue umount wedge** — DISTINCT from the AGI drain wedge. Stack:
   `xfs_fs_put_super -> __flush_workqueue` (D-state), with `P73-WAITSTALL … work_busy=2
   relflush=1` (a DLM inode work item stalled waiting on the shut-down peer). Happened when
   prep umounted pve2 while pve1 was mid-shutdown. Dossier: `tests/logs/pve_messystate_*/`.
   Likely a cross-node teardown-ordering wedge; needs its own RULE-4 pass.
2. **cross-node stale-inode dialloc corruption** (the shutdown trigger itself) is a real
   coherency defect. Hypothesis: the fix's iodone token-guard may *also* reduce it (stops
   spurious `pag_dlm_meta_pending` underflow → premature deferred `ag_unlock` → peer FUA-reads
   stale inobt/AGI). Unconfirmed — the fix build triggered it MUCH less (0 in 5 amp runs vs
   1st-run on the old build). Verify separately.

## NEXT STEPS

1. User manually resets pve1. Then: clean prep 2/tcp on D1DA64 (both nodes).
2. Run `scripts/agi_wedge_verify_det.sh` several cycles (alternate TARGET pve1/pve2, reprep
   between) → confirm umount completes + P-AGMETA-RECLAIM>0 every shutdown. THAT is the
   FIXED-AND-VERIFIED bar (RULE 6).
3. Then tackle the pve2 flush_workqueue wedge and the stale-inode corruption (both OPEN).
4. Nothing committed. Instrumentation (hold-ring, P-AGMETA-RECLAIM) is permanent + toggleable.
