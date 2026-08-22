---
name: ccloop-c7ee71c6-sess335-GPT-ruling-0.12.3-review-3-stopships
description: sess335 RULE-5 review of 0.12.3 D-513 landing: NO-GO, 3 stop-ships (barrier invalidate-before-publish must succeed; FSWIDE gate before no-DLM return;…
metadata:
  type: project
tags: [d-513, rule-5, stop-ship, mount-barrier, quarantine]
---

# sess335 — RULE-5 diff review of the sess334 0.12.3 landing: NO-GO, 3 new stop-ships

GPT reviewed the full sess334 landing (import_verdict, classify_terminal, publish_refusal, reap rewire, barrier_classify_slot, barrier flow, backfill identity check). Items A, B, 4, 5 PASS. Verdict **NO-GO for the rig** until:

## Stop-ships
1. **Barrier pre-publication invalidation failure is ignored** (item-D deviation). At the barrier replay-refusal site (~xfs_mxfs_dlm.c:47887) `mxfs_dlm_invalidate_cached_views(mp)` return is discarded before `mxfs_freplay_publish_refusal()`. A failed drop can publish + AG-admit while stale/partial prefix images stay cached. FIX: check return; on failure alert + `continue` (nothing published, slot stays in the cut, later rounds retry, admission bound fails mount -EBUSY which defers late deaths). NOT LANDED YET.
2. **FSWIDE gates bypassed by `if (!mp || !mp->m_mxfs_dlm) return 0;`** (item-6 deviation) — fail-open success path. FIX: `if (!mp) return 0;` then the quar_fswide start-gate, THEN `if (!mp->m_mxfs_dlm) return 0;`. Safe: m_mxfs_quar_lock is init'd in xfs_init_mount_workqueues (pal/linux/xfs_super.c:692, fill_super) before the barrier; abort_fswide with NULL m_mxfs_dlm is safe because drained==0 there so defer_late_deaths isn't called. No import can race while m_mxfs_dlm is NULL (imports come from the DLM monitor) — document that; one gate covers both returns. NOT LANDED YET.
3. **publish_refusal -EPERM arm retained lease on transient readback failure** (default: arm returned 0 without release → victim grants frozen with no publisher). FIX = release ONCE at top of the -EPERM arm before the leaseless readback; per-case releases removed. **LANDED sess335** (3 edits: release moved to top, removed from case 0 / -EBADMSG/-EPROTO / -ENODATA arms).

## Non-blocking cleanups GPT sketched (do while landing 1+2)
- publish_refusal success arm: use mxfs_freplay_import_verdict(mp, slot, &ocanon, "publish") instead of raw import_oc (defense vs lower-layer contract regression; invalid ocanon then fails closed FSWIDE).
- Barrier round-loop -EPERM reclassify: `if (crc == -EAGAIN) { quarblocked |= bit; continue; }` (avoid misleading generic alert); crc>0 arm also `quarblocked &= ~bit` for symmetry. crc==0 MUST still fall through to the generic wait-state alert (deliberate).
- Reap -EPERM reclassify: `if (crc < 0) { set_bit(MXFS_REAPF_FREPLAY); mxfs_reap_sched(..., "freplay-classify"); continue; }`; crc==0 falls through to freplay-fence re-arm (correct).

GPT scrutiny answers: (b) classify_terminal's unconditional release is safe+appropriate; (e) poll todo&~terminal reduction correct; (f) no terminal∩replayed path exists.

## After landing 1+2+cleanups
make clean && make modules, VERSION 0.12.3→0.12.4, ledger #90 update, re-review NOT required (GPT: "after those are fixed, the remaining points are cleanup"), then rig: prep_cluster (240s budget), 7 pre-rig unit checks (sess333 memory), Q7 plan (sess325 memory) + sess328 Q3 residue thresholds.
