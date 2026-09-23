<!-- sess425 RULE-5 ruling (D-0342): partial ledger purge = HELD failure at recovery-complete; keep blockers until a COMPLETE pass returns 0; purge tombst… -->
# sess425 RULE-5 ruling — partial ledger purge ignored (D-TCP-RECOVERY-COMPLETE-IGNORES-PARTIAL-LEDGER-PURGE-0342)

Hole: all 6 mxfs_dlm_ledger_purge_owner callers (v5_mount.c:970 goodbye, :2825 fenced-slotless, :3840
handle_node_death, :3904 recovered_cb, :3937 clean_depart, :5620 recovery_complete2; dlm.c:1389 lazy)
ignore rc; they drop imported blockers (mxfs_dlm_purge_node) and, at 5620, republish the slot EMPTY over
retained bits (rig: test20 P-TAUTH-PURGE-PARTIAL rc=-5 x2 during 0.34.0 formation, completion continued).

## Ruling
(a) Recovery-complete: non-zero purge = HELD failure like the hb-purge failure at the same site (ladder
retries). lease_unregister/note_dead before the purge are fine if idempotent and they do not make the
slot allocatable or drop the victim tombstone. Successful purge must be durably committed BEFORE dropping
blockers or publishing EMPTY. Key the held state by the old occupant {node,inc/epoch}, not slot number.
(b) Purge vs takeover: attempt purge before handoff but never depend on it. -ESTALE on a page = the
successor inherits the purge obligation; the successor must apply the death/purge tombstone ON IMPORT
before the page is grantable; the tombstone must survive the view change and not vanish because the
membership callback already ran. -ESTALE stops the walk, so it is NOT whole-operation success: later
pages may still be ours — restart/rescan against the CURRENT ownership set until a complete pass returns
0; only then drop that master's blockers. Dedupe concurrent caller/tick work per victim.
(c) Keeping the imported blockers while bits remain is correct fail-closed (dropping them = decisions
diverge from durable authority, -EBUSY loops, slot-reuse aliasing). Whole-victim blockers over-block
clean pages; page-by-page removal after each page commit is the refinement. -ENOTRECOVERABLE may be
indefinite → explicit page/fs repair or fencing, never blocker removal or slot reuse.

## Fix plan (0.35.2, after the 0.35.1 rig verdict)
1. mxfs_dlm_ledger_purge_owner: on rc != 0 keep the victim's imported blockers, add {node,slot,inc} to a
   master-owned purge-pending list (dedup), return rc. Tick (mxfs_dlm_release_retry_tick) re-runs the
   purge over the pages mastered NOW until a full pass returns 0, then drops the blockers.
2. recovery_complete2: rc != 0 → P-TAUTH-COMPLETE-LEDGER-PURGEFAIL + V5_COMPLETE_HELD_FAIL before
   purge_node/takeover/disklock purge.
3. Import (dlm_page_load): dlm_owner_purged() already retires purged owners lazily on import — keep, and
   make sure purged_owners survives (it is ctx-level, not per-view: OK).
