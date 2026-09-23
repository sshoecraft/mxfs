<!-- sess424 END: 0.35.0 built+deployed (sv 9FF0C36E); ghost-grant fix + step-4 wiring in; rig 32/tcp STILL fails — FREEZE-DRAIN-TIMEOUT wedge on page 178… -->
# sess424 end state (2026-08-28 ~09:45Z) — relay boundary

## Fleet / rig
- mxfs.ko = 0.35.0 sv 9FF0C36EE74C7F5A21A926E (built 09:12Z by tests/sess424_chain.sh; usermode gate incl.
  formation_test PASS).  Chain log tests/evidence/sess424_s424.log; it continues (token verify FAILED rc=124
  x4, then prep d0287 / d0287 / sweeps / 32-caw board — read its STAGE lines first).
- 32/tcp prep on 0.35.0 FAILED 26/32 mounts ("can't read superblock" = root-inode EX timeout again).
  Raw per-node dmesg: tests/evidence/sess424_s424_dmesg/prep_token_test*.txt.  Digest:
  * test1 (slot 0, bootstrap) activated page 1786 (ino=128's page) then PREPAREd it to test2 (view-change).
  * test2 activated page 1786 (frozen-msg), imported 3 PR holders (slots 2,3,4) from the record, then
    P-TAUTH-DOUBLE-GRANT: req node=1057180514 (slot 7) EX vs record holders=0x10 (slot 4 = 1227391573 PR)
    — the table decided EX although the ledger still had slot 4's PR bit.
  * then test2: 94 x P-TAUTH-FREEZE-DRAIN-TIMEOUT page=1786 "in-flight transition did not finalize" — page
    stays FROZEN forever; every requester gets REMASTER (P74-GRANT status=12 x4381 fleet-wide), "lock request
    failed after 10 retries" x54, P-LKTIMEOUT-REMOTE master=3752614140 (test7 slot 8); 26 mounts abort.
  * P-TAUTH-STATS why=close on the 26 failed nodes: commits=0 (they never granted anything).  No GHOST, no
    LATE-DELIVERY, no POISON, no REFUSE.
- NEXT RULE-4 TARGET (H2): dlm_page_freeze_drain (dlm.c ~1425) waits for dlm_page_has_pending(page)==false;
  a PENDING_DURABLE / PENDING_RELEASE table entry whose txn was refused/abandoned (the DOUBLE-GRANT -EBUSY
  path? the finalize "refused: undo" path? a txn_commit error return before finalize?) never clears -> page
  frozen forever.  Read dlm_page_has_pending + every dlm_txn_* error path for an entry left in a PENDING
  state; reproduce in tests/tauth (formation_test with an injected DOUBLE-GRANT refusal + view change), then
  fix.  Also H3: why the table decided EX over an imported PR holder (import resolved owner 1227391573 slot 4
  — was that entry dropped by the membership purge before the decision and not re-imported because
  page_import_gen already matched?).

## Landed in tree AFTER the 0.35.0 build (UNBUILT; bump VERSION to 0.35.1 before the next build)
- Mount barrier "resolved elsewhere" (D-MOUNT-WINDOW window arm, s423 rerun): dlm/disklock.c
  mxfs_disklock_slot_terminal_for (ZERO record or ACTIVE successor of another inc, fresh read);
  dlm/v5_mount.c mphase_dead_epoch[], mphase_resolved_mask/node[] set in v5_recovered_cb,
  mxfs_v5_dlm_mount_resolved_elsewhere(mask) (marker not pending + identity witnessed reclaimed + terminal
  sector; P233-MPHASE-RESOLVED-ELSEWHERE / P233-MPHASE-NOT-TERMINAL), recovery_acquire -ENODATA when the
  marker is not pending; xfs/xfs_mxfs_dlm.c barrier drops resolved bits from cohort/drained each pass.
  Ruling: docs/rulings/barrier-resolved-elsewhere.md.  Objects compile.
- tests/d_mount_window_death_verify.sh window arm accepts either resolver; asserts exactly one publication
  cluster-wide and no mount abort.
- Ledger: D-MOUNT-WINDOW next updated (list field — use ledger_set.load/find/save(doc, before)).

## Earlier this session (see docs/history/docs/history/docs/history/compiled-tauth-step3-step4-campaign.md and the two
## GPT-ruling memories): step-4 v5 wiring, ghost-grant fix (D-...-0340 filed), formation_test, P-TAUTH-STATS,
## docs/awareness updates, s422/s423 dispositions.

## Also owed
- intents burst harness (s423): census intents=0 on the victim slice — the harness does not yet produce
  intents in test8's slice (D-FOREIGN-SLICE-INTENTS-ABANDONED verification).
- Ruling items for per-holder identity (shape A: 256-byte entry with 16-bit {node,inc} folds, PROTO_GEN
  bump) — design accepted by GPT this session (see transcript; not yet in a memory of its own).
- docs/tcp-authority-ledger.md + awareness need the barrier fix + FREEZE-DRAIN finding recorded.
