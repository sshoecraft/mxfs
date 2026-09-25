<!-- sess411 ROOT CAUSE of fln4 -117: survivor replays a live-fenced victim's slice while it is still changing; stale/absent CRC-valid records silently dr… -->
# -117 foreign-replay failure (fln4_hb_churn slot 29, also sess409 slot 12): ROOT CAUSED sess411

## Evidence chain (all from tests/evidence/sess410_fln4_hb_churn/ + tools/mxfs_logslice.py on ~/disk.img)
1. Kernel (test1, 0.26.12) failed pass-2 at xfs_inode_item_recover.c:373 `ldip->di_magic != XFS_DINODE_MAGIC`, ino 16787046, inside txn lsn=0x1000074bd; P227-FR-UNWIND err=-117; terminal TORN verdict + FSWIDE quarantine published (replay_test1.txt:150-204).
2. tools/mxfs_logslice.py (written sess411; upstream-faithful reassembly, O_DIRECT reads) decodes the SAME slice from the platter NOW: all 25 txns committed clean, 5775 inode items ALL magic-valid, 0 open txns. Txn 074bd = 131 items (th_num_items=390 regions), contains ino 16787046 with valid core (cc=4), and 07508 has its cc=5 version.
3. Fork recovery engine verified upstream-identical by reading: xlog_recover_add_to_trans/add_to_cont_trans/commit_trans (batch=100)/recovery_process_trans/ophdr_to_trans/process_data/xlog_recover_process CRC path (xfs_log_recover.c 3958-4435, 4838-4910). CRC mismatch would be fatal+logged — never logged, so kernel-read records were CRC-intact.
4. items=100 in P227-FR-ENFORCE-ADMIT = the BATCH count (mxfs_n_items counts item_list in xlog_recover_items_pass2, line 3723). Kernel failed in batch 1 (≤100 items, reorder puts 3 BUFs first then INODEs in log order) but platter position of ino 16787046 is ~#117 → kernel's item list was ≥17 items SHORTER → its byte view lacked regions the platter has.
5. Timeline: survivor replay ran 17:01:40.87-42Z (P144-WR realns=1787504500868040460); victim (test20 slot 29) was ALIVE and appending until withdraw ~17:01:46-47 (victim 300-301s, anchor P145 realns=1787504462@256.6s); victim logerr=0 (no log write ever bounced); only 1 command from test20 bounced at the target in the whole window.

## Mechanism
Foreign replay begins ~22ms after the recovery lease (P238-RECOV-LEASE 700.867 → slice read 700.889) with NO drain barrier. The victim's slice can still be changing under the reader (in-flight admitted-pre-preempt writes; SCSI simple-task R/W reordering; loaded target aio). Blocks not yet written this fs-life hold the PREVIOUS mkfs life's records (mkfs zeroing not durable — dev note) — same cycle 1, CRC-valid near-twins from the identical prep/churn workload. Recovery's ophdr walk silently skips unknown-tid regions ("slack space" tolerance, xlog_recover_ophdr_to_trans returns NULL), so a stale record inside a multi-record txn span DROPS items without any error; the next current record's regions then fill the wrong ri_buf slots → bad ldip magic → -117 → FALSE TORN verdict, FSWIDE quarantine (availability loss). Worst case is silent: a mis-assembly that happens to parse could APPLY wrong images.

## Both -117s (sess409 slot 12, sess410/411 slot 29) are hbpause+churn arms; hb_idle passed — consistent (idle victim has no in-flight writes / no deep slice content).

## Fix directions (for design consult, not yet ruled)
(a) Quiesce barrier before slice read: verified PREEMPT-AND-ABORT semantics (dm_pr_preempt drops abort — sess378; must go via PAL SG direct) + confirmation the target has no in-flight victim commands, or a bounded settle + stability re-read of [tail,head].
(b) Per-record mount-incarnation stamp in the log record header (detect previous-life records exactly, treat as hole/head, not slack) + durable slice zeroing/stamping at mkfs or first mount.
(c) Foreign-replay strictness: unknown-tid non-START ophdr inside [tail,head] while txns are open ⇒ ambiguous view ⇒ retryable refusal (NOT terminal TORN) so a re-read after settle can succeed instead of freezing the domain forever.
Note: the current outcome (refusal+quarantine) is fail-safe but wrongly TERMINAL — the slice is actually replayable (platter is clean); D-513 refusal-containment machinery worked as designed.

## State
fln4_log_idle arm died with sess410 (header only) — still needs rerun for D-409 closure. fln4_hb_churn victim-side containment PASSed (withdraw +73s, 0 post-withdraw conflicts). Slice 29 evidence preserved on disk.img (quarantined, nothing run since); next prep/mkfs DESTROYS it.
