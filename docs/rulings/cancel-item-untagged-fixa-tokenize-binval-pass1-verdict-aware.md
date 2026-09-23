<!-- sess476 RULE-5 ruling (D-FOREIGN-SLICE-INTENTS-ABANDONED chain 105): untagged CANCEL item = by construction (format gate !STALE); fix = A tokenize CA… -->
# sess476 GPT ruling — untagged CANCEL buffer items (chain 105 refusals)

## Root (code-proven, probe s475b pending)
- pal/linux/xfs_buf_item.c xfs_buf_item_format_segment: trailer appended only `if (!(bli_flags & XFS_BLI_STALE) && wants_authority)`; STALE branch logs the bare format with XFS_BLF_CANCEL → EVERY CANCEL item is untagged.
- xfs/xfs_trans_buf.c xfs_trans_binval sets STALE/CANCEL, clears BLFT mask + data map, sets LI_DIRTY directly (no xfs_trans_dirty_buf → no capture either).
- Consequence: any txn freeing a metadata block (bmbt collapse, dir/attr block, AG btree block, inode cluster) can never be foreign-replayed (ATOMIC-SKIP on the untagged CANCEL).

## Ruling: fix A + pass-1 verdict-aware cancels. B REJECTED.
- B ("CANCEL is a no-image item, allowlist it") rejected: a CANCEL has a real cross-txn effect (pass-1 cancel table suppresses earlier images), authority of OTHER images in the txn does not authenticate the CANCEL's (blkno,len) target (multi-domain txns; node may hold AG grant but have lost the inode grant), so B = unauthenticated side-effecting item — exactly what the strict allowlist forbids.
- A: capture authority in xfs_trans_binval BEFORE stale conversion (first-capture semantics: keep an existing valid capture; NONE/INCOMPLETE if no unambiguous grant); lift the STALE gate on BOTH size and format sides (must stay identical — mismatch = log corruption); append trailer before the stale early-return; set XFS_BLF_MXFS_AUTHORITY on the CANCEL format. BLFT-change void check: tolerate ONLY the exact stale transition (captured blft → cleared BLFT + CANCEL); any other type change still voids.
- Class map: bmbt → INODE(owner ino); dir data/leaf/node/free → INODE(dir ino); attr → INODE; bnobt/cntbt/rmapbt/refcountbt/AG headers → AG; inode cluster (STALE_INODE) → ICLUS; SB → SB. Never pick "some held inode grant" — must be unique to the operation (cursor/caller context preferred). Audit that the grant is still held at binval in every free path (deferred-free/EFD rolls especially) — A exposes a gap as nocap/INCOMPLETE, B would hide it.
- Old logs with untagged CANCELs keep refusing (no compat exception).

## Companion pass-1 hazard (REAL, quarantine does NOT cure it)
- pass 1 xlog_recover_buf_commit_pass1 adds every CANCEL unconditionally; a later-REFUSED txn's CANCEL suppresses an earlier ADMITTED txn's image of that block in pass 2 → torn admitted txn before quarantine publishes. Removing entries in pass 2 is too late.
- Mechanism: in xlog_recover_commit_trans pass 1, run a SIDE-EFFECT-FREE whole-txn classifier; skip xlog_add_buffer_cancelled for a txn whose pure verdict is refuse. Split classifier into pure decision (verdict, reason bits, proposed domain, counts) + pass-2 publication (telemetry, quarantine fold, terminal records). Pass-1 and pass-2 verdicts must be identical (stable authority snapshot); mismatch = fatal recovery invariant violation. Admitted txns still do the pass-2 xlog_put_buffer_cancelled; refused txns had no add so no put.

## Verification bar
- existing: policy_refused_txns==0, classless_images==0, authority_mismatch_images==0, atomic_skipped_txns==0, undischarged-EFD>0, quarantine reason==8 only — necessary not sufficient.
- plus: probe shows the former untagged item is XFS_LI_BUF+CANCEL of the expected blkno/len/pre-BLFT; untag_cancel==0, no nocap, no NONE/INCOMPLETE; bmbt CANCEL class INODE w/ correct owner/epoch/lineage; pass1_cancel_add_admitted>0, pass1_cancel_add_refused==0, pass1/pass2 verdict mismatch==0, cancel add/put balanced, no table residue; free-path coverage (bmbt collapse, bnobt/cntbt, dir block, attr block, inode cluster stale); chk clean.
- NEGATIVE tests (separate profile): T2 CANCEL with stale/wrong grant epoch → REFUSE, atomic-skip, NO pass-1 add, T1's B image NOT suppressed; and a mis-targeted CANCEL (authority for another object, none for B) → refuse.
- GPT corrections: "CANCEL effect is pass-1 regardless of verdict" is the companion DEFECT not a justification; "other images carry the free's authority" is not generally valid; CANCEL-last reorder is irrelevant (table is global, built in pass 1).
