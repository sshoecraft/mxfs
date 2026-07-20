---
name: sess11run-HANDOFF-evict-fix-insufficient-revert-under-ilock-next-probe
description: sess11(ccloop) HANDOFF: in_ail-gate evict fixes (modify 2501 + acquire 4663) INSUFFICIENT/harmful — loss persists (now data-file node2_f38 too, not j…
metadata:
  type: project
---

## sess11 (ccloop 4cb2d0a2) HANDOFF — GPT touched-buffer fence partial impl INSUFFICIENT; next probe pinned

### Tree state: CLEAN BASELINE build 1D3115A5 (= DE3A7E21 + inert FIX3 + harmless P11 probes). Buildable. All evict experiments REVERTED. Cluster test1-4 mounted+idle (grub now has log_buf_len=16M → 16M dmesg ring, KEEP — survives the storm).

### What this session PROVED (extends [[sess11run-ROOT-committed-dirent-reverted-by-evict-before-publish-GPT-fix]])
1. FIX3 (sess10 9527F28F) conclusively REFUTED: P67 branch gated behind `mxfs_dir_postread_reread`=0 default (inert); flag ON regresses to 14/400. Read-side gen-stale = wrong layer.
2. ROOT (instrumented, 3 distinct losses node3_f45.md5/node4_f22.md5/node2_f13.md5 + node2_f38 DATA FILE): durable single-dirent loss; the dirent is committed (P-CRNAME-DONE rval=0) but appears in ZERO P-RELFLUSH/P11-FLUSH-CLEANSKIP block images on ALL 4 nodes the whole round → its in-core dir DATA block NEVER contained it at any flush. The committed dirent is REVERTED out of the in-core buffer before publish-flush destages it → lost on every node (cold readdir + lookup ENOENT).
3. NEW: the loss is NOT .md5-specific — last run lost node2_f38 (a 1st-wave DATA FILE). Correlates with the dir's 2→3 data-block GROWTH/split window. Lost ALWAYS during concurrent insertion into the growing/contended dir.
4. CRITICAL NEW CONSTRAINT: the revert happens BETWEEN addname-commit and the immediately-following durable_signal flush (~240us, SAME thread, UNDER ILOCK_EXCL). e.g. test2: CRNAME f13.md5(57.200924)→CRNAME-DONE rval=0(57.201191)→P-DSIG(57.201297)→flush off1(57.201434)=DATA-files-only, NO f13.md5. No concurrent evict can run under ILOCK_EXCL, so the revert is NOT a concurrent peer-BAST evict during the create. => GPT's "concurrent BAST evict" hypothesis is likely WRONG for this window; the revert is something WITHIN the create/grow/durable_signal path (a buffer stale+realloc, or a split relocating the entry into a block the flush's extent iteration misses, or modify_refresh interplay).

### Fixes TRIED this session and their results (do NOT just re-apply)
- Removed `in_ail &&` gate on the cluster-undestaged keep at the MODIFY-path evict (mxfs_dir_evict_data_blocks ~2501, build 78B0C9B7): keep iff `(!incarn_aba && mxfs_dir_buf_is_undestaged)`. drc4_repro STILL FAILS (node2_f38 round 23 vs baseline round 5-15 — pushed later but NOT fixed). REVERTED.
- ALSO removed it on the ACQUIRE-path drain_evict (mxfs_dir_drain_evict_data_blocks ~4663, build A0D1A382): HANGS the test (>280s, dir-EX handoff STALL — a node holds a buffer peers need). HARMFUL in isolation. REVERTED. Confirms GPT: acquire-side suppression needs the COMPLEMENTARY guaranteed release-destage, else livelock.
- HARNESS NOTE: run.sh/validate_drc4 (MQTT barrier suite) became unreliably SLOW this session (>200s even on BASELINE — runs all 24 rounds; MQTT broker 192.168.1.149 IS reachable, not the cause). USE drc4_repro (standalone, exits at first fail, ~10s/round, reliable) for correctness validation. Harness: `/tmp/...scratchpad/drc4_clean.sh` (reset+prep no-dirwr+drc4_repro) or `tests/tcp/drc4_capture.sh N` (dirwr=2, perturbs timing/heisenbug — use only for forensics, not pass/fail). `tests/tcp/validate_drc4.sh` uses run.sh (slow).

### THE decisive NEXT PROBE (RULE 4 — run FIRST next session)
Confirm the revert + find what causes it: add a probe RIGHT AFTER xfs_dir_createname() returns 0 (xfs/libxfs/xfs_dir2.c ~488, gated dirwr, storm dir ino<=256, only for name[]~'node*') that LOOKS UP the just-added name to get its data-block daddr, then logs that daddr + a mxfs_dir_block_names() dump of that block's in-core buffer → CONFIRM the entry IS in the in-core block immediately post-addname. Then the existing P-RELFLUSH/P11-CLEANSKIP at durable_signal shows the SAME daddr WITHOUT it. The delta isolates the reverting step. Prime suspects to instrument between: (a) xfs_dir2_node/leaf split relocating the entry to a block whose extent isn't in i_df at flush; (b) a buffer xfs_buf_stale+realloc; (c) the durable_signal's own xfs_log_force(SYNC) racing xfsaild write-completion that frees/replaces the buffer.

### THE correct FIX direction (GPT-5.5, [[sess11run-ROOT-committed-dirent-reverted-by-evict-before-publish-GPT-fix]]) — implement COMPLETE, not partial
Per-EX-grant TOUCHED-BUFFER writeback fence: (1) mark every dir DATA buffer logged under EX `cluster_undestaged`+hold at the low-level dir-data log points (xfs_dir2_data_log_entry/header/unused); (2) NO evict/cold-read clears XBF_DONE on it (ALL paths: modify-evict 2501, acquire drain_evict 4663, read-side xfs_da_btree 3260, bmbt 836/12717); (3) publish: force-write every touched buffer HOME before DLM unlock even if it looks clean; (4) BAST must DEFER evict/reload until the local publisher finishes (schedule, don't sync-IO in callback) — this is the missing half that makes (2) not livelock. Tie clean-block refresh to a PEER durable epoch (LVB), not grant churn (avoid over-fire). Do NOT union-merge dir data blocks. The infra exists: b_mxfs_logged_seq/b_mxfs_written_seq + mxfs_dir_buf_is_undestaged() already = the cluster-undestaged signal.

### Criterion NOT met. 2/tcp passes; 4/tcp fails ONLY dir_reuse_coherency (durable dirent loss). See [[sess21-leaf-rebuild-fix-works-90of91-residual-stale-datablock]] (leaf-rebuild in-tree, fixes leaf holes not data-block loss) [[sess42-SYNTHESIS-block0-split-is-double-sf-conversion-lineage]].
