---
name: sess16-gpt-architecture-demote-drain-by-lock-ownership
description: sess16 GPT-5.5 consult: crash_consistency root = release fence drains by CURRENT-FORMAT walk (incomplete across sf↔block); fix = drain ALL buffers di…
metadata:
  type: project
---

## sess16 GPT-5.5 architectural consult (RULE 5) on the 2/tcp crash_consistency durable dir lost-update. GPT confirmed my hypothesis.

## ROOT (confirmed): the sess97 release fence discovers dir blocks to drain by WALKING THE CURRENT DIRECTORY FORMAT (mxfs_dir_data_durable / mxfs_dir_flush_data_blocks for_each_xfs_iext over i_df). That is fundamentally INCOMPLETE — misses: the shortform-inline dinode (dirents live in the inode cluster buffer; data-fork walk lands nothing, returns true vacuously), blocks created mid sf→block conversion (extent not in-core/committed at fence snapshot), block→sf freed-but-still-cached blocks, and reused/freed daddrs. So a committed-unwritten dir block (daddr 2744: in_ail=1, dirty=0, pin=0, undestaged [logged_seq!=written_seq], buf_incarn==cur_gen SAME incarnation, buf_gen<i_dlm_dir_gen) SURVIVES the EX handoff → peer modifies the home block → this node's stale own copy is used as RMW base → durable lost update.

## INVARIANT (write in code): No metadata buffer protected by a DLM resource may remain dirty/pinned/delwri/in-AIL-undestaged (logged_seq>written_seq) capable of later home writeback when that DLM resource is released/demoted to another node. MXFS has NO peer-visible XFS CIL/AIL replay, so home-write-before-unlock is MANDATORY.

## FIX ARCHITECTURE (GPT, GFS2/OCFS2-style demote): drain by LOCK OWNERSHIP not current format.
- Per-dir-DLM-lock registry of every buffer dirtied under that EX tenure (hook xfs_trans_log_buf for dir data/leaf/free/node + xfs_trans_log_inode for the dir inode [shortform dirents] + dir block init sites + stale/free paths).
- On BAST/demote, WHILE STILL HOLDING EX: (1) quiesce new dir txns + wait active==0; (2) xfs_log_force(_lsn) SYNC through protected mutations + wait unpin; (3) synchronously xfs_bwrite EVERY protected buffer whose logged_seq!=written_seq (NOT just XFS_LI_DIRTY — the trace state is dirty=0,in_ail=1,undestaged=true); (4) wait I/O + blkdev_issue_flush/FUA (home block visible on LUN before unlock COMPLETES, not just submitted); (5) invalidate/drop the buffers; (6) THEN dlm_unlock. Assert before unlock: logged_seq==written_seq && !dirty && !delwri && !pin && !(in_ail&&undestaged); else withdraw/shutdown — never hand a peer an un-drained lock.
- On EX ACQUIRE (gen advanced / peer modified): invalidate old-gen cached dir buffers + reread from LUN. If an old-gen buffer is in_ail+undestaged at acquire => FATAL coherency violation (do not silently keep).

## REFUTED (GPT agrees): (b) acquire-side writeback of own committed-unwritten blocks — UNSAFE, overwrites peer's newer home block when buf_gen<i_dlm_dir_gen. Read-side keep-guard cannot be primary correctness (in_ail+undestaged+buf_gen=0 is AMBIGUOUS: fresh-in-core-only block vs stale superseded leftover — proven by the leaf-CRC corruption when I discarded it [[sess16-stale-tenure-keepguard-fix]]). Make the bad state UNREACHABLE at demote instead.

## DECISIVE NEXT INSTRUMENT (cheap, do first): at the dir EX release fence exit (xfs_mxfs_dlm.c bast_process ~3868, before unlock), dump EACH dir data-fork buffer's daddr/logged_seq/written_seq/in_ail/dirty/pin + the inode i_df.if_format. If daddr 2744 (or any) is undestaged at release => demote-drain gap CONFIRMED → implement the ownership-drain. Then incremental: simplest viable fix may be to make the existing fence loop's mxfs_dir_data_durable ALSO cover the sf-inline dinode + re-snapshot format after conversion, rather than the full registry. Build/repro = tests/cc_blockdir_probe.sh (per-iter dmesg clear added; <15 iters). Then FULL ./run.sh 2 tcp 16/16 ×3. Fallback 17DCD050. [[sess16-ROOT-xfsaild-stale-flush-reused-daddr]]
