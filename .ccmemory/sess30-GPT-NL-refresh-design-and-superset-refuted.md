---
name: sess30-GPT-NL-refresh-design-and-superset-refuted
description: sess30 GPT-5.5: write-side set-superset discard REFUTED (legit-remove resurrection); correct fix = NL-side refresh: wait pins→reload extent-map→stale…
metadata:
  type: project
---

## sess30 (ccloop 8ddb16a2) — GPT-5.5 consult (RULE 5). dir_reuse_coherency 2/tcp.

### Failure is INTERMITTENT, BOTH faces (same build AB435ACC, run-to-run variance):
- FACE A (DATA): readdir<200, a contiguous create-order range (=one dir DATA block) durably missing on both nodes.
- FACE B (LEAF): readdir=200 but lookup_fail=N (e.g. 11) — names in data blocks but leaf hashval gone → stat ENOENT.
Both = a node RMW's a STALE cached dir DATA/LEAF block + durably writes it, dropping peer's committed entries. Criterion needs BOTH faces fixed every round (24 rounds).

### REFUTED this session:
1. Acquire-side aggressive pin-drain (extend 50→2000 iters + periodic log_force in mxfs_dir_drain_evict_data_blocks): REGRESSED to readdir=0/200 + xfs_dir3_block_verify corruption. Root: forced cold-reads of dir block 0 while the reader's in-core extent-map was STALE (nextents=1 block-format) but disk grew to leaf-format (XDD3 data block read as XDB3 block) → verifier fail. LESSON: must reload extent-map BEFORE evicting/cold-reading dir blocks. REVERTED.
2. Write-side SET-SUPERSET discard at xfsaild chokepoint (discard write iff disk dirent/inumber set ⊋ buffer set): GPT REFUTED as UNSOUND. Counterexample: legit remove of A → buf={B}, disk still={A,B} before publish write lands → disk⊋buf → discard → A resurrected; worse, the chokepoint discard marks XBF_DONE + xfs_buf_ioend (removes BLI from AIL) so a crash before publish loses committed metadata. publish-before-notify does NOT save it (the removal write IS the {A,B}→{B} write). Inumber sets also insufficient identity (hardlink/rename/reuse). FACE B leaf (hashval,addr) superset ALSO unsound (legit leaf compaction/rebalance → non-superset). DO NOT add an EX-held write-side discard; keep chokepoint detector-only / NL-owner-only.

### GPT's MINIMAL CORRECT FIX = NL-side remote refresh (the sharpened sess29 tenure-local design):
Core: refresh the stale cache OUTSIDE EX (at NL, before acquiring/reusing EX), reloading the inode mapping FIRST. Never reread/evict/wait-pins while holding EX (constraint 4: extends EX hold → peer 120s DLM timeout rc=-110).
- **A.** Treat ANY peer dir-generation advance as DIR_NEEDS_REMOTE_REFRESH (not just the DIR_MODIFY heartbeat flag). Must cover block→leaf/leaf→node growth, freespace, extent-map changes.
- **B.** Refresh while NL, before requesting EX. If grant already arrived and refresh still needed: drop/downgrade grant → refresh at NL → reacquire. Gate EX acquisition on loaded_gen >= observed_peer_gen (retry ≤2× converges: after peer releases+publishes, disk is current).
- **C.** Refresh ORDER (mandatory): (1) wait pins: log_force(SYNC) + wait inode pincount==0 + wait dir-buffer pins==0 (safe to wait at NL — no peer blocked; these are OUR own old-tenure CIL tails); (2) reload inode core + data-fork extent map from disk (MANDATORY before any cold-read, else block→leaf XDD3-as-XDB3 verifier fail); (3) stale CLEAN cached dir DATA/LEAF/FREE buffers (never clear XBF_DONE / never stale a PINNED DONE buf — loop back to pin-wait). Then set loaded_gen.
- **D.** Keep write-side chokepoint conservative (NL-owner skip only / detector); no EX-held discard.

### KEY SEQUENCING INSIGHT (mine, reconciling with existing code):
The slow-path acquire ALREADY reloads inode (xfs_mxfs_dlm.c:8642) + evicts (8687) POST-grant; the evict SKIPS pinned blocks (the leak). Move the PIN-WAIT to NL (pre-DLM-request): at NL we hold no EX (no peer blocked) and can log_force+wait our dir-buffer pins unboundedly. Once unpinned at NL, the existing post-grant reload+evict fully refreshes (no skip) → cold-reads peer's current image (LIO write-through coherent). At NL with no EX held, dir buffers can't be re-pinned (no local dir mods without EX). Implementation point: pre-DLM-request in the acquire entry (mxfs_dlm_ilock_begin), NOT under ILOCK_EXCL.

### NEXT: find mxfs_dlm_ilock_begin pre-request point; add dir NL pin-drain (log_force+wait dir-buf pins) there. Then post-grant reload(8642)+evict(8687) fully refresh. Test dir_reuse 2/tcp (both faces), then full ./run.sh 2 tcp. See [[sess30-LIO-coherent-and-acq-pin-drain-fix]], [[sess29-GPT-design-tenure-local-poison-purge-at-NL]].
