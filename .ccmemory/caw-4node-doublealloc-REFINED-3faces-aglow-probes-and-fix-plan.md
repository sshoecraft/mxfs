---
name: caw-4node-doublealloc-REFINED-3faces-aglow-probes-and-fix-plan
description: 4/caw ROOT refined: shared block-fmt SUBDIR blocks (agbno9/AG) incoherent cross-node — 3 faces (file-data double-alloc / undurable-garbage / torn-RMW…
metadata:
  type: project
---

## 4/caw cache_coherency ROOT — REFINED (ccloop 12e0d157 sess3, 2026-07-07)

Supersedes the "pristine-snapshot" reading in
[[caw-4node-doublealloc-fable-design-fix-freelist-choke]]. Chain:
[[caw-4node-cache_coherency-ROOT-bnobt-doublealloc-NOT-prfence]] →
[[caw-4node-doublealloc-current-code-state-and-next-probe]] → this.

### What the shared block reuse actually is
cache_coherency's 4 subdirs (cross_visibility/cross_write_read/rename_visibility/unlink_visibility)
are each created by whichever node WINS the mkdir race → each subdir's inode lands in that node's
affine AG, and its BLOCK-FORMAT dir block lands at **agbno 9** (the first block after the 9 static
AG-meta blocks 0-8) of that AG. All 4 nodes then RMW every shared subdir → the dir block at agbno 9
in each AG is a hot cross-node RMW hotspot. diagowner seen: AG0=ino131, AG1=ino2097280, AG2=ino4194433,
AG3=ino6291587 (one subdir per AG, comm=mkdir).

### THREE FACES of the incoherence (all → dir3 read-verify fail → FS shutdown → 0/4 cascade)
1. **file-data double-alloc**: daddr holds pure FILE data ("hello from node 1" .txt; or a 32-hex
   .md5) — a file's data block aliases the dir block. (run A, build 0510FC3E: P-DBLALLOC daddr=72
   holds=dir-block comm=kworker = delalloc writeback.)
2. **undurable-garbage**: daddr read owner=0 garbage (dir block alloc'd but write not durable when a
   peer FUA-read it).
3. **torn-RMW wrong-CRC**: valid XDB3 magic + correct self-blkno but CRC MISMATCH (P15I-CRCFAIL
   err=-74) — dir block partially overwritten / RMW'd incoherently. (run C, build B6F0D45F.)

### What is NOW RULED OUT (RULE-4, instrumented)
- NOT a PR-fence/coherency-regression (sess2 misdiagnosis).
- NOT a DLM bypass: AG-DLM is acquired at the CHOKE `xfs_alloc_vextent_prepare_ag`→`xfs_alloc_fix_freelist`
  for ALLOC, and `xfs_free_extent_fix_freelist` for FREE (both call mxfs_ag_dlm_lock BEFORE fix_freelist).
  All 5 vextent wrappers incl. delalloc-writeback's `xfs_alloc_vextent_start_ag` route through
  `xfs_alloc_vextent_finish` (verified). So Fable's "(a) no DLM" is refuted.
- NOT Fable's "pristine bnobt snapshot": P-AGLOW-ALLOC at agbno9 shows agf_freeblks=261635 of
  agblocks=261653 (18 used, NOT pristine) on all 4 nodes.
- Acquirer coldread (bnobt/cntbt) + release bnobt/cntbt hard-barrier (P117 evict clean+drained) are
  PRESENT but insufficient. AGF/AGI release-evict was REVERTED (sess118 desync).

### DIAGNOSTIC PROBES LEFT IN CODE (build B6F0D45F, xfs/libxfs/xfs_alloc.c) — remove before final criteria run
- `P-AGLOW-ALLOC` (in xfs_alloc_vextent_finish, ~line 4260): un-gated, agbno<64, logs owner/diagowner/
  tenure/agf_freeblks/agf_longest/agblocks/node/wasfromfl/comm/realns.
- `P-AGLOW-FREE` (in xfs_free_ag_extent success path, ~line 2744): un-gated, bno<64.
These are LIGHT (agbno<64 only) and keeper-equivalent behavior; safe to keep for diagnosis.

### FIX PLAN (next session, in priority order)
1. **Fable fix #2 — acquire-side AGF/AGFL FUA-REFRESH on fresh peer grant** (the one clearly-missing,
   low-risk piece). In the fresh_acquire path (xfs_mxfs_dlm.c:~23074, where coldread_discard(pag,true)
   runs), ALSO lock AGF+AGFL buffers, clear XBF_DONE (do NOT xfs_buf_stale/evict — that is the sess118
   desync), mark _XBF_FUA_FRESH so next read cold-fetches from the MEDIUM. Result: AGF roots/freeblks/
   longest + AGFL + bnobt/cntbt form ONE coherent cold snapshot per tenure. Safe: fresh peer grant ⇒
   Inv-1 guarantees no dirty AG state to lose. Read mxfs_ag_meta_coldread_discard (xfs_mxfs_dlm.c:21206)
   and mirror its structure for AGF/AGFL with clear-DONE instead of stale.
2. **Dir-block coherence (torn-RMW face)**: the shared subdir block itself needs drain-durable-before-
   EX-release + FUA-coherent-read. Verify the dir-block EX release drains daddr9 durably (Inv-1) and the
   peer FUA-read is coherent; the dir_* params (dir_release_stale/dir_wr_barrier/dir_newtenure_evict) may
   have a gap for the block-format single-block subdir hotspot.
3. PAL ordering (Fable #4): yield = drain writes → SYNCHRONIZE CACHE (or FUA writes) → CAW release, so a
   peer's fresh-grant FUA-read sees the drained image not a SCST destage race. (blkdev_flush "dropped by
   LIO" note at xfs_mxfs_dlm.c:5439 — verify it works on SCST.)
Validate each change: 4/caw cache_coherency ×3 consecutive clean (require P-BLKRV-CRC=0, no shutdown,
4/4) before trusting (single PASS is variance per sess117). Then 8/16-caw cache_coherency + dir_reuse.
Do NOT: write-side interlocks, AGF/AGI release-evict, force_block=0 (all refuted). Fable consult already
done ([[caw-4node-doublealloc-fable-design-fix-freelist-choke]]); a 2nd consult (Fable then GPT) only
after implementing #1 and re-measuring.
</body>
