---
name: sess56-dir-format-coherency-fix-and-agi-residual
description: sess56 (run14d): posix_multi16 dir-format-coherency root FIXED (fast-path EX consume MXFS_IF_DIR_RELOAD). Residual = AGI iunlink-list corruption.
metadata:
  type: project
---

## sess56 (ccloop 14d31183) — dir block->leaf format-coherency shutdown FIXED

Continues [[sess55-faceB-is-M2-stale-bmap-not-allocator]]. Only `posix_semantics_multi16`
FAILs (`elapsed>600s`) from FS shutdowns under `tests/repro_agi_unlink_storm.sh 16 6`
(reset via `tests/reset4.sh 16`).

### THE sess55 "on-disk inode-cluster clobber" FRAMING WAS A RED HERRING
P56-DIRWR-OVER-DISKINODE (write submit) fired 0× like M1/M2. The real signature:
`P54-DIRBLK-PROBE` shows the ON-DISK dir block is VALID (XDB3, owner ok, crc ok), but the
shutdown is `Corruption of in-memory data` at `xfs_buf_verify_write` / `xfs_dir3_block_verify`
/ `xfs_dabuf_map HOLE` — an IN-CORE staleness, not an on-disk clobber.

### PROVEN ROOT (RULE-4, P56-FMT-BLOCK-RELOAD-PENDING fired on the exact shutting-down dir)
A dir grows block->leaf (a peer adds dirents). Block 0 changes XDB3->XDD3 on disk; the dir
inode gains a 2nd extent (nextents 1->2, leaf block). The evict-ring (`note_dir_modified`,
xfs_mxfs_dlm.c ~L8633) arms `MXFS_IF_DIR_RELOAD` on peers but **does NOT bump i_dlm_dir_gen
when gen==0** (the `gen != 0` guard). The dir-EX FAST-path acquire refresh
(`dir_ex_stale_refresh`, ~L5429) keyed ONLY on `i_dlm_dir_gen > i_dlm_dir_loaded_gen` —
it ignored the flag. So a fast-path mkdir/remove reached `xfs_dir2_format` (xfs_dir2.c:286)
with a STALE 1-extent map, decided FMT_BLOCK, read block 0 with block ops -> XDD3-vs-XDB3
verify fail -> `xfs_create`/`xfs_remove` dirty-trans cancel -> `SHUTDOWN_CORRUPT_INCORE`.
Slow-path acquire ALWAYS reloads (P105 shows nextents=2 correct) so only fast path was buggy.

### FIX (build 0273A7EB, KEEP) — xfs_mxfs_dlm.c fast-path dir-EX acquire (~L5429, ~L5511)
1. `dir_ex_stale_refresh = true` ALSO when `(ip->i_flags & MXFS_IF_DIR_RELOAD)` (bypasses the
   gen check AND the self_created gate — the flag is a definite peer-modify signal).
2. In the reload block: `xfs_iflags_clear(ip, MXFS_IF_DIR_RELOAD)` before reload; re-arm if
   `ip->i_dlm_stale` still set after (reload bailed). Mirrors consumer path (~L1192).
RESULT: P56-BLKREAD 0×, P56-FMT-BLOCK-TORN 0×, NO dir3_block_verify/HOLE/FMT shutdowns. Repro
ran full 300s (was round-1 shutdown). reload_BAIL=0 (not a trylock-bail issue).

### RESIDUAL BLOCKER (next): AGI unlinked-list corruption (SEPARATE root)
After the fix, only test1 shut down, signature = `Metadata corruption at xfs_iunlink+0x27c
xfs_agi block 0x2` -> `xfs_trans_cancel line 1060 Caller xfs_remove` -> CORRUPT_INCORE. This
is the original agi_unlink_storm bug ([[sess53-agi-insert-stale-head-shutdown-fix]] fixed
rmdir-insert 9C3D67D7 but remove-side AGI bucket-head coherency residual). AGI is AG metadata;
under 16-node concurrent unlink into shared AGs a node's cached AGI unlinked-bucket head goes
stale (peer modified the list). Likely needs AGI FUA-reread/invalidation on AG re-acquire,
analogous to the dir-gen mechanism. Builds this session: 26D4F790 -> B8E5254C -> CDEDB37B ->
7BCAA93A -> 0273A7EB (FIX) -> 421AC395 -> A1F53770 (current, +P56-BLKREAD probe). Probes P56-*
gated behind mxfs.dirwr; remove before ship. Marker NOT written (criterion still fails on AGI).
</body>
</invoke>
