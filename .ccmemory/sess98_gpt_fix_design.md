---
name: sess98_gpt_fix_design
description: sess98 GPT-5.5 fix for unlink lost-update (given the NEW write-trace evidence): shared dir buffers must be NON-CACHEABLE across DLM tenure — on EX re…
metadata:
  type: project
---

# sess98 — GPT-5.5 design for the unlink_visibility durable lost-update

Consulted GPT (RULE 5) WITH the sess98 write-trace proof ([[sess98_lessons]]).
GPT confirmed the diagnosis and gave a concrete minimal fix. Core model:
**for shared dir metadata, treat the xfs_buf cache as TENURE-LOCAL, not a
persistent cache.** The DLM serializes the CPU-side RMW, but XFS's per-node
buffer/AIL/xfsaild still writes stale local copies later = the lost update.

## THE MINIMAL FIX (implement first — release + acquire are a PAIR; one alone fails)

### Release path (on dir EX BAST/release, for EACH dir block dirtied this tenure)
DO NOT use whole-AG `xfs_ail_push_ag_sync` (slow 26→148s + deadlock amplifier).
DO NOT call `xfs_trans_ail_delete()` manually (breaks log-recovery/tail semantics).
Per buffer, while still holding dir EX:
1. `xfs_log_force(mp, XFS_LOG_SYNC)` (commit the txn that dirtied it)
2. if pinned: drop bp lock, `xfs_buf_wait_unpin(bp)`, retry (never reread/evict pinned)
3. `xfs_buf_lock(bp)`; recheck pin
4. if dirty/DELWRI/in-AIL: targeted `xfs_bwrite(bp)` (waits bio); retry
5. verify `!pinned && !XBF_DELWRI && !XFS_LI_IN_AIL` (truly checkpointed)
6. **`xfs_buf_stale(bp)`**  ← THE MISSING STEP. Marks XBF_STALE: removes the local
   copy from cache + future writeback so xfsaild can NEVER flush a stale image,
   AND forces the next read to cold-fetch. Only stale a CLEAN/non-AIL/non-pinned buf.
7. `xfs_buf_unlock(bp)` + `xfs_buf_rele(bp)`
THEN release the DLM EX. (Don't hold bp locks across the DLM unlock.)

NOTE current `mxfs_dir_evict_data_blocks` (xfs_mxfs_dlm.c:379) only clears XBF_DONE on
durable blocks — GPT says use `xfs_buf_stale()` (stronger: also blocks future
writeback). That's likely why reverts persisted: a cleared-DONE buffer can still be
re-dirtied/re-flushed; a STALE one cannot.

### Acquire path (EVERY dir-modifying EX acquire)
- if incore bp exists: if pinned/dirty/in-AIL → DON'T reread, DON'T write → block on
  local release-fence or treat as protocol violation/shutdown; else `xfs_buf_stale(bp)`
  + rele.
- cold-read from target (plain, NON-FUA) → RMW.

### Fast path
Because release `xfs_buf_stale()`s the buffer, the next read cold-fetches REGARDLESS of
lock fast/slow path — so buffer-level coherency makes fast-path grants SAFE without
disabling them. (If still racy, gate: shared-dir EX always slow-path invalidate+coldread.)

## WHY my sess98 Inv1 (IN_AIL) fix was necessary but insufficient
Release now lands the block before handoff, BUT kept a cacheable copy → acquire could
still hit stale local state / xfsaild re-flush. Need the DISCARD (xfs_buf_stale) on
release + cold-read on acquire. One side without the other = still fails.

## Optional cleaner architecture: on-disk per-directory coherence EPOCH (we own format)
Epoch alone is only a DETECTOR — does NOT stop stale xfsaild writeback. Needs 3 parts:
1. READ-validate: each dir block carries dir_epoch; bump on every committed dir mutation;
   acquirer reads committed epoch E+1, cold-reads, requires block.epoch==E+1 else retry.
2. WRITE-suppress: before submitting a shared dir buf write, if buf.epoch < committed
   epoch → skip write + stale buf (hard part: must integrate with log recovery).
3. RECOVERY-validate: replay a logged dir item only if L > on-disk block epoch D (else
   skip — prevents a crashed node's old log replaying over a newer published epoch).
Do the buffer write-invalidate handoff FIRST; epoch is the correctness/recovery layer.

## NEXT SESSION: implement release publish-and-discard (xfs_buf_stale + drop whole-AG push)
Current build 8AA373A2 (= E06FDBC3 + P-DIRWR + P-DIRFASTEX + P-RELFLUSH probes + IN_AIL
fix in mxfs_dir_data_durable). Edit the bast_process dir release loop (xfs_mxfs_dlm.c
~L1306-1445): drop `xfs_ail_push_ag_sync(d_agno)`; keep targeted mxfs_dir_flush_data_blocks;
after durable, change mxfs_dir_evict_data_blocks to `xfs_buf_stale()` the clean blocks (or
add a new mxfs_dir_stale_data_blocks). Verify `xfs_buf_stale`/`xfs_buf_wait_unpin` are
callable (wait_unpin is static in pal/linux/xfs_buf.c:1020 — de-static/export if needed).
Build, reset4 (fua_disable=1), run unlink_visibility; expect reverts gone (P-DIRWR active
monotonic) + fast (~9s, NOT 148s) + rename/cwr stay PASS. Watch intermittent bnobt
double-free (separate; GPT same fence applies to AGF/AGI/bnobt bufs). [[sess96_gpt_fix_design]]
