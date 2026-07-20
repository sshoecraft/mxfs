# P14-INSTR Analysis — v0.3.17 Bug-A-residual / AG-btree corruption

**Status**: v0.3.17 = v0.3.16 + P14-INSTR Site A (invalidate_ag_meta verdicts) + Site B (xfs_free_ag_extent gtbno pre-fail dump). Diagnostic-only. Strip before merge.

## What we are looking for
At iter 4 of 15-iter @ 512MB stress on T1 (with v0.3.16), `xfs_free_ag_extent` fires `bno + len > gtbno` (xfs_alloc.c:2140) inside `xfs_defer_finish_noroll`. T1 only; T2 stays clean.

## Leading hypothesis (H1)
On a fresh AG-acquire (post-BAST), `mxfs_dlm_invalidate_ag_meta` walks `pag_bcache` and stales AG-meta buffers. It **skips** any with:
- `b_log_item != NULL` (active bli)
- `_XBF_DELWRI_Q` set
- `!list_empty(b_li_list)` (pending log items)

For btree blocks (bnobt/cntbt) the skip should be safe IF cached-AG release flushed those buffers before unlock. But on a fresh acquire that follows our own bast_work_fn cycle, an in-AIL not-yet-iflushed btree block would be skipped → T1 reads stale cached btree content → T1's free-extent merge logic computes against pre-demote tree → bno+len overlaps a peer-committed neighbor.

Same family as v0.3.10's inode-buffer-stale-with-pending-iflush issue, applied to AG-meta.

## Site A — what to look for in dmesg
For ACQ-FRESH event that immediately precedes a FREE-AG-EXTENT-FAIL:
- Want: every bnobt/cntbt/agf/agfl buffer for that AG shows `verdict=STALED`.
- Smoking gun: any `verdict=SKIP-bli-locked|SKIP-delwri-locked|SKIP-li_list-locked|SKIP-bli-unlocked|SKIP-delwri-unlocked|SKIP-li_list-unlocked` for ops=bnobt or ops=cntbt.

If we see SKIPs on btree blocks at fresh acquire — H1 is confirmed.

## Site B — what to look for
At failure:
- `agf_freeblks` vs `pagf_freeblks` mismatch → cached AGF disagrees with on-disk
- `agf_freeblks` very different from what T1 might have computed → peer wrote
- bno+len vs gtbno overlap magnitude → small overlap (~1 block) suggests off-by-one;
  large overlap suggests range came from a different btree generation entirely.

## Files modified for v0.3.17
- `xfs/xfs_mxfs_dlm.c` — Site A in mxfs_dlm_invalidate_ag_meta
- `xfs/libxfs/xfs_alloc.c` — Site B + `#include <linux/ktime.h>`
- `VERSION` 0.3.16 → 0.3.17

## Build/deploy log
- make clean ✓
- make modules ✓ (warnings as before, exit 0)
- tools/make ✓
- mxfs_deploy.sh test1 --no-mount ✓ → MODULE_LOADED
- mxfs_deploy.sh test2 --no-mount ✓ → MODULE_LOADED
- /mnt/shared mounted on both ✓

## What if H1 is refuted (all STALED)
Move to H2: T1's transaction holding pre-acquire AG view. Add P14-instr to xfs_defer machinery — log when an EFI is queued vs when it runs and which AG view (xfs_perag generation stamp) was active at queue vs run.

Or H3: T2's writes hit disk after T1's invalidate — would manifest as `verdict=STALED ... blkno=X` followed by T2's BAST notify, then re-acquire by T2 (impossible since T1 holds), so likely not the cause unless there's an iodone-after-release race.

Or H4: deferred-extent-free race — bno computed against wrong cluster.

## How to read the dmesg cross-merge after stress
1. `sudo dmesg -T --color=never > /tmp/t1.log` on test1
2. Same on test2
3. Convert `[realns]` to t_ms using kernel boot offset
4. Sort merged by realns
5. Find FREE-AG-EXTENT-FAIL line on T1
6. Walk back from there to the most recent ACQ-FRESH agno=N that matches the failing AG
7. List all P14-INSTR Site-A lines for that ACQ-FRESH
8. Compare blkno of any non-STALED verdict against the AG's bnobt root block

## Run history
- v0.3.17 stress run 1: iter 1 FAIL — xfs_remove rc=ENOENT for "perf_t2", T2's create lost from disk before T2 released DLM grant. Cross-merge showed P14 STALED verdicts only (no SKIP signal), so this was a different bug than AG btree H1.
- v0.3.17 stress run 2: iters 1, 2 PASS, iter 3 FAIL — different mode again: CAW deadlock (T2 `DLM inode lock unrecoverable: ino=128 mode=3 rc=-110` after 3×120s timeouts, T1 `lock exhausted 100 retries for ino=0 type=3` on AG=1). Stress was killed manually.
  - **H1 SMOKING GUN CAPTURED**: T2 dmesg at 74388.256905 — `P14-INSTR ... agno=0 blkno=2 ops=agi verdict=SKIP-bli-unlocked b_log_item=000000007a88cd16 flags=0x200030 li_empty=1`. An AGI buffer survived staling on fresh AG acquire because b_log_item was attached. Existing skip-on-bli-attached logic premise ("cached-AG release flushes everything") is empirically wrong in some cases.
  - However: this particular SKIP didn't directly cause the run-3 deadlock. Run-3 failure was a CAW deadlock (different family). The AGI SKIP is likely the cause of a DIFFERENT class of failure (e.g. session-12 iter-4 AG btree corruption family, or "Free inode not marked free" family).
  - bnobt/cntbt/inobt/finobt all STALED in this acquire (only AGI got skipped). So session-12's specific corruption (bno+len>gtbno on bnobt) requires a different timing window — bnobt-with-bli-attached at fresh-acquire moment.

## Latent dir-stale bug (deferred)
Run 1 exposed a real cross-node dir-coherency bug where T2's `xfs_create` of perf_t2 was committed locally but never iflushed to disk before T2 released ino=128's DLM grant in `mxfs_dlm_bast_process`. T1 then read empty dir from disk, modified it, and T2's later reload pulled empty disk content over correct in-memory state. Trace: T2 mem_size=21 first_entry="perf_t2" but disk_size=6 disk_mode=0x41ed.

This is rare and load-bearing for cross-node coherency. Hypothesis: even after `xfs_log_force(SYNC)` (which is documented to wait for iclog completion callbacks → AIL insertion), `xfs_ail_push_all_sync` may observe a brief AIL-empty window before the bli is fully drained from CIL into a written cluster buffer. Or some inode-flush path skips the cluster buf write entirely.

Defer until AG-btree bug is closed; we have one rare repro on hand. Fix would likely add a synchronous direct-iflush + delwri_submit on the inode's cluster buffer in bast_process before staling.

## CAW slot exhaustion on AG=1 (run-2 iter-3) — investigation breadcrumbs
Failure trace:
- T1: `dlm_caw: lock exhausted 100 retries for ino=0 type=3` (resource->ino=0, type=3=AG; ag=1 from caller context); `DLM AG lock failed: ag=1 rc=-110`; page discards on inode 0x84 (=132 dec); repeated `MX-INSTR bast_notify ino=128 ... BRANCH=DEMOTING_already` every ~7ms.
- T2: 3×120s `disk lock acquisition timed out` for ino=128 mode=3; `DLM inode lock unrecoverable: ino=128 mode=3 rc=-110 — shutting down filesystem`.

Hypothesized chain (NOT yet validated):
1. T1's bast_process for ino=128 enters DEMOTING state.
2. bast_process needs to flush dirty data → AIL push → triggers writeback → block allocation → mxfs_ag_dlm_lock(AG=1).
3. AG=1 fresh-acquire CAW grant attempt.
4. find_slot or CAS retries spin and exhaust at 100 retries → ETIMEDOUT.
5. bast_process can't complete; ino=128 stays DEMOTING.
6. T2 keeps polling for grant on ino=128; never gets it.
7. T2 times out 3× → unrecoverable shutdown.
8. After T2 shutdown, T2's heartbeat stops → eventually lease-expire on T1 → CAW purge of T2's slot bits → modifies AG=1 slot → T1's CAS continues to miscompare.

P15-INSTR plan for next session:
- Add CAW traffic logging in mxfs_dlm_caw_lock for AG resources (gate on resource->type == MXFS_LTYPE_AG): each retry iteration log retry#, find_slot result, slot_idx, cur_slot.{generation, granted_mode, holders, waiters, yield_to}, the action taken (claim-empty / register-waiter / yield-backoff / yield-stale-clear / upgrade-release), CAS result.
- Reproduce stress; cross-merge with T2 to identify which node mods are causing T1's CAS misses.
- Likely candidates: heartbeat thread (no — separate region), lease-expire CAW purge (yes — runs after peer goes silent).
