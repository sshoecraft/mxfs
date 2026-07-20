---
name: sess4-END-classB-reload-adopt-gap-next-steps
description: sess4 END: class-A concurrent-EX FIXED+verified (0 dbl-grants runs 21-26). Class B open: r10 dangler = reused-ino shells never adopt valid disk dinod…
metadata:
  type: project
---

# sess4 END — state + exact next steps (build 3FB52EFE4316895B2C328EA deployed)

## FIXED + VERIFIED this session (keep!)
1. **Class A (concurrent EX → stale-base RMW → readdir dirent loss): FIXED.** Root: mxfs_dlm_unlock's WAITING/BLOCKED fallback reaped concurrent live local requests (LIFO chain) → dangling newlk → timeout freed recycled LIVE peer grant → double-grant. Fix: `pend_waiter` linkage (dlm/dlm.h+dlm.c) + unlock-fallback skip (P4U-SKIP-INFLIGHT: fires 17-126×/run, correctly) + timeout-free identity guard (P4G: 0 post-fix). **Runs 21/22/23/25/26: ZERO readdir loss, ZERO P-DOUBLEGRANT/MX-DOUBLEGRANT** (previously every run lost dirents). Round times healthy 24-35s.
2. P4X-UNLINK success-path fix (xfs_inode.c: `error=0; goto std_return`), P4I-IFREE, P4C-IALLOC-WR/IFREE-WR cluster-slot decode, P27 hex masks, P4S-LIVESHELL probe, streaming dmesg (prep_node.sh), scripts/mxfs_dirdump.py (raw dir decoder; da3_blkinfo=56B!), scripts/p29_replay.py.

## OPEN: Class B — the ~round-10 dangler (`readdir=800 lookup_fail=1..2`)
Reproduces EVERY run at r~10 (runs 20,22,23,25,26; victims vary: node4_f19.md5, node4_f29, node5_f31, node8_f10). Shape (run23/25 proven):
- rank1's rm frees victim ino each round (P4I+P4C-IFREE-WR land promptly ✓).
- r9: creator re-creates the name; SAME ino reused; create commits (P-CRNAME-DONE rval=0).
- **Creator's own in-core inode mode becomes 0 within ~11s of create** (its own P26-IGET-FAIL) = DEFECT B2: something (late freed-hint reload? inodegc?) zeroes a freshly-created inode in-core; the committed ILI still destages so DISK becomes valid (0x81a4).
- r10+ verify on ALL nodes: `P-IGET-ENOENT incore_mode=0 cached_disk_mode=0x81a4 fua_disk_mode=0x81a4 flags=0x0 dlm_stale=1` — disk VALID everywhere, every node's shell stuck free = DEFECT B3: the reuse-reload machinery never adopts the valid dinode.
- run26 discriminator: P4S-LIVESHELL-RELOAD fired 1× vs 306 ENOENT probes ⇒ the failing igets do NOT take the sess38 live-shell branch (xfs_icache.c ~955). Either they're on the sess40 IRECLAIMABLE branch (its P-REUSE-RELOAD outcome log is instr-gated = invisible; mxfs_reuse_reload=1, mxfs_reuse_dlm=0 default) with the cheap reload failing to adopt, or the ENOENT comes from cache-miss/INCORE flows (probe doesn't print iget-call flags). FIX B1 (igrab-fail → goto out_skip in sess38 branch) is IN (harmless, kept).

## NEXT SESSION — precise steps
1. Add un-gated outcome probes: (a) in the sess40 IRECLAIMABLE reuse block (xfs_icache.c ~1012): entry + post-reload mode + return; (b) in mxfs_dlm_reload_inode (xfs_mxfs_dlm.c 11557) for NON-dir inodes: entry conditions + which early-return taken + from_disk rc + final mode (suspect an early bail for regular files / the imap/cluster-buffer path serving the FREED slot); (c) print iget-call `flags` in P-IGET-ENOENT.
2. Rerun 8/tcp dir_reuse (dirwr=1) → the victim's iget path is then fully named → fix the adopt gap (likely: reload must from_disk a valid-disk dinode over a mode-0 shell and clear dlm_stale; verify sess87 snapshot guard isn't refusing).
3. DEFECT B2 (creator zeroing): after B3 fix, check if creator-side still occurs (it may be the freed-hint ring marking + reload-from-stale-disk racing the create's destage — guard: never reload-to-free over a DIRTY/pinned/in-CIL in-core inode; the reload self-skip gate at ~11820 (`!mxfs_dir_disk_superset && itemp && (IN_AIL|DIRTY|ili_fields|pin)`) already covers non-dir — VERIFY it's reached for this path, or find the OTHER zeroing site (P20-CLUSTER-INVAL site=reload? xfs_iget_recycle?).
4. THEN: 8/tcp ×5 consecutive clean → 4/2/1 regression → full `./run.sh N tcp` suites ×{1,2,4,8} → criteria marker.
- Also pending: leaf-index class from run19 r14-17 (lookup ENOENT via leaf) — likely same B family; re-check after B fix. AG↔dir ABBA -110 (run16) not seen since class-A fix; watch.
- Test cadence: boot 55s + ccloop_reset 8 (~250s) + run.sh 8 tcp dir_reuse_coherency (480s, keep in ONE ~595s foreground call; NEVER combine with reset in one tool call — tool cap kills mid-run and the barrier death poisons rounds).
- The r~10 REGULARITY: onset when ino-reuse cycling has churned ~8-9 rounds — maybe the freed-hint ring (mxfs_dlm_note_inode_freed) wraps → stale dlm_stale=1 marks with no clear. Check ring size vs 800 frees/round ≈ onset at ring-capacity/800 rounds.

Links: [[sess4-ROOT-FIX-unlock-fallback-eats-live-request-concurrent-EX]] [[sess4-MID-classB-dangler-inode-reuse-staleness-guards]]
