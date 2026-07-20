---
name: sess-tcp-SEED-correction-notification-not-acted-on
description: CORRECTION to seed-root memory: the dir-inode-free "ring overflow" cause is UNPROVEN (rm-rf frees dir LAST = newest, so overflow would KEEP it). note…
metadata:
  type: project
---

## Correction to [[sess-tcp-SEED-ROOT-ino131-free-lost-to-evict-ring-overflow]]

The CONCLUSION (node2 keeps a STALE INCARNATION of the reused dir ino=131 → block0→112 → the whole bug) and the FIX (incarnation-verify on dir-EX acquire, ring-independent) are CORRECT and unchanged. But the specific "evict-ring 28-entry overflow drops 131" cause is UNPROVEN and probably WRONG:
- `rm -rf D` removes the 100 files FIRST, then rmdir's the dir LAST → ino=131's INODE_FREE is the NEWEST ring entry → overflow would KEEP it (drop oldest = files), not drop it. node2 gets the FILES not 131 → inconsistent with simple overflow.
- `mxfs_dlm_note_inode_freed` @ xfs/xfs_inode.c:3499 has NO dir/file guard (publishes ALL frees on the success path). So 131 IS published.
- `EVICT-RING-FLAG ino=131 = 0` on node2 means the CONSUMER's flag action didn't fire, which is gated (xfs_mxfs_dlm.c:11986-11990) on: cached ino=131 live (not RECLAIM/NEW/ISTALE) AND `VFS_I(ip)->i_mode != 0` AND `(uint32_t)VFS_I(ip)->i_generation <= gen`. So node2 may RECEIVE 131's free but NOT flag-stale because its cached i_generation > the freed gen (node2 cached a LATER incarnation than the one just freed), or ino=131 wasn't cached at that instant, or the dispatch was missed. Needs a FAIL-run probe to confirm WHICH.

### WHY the fix is robust regardless: the evict-ring (latent, conditional consumer gate, asymmetric — node1 gets 0 dir-modify) cannot be the correctness mechanism for the reused dir inode. The reliable signal is the on-disk incarnation: on dir-EX acquire (fast AND slow path) and dir lookup/readdir, compare in-core `VFS_I(dp)->i_generation` vs on-disk `di_gen`; mismatch ⇒ inode reused ⇒ force full reload + invalidate cached EX grant + cached dir buffers before any modify. node1 mints a fresh di_gen each round, so node2's stale i_generation mismatches ⇒ reload ⇒ block0→120.

### Next-session probe to pin the exact notification failure (optional — fix doesn't need it): add a capped log in the INODE_FREE consumer (xfs_mxfs_dlm.c ~11981) for ino=131 showing received gen vs in-core i_generation vs the flag conditions; run drc to a FAIL.
Build AFE4E833. Marker NOT written. [[sess-tcp-WHY-merge-misses-it-EX-held-stale-incarnation-fork]]
