---
name: sess127-root-fix-durable-before-visible-new-inode-iget-coord
description: sess127 ROOT FIX (build 1C7F8320): new-inode durable-before-visible gap; coordinated PR+reload at iget cache-miss free-state ENOENT. unlink_visibilit…
metadata:
  type: project
---

## sess127 — TRUE ROOT of unlink_visibility found + FIXED (build `1C7F83208FE0FB210B31100`)

### The proven chain (RULE 4, deterministic repro)
`tests/repro_uv_create_race.sh` (NEW, in-tree): 4 nodes concurrently `mkdir -p /mnt/shared/.mxfs_test` + 30 creates each. On builds before the fix this reproduced 100%: every mkdir-race LOSER got `mkdir: cannot create directory: File exists` (mkdir -p FAILS = POSIX violation) and 0 creates.

Decisive probe: ungated **P-IGET-ENOENT** (was `mxfs_instr_enabled`-gated at xfs_icache.c:653 — invisible under instr=0 for many sessions!) fired on all losers with **`fua_disk_mode=0x0`** = the winner's new dir dinode reads FREE straight off the platter.

**Mechanism**: creator commits dirent+child-dinode in ONE txn. Parent-dir BAST release flushes the PARENT durable (loser sees the dirent) but NOT the new CHILD dinode (sits in creator's AIL). sess44 deferred-publish = creator's child-EX is LOCAL (no CAW slot), and xfs_lookup igets with lock_flags=0 → loser performs NO inode-DLM acquire → nothing ever BASTs the creator to flush → loser reads free dinode → check_free_state ENOENT for a name that exists. Downstream: pre-verify counts 60/120; EEXIST-loser orphan path + double-allocation pressure → `xfs_difree_inobt i != 1` double-free shutdown on ALL 4 nodes (seen after run 3).

### THE FIX (xfs/xfs_icache.c, xfs_iget_cache_miss, at check_free_state)
On `-ENOENT && !tp && !dlm_acquired && !XFS_IGET_CREATE && mode==0 && multi-node`: ONE coordinated
`mxfs_dlm_ilock_begin(ip, MXFS_LOCK_PR)` + `mxfs_dlm_reload_inode` + `ilock_end`, then re-run
check_free_state. The PR acquire BASTs the creator (its publish-on-dir-BAST EX), whose sess38
writer-flush release path makes the dinode durable; reload reads the real mode. Genuinely-free
inode = uncontended acquire (~1 CAW RTT) + legit ENOENT. Probe `P127-IGET-COORD` logs post_mode.
This is the sess40 "Type-A reuse_dlm" dance relocated to the PROVEN site (cache-MISS) and ungated.

### Also this session (carried in build)
1. **REMOVED sess126's harmful Phase-1** (`dp->i_dlm_stale=true` in xfs_create EEXIST loser branch) — PROVEN to reintroduce the sess91 stuck-stale d_revalidate thrash (8× P-DREVAL-STALEFLAG, walk dies at parent component). Replaced with probe `P127-EEXIST-LOSER`. The loser's parent is already fresh (its own mkdir EX reloads it).
2. KEPT sess126 Phase-2 (dirs skip d_revalidate affine fast-path).
3. NEW probe `P127-DIRMISS` in xfs_lookup (ungated, miss-only): dumps in-core shortform names at any multi-node dir-lookup ENOENT.
4. UNGATED `P-IGET-ENOENT` (keep ungated — it was the multi-session blind spot).

### Results
- repro r4: ALL 4 nodes mkdir rc=0, 30/30 creates each, 120 files, ~1s/node.
- `test_unlink_visibility` (4 nodes): **PASS in 33s** (was FAIL at 132-370s for many sessions).

### Refuted along the way (don't revisit)
- "loser's cached parent dir is stale" (sess126 premise) — FALSE, EX-reload makes it fresh.
- "PR-storm starvation of dir EX is the proximate cause" — the 121s EX hold was real but secondary; creates failed in the first 2s regardless.
- shared-dir lock contention as root — after the iget fix the whole 4-node create+delete test runs in 33s.

### NEXT
Full `tests/criteria/cache_coherency.sh --nodes 4`, then watch rename_visibility/cross_write_read for regressions from the new coordinated acquire (cost confined to dirent-resolves-but-inode-free anomaly path; verify-gone phase of unlink does hit it per stale dirents — watch timing). Then full verify_ship.sh.

Related: [[sess127-shared-dir-create-starvation-after-removing-harmful-stale-flag]] [[sess126-mkdir-race-loser-cannot-create-poslx-root]] [[sess107_lessons]] [[sess40_lessons]] [[sess44_lessons]]
