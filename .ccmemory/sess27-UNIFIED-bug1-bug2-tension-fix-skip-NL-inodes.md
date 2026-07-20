---
name: sess27-UNIFIED-bug1-bug2-tension-fix-skip-NL-inodes
description: sess27 UNIFIED: BUG1(file-inode revert) & BUG2(dir-inode di_size revert) are in TENSION via partial_iwrite. Fix=inode-cluster write that writes OWNED…
metadata:
  type: project
---

## sess27 (ccloop 8ddb16a2) — THE UNIFIED FIX for dir_reuse_coherency 2/tcp

### The two bugs are in TENSION via the partial-inode-write setting
- `partial_iwrite=1` (default, partial writes = write only b_li_list-logged inodes): REVERTS node2's FILE inodes (BUG1, P26-IGET-FAIL: dirent→freed inode) because it skips node2's own freshly-allocated-but-checkpointed inodes. BUT it PROTECTS the shared DIR inode (node1's stale di_size=1 dir inode is NOT logged at write time → skipped → no revert).
- `partial_iwrite=0` (whole-buffer writes): FIXES BUG1 (all node2's file inodes written) BUT REVERTS the shared DIR inode (BUG2): node1 whole-writes its inode cluster containing the dir inode (which node1 cached with stale di_size=1 from a PRIOR tenure, before it released the dir EX to node2) → overwrites node2's durable di_size=2 → the reader's reload reads di_size=1 → 1-block extent map → datascan ndb=1 scanned=100 → misses node2's block-1 entries (proven: [[sess27-BUG2-CRACKED-lookup-reload-stale-1block-extent-map]]).
- So NEITHER setting passes: each fixes one bug and exposes the other. The dir inode (e.g. ino 131) is REUSED+SHARED (rank1 creates it + adds files; rank2 adds files + grows it), so node1's prior-tenure cached copy reverts node2's grow under whole writes.

### THE FIX (GPT design [[sess27-gpt-design-release-drain-is-foundation-unified-root]] applied): inode-cluster write = WRITE OWNED, SKIP PRIOR-TENURE
Rewrite mxfs_submit_partial_inode_write (pal/linux/xfs_buf.c) so it writes EVERY inode sector in the cluster EXCEPT sectors of inodes that are IN-CORE on this node with `i_dlm_mode == MXFS_LOCK_NL` (this node released that inode = prior tenure, a peer may own/have-superseded it). This simultaneously:
- writes node2's OWN held (EX) file inodes even after their log item detaches → fixes BUG1 (no more skip-my-own);
- skips node1's RELEASED (NL) dir inode → node1 can't revert node2's di_size=2 → fixes BUG2;
- preserves sess115 cross-node false-sharing (a peer's inode cached on this node is NL → skipped).
If nothing to skip (no NL inode in the cluster) → return false → normal whole-buffer write.

### Implementation notes / RISKS
- Enumerate the cluster's inodes by NUMBER (the NL ones are NOT on b_li_list): agno = bp->b_pag->pag_agno (inode-cluster bufs have b_pag); agbno = XFS_DADDR_TO_AGBNO(mp, bp->b_maps[0].bm_bn); base_agino = XFS_AGB_TO_AGINO(mp, agbno); for s in 0..ni-1: lookup (base_agino+s) in pag->pag_ici_root under pag_ici_lock (or rcu); if ip && ip->i_dlm_mode==MXFS_LOCK_NL → mark its `spi` sectors skip.
- DO NOT skip an inode that is NOT in-core (we have no NL signal for it; leave it written — owning-cluster assumption).
- sess17 FALSE-POSITIVE WARNING: a freshly-created inode can transiently read i_dlm_mode==0/NL; skipping it would DROP a legit write (corruption, sess23 suppression-was-corruptor class). Guard: only skip if the inode is NL AND not currently flush-locked/logged AND (ideally) born in a prior tenure. Start STRICT: maybe only skip NL inodes whose VFS inode is a DIR (S_ISDIR) — the proven BUG2 victim — to minimize blast radius, then broaden if needed.
- Verify against the WHOLE suite (esp. cache_coherency/strong_consistency/posix_multi which already pass under partial_iwrite=0, and crash_consistency).

### Test plan
1. Implement skip-NL-inode write. 2. dir_reuse with DEFAULT args (no partial_iwrite override) → expect P26-IGET-FAIL=0 AND lookup_fail=0 AND readdir=200 across all 24 rounds. 3. Full ./run.sh 2 tcp ×3 = 100% → criterion MET.
Tree at 0548BE0A (diagnostics + datascan extent-map+scanned probe + partial_iwrite toggle default 1). FUA DEAD (LIO). Reboot cluster before runs (test2 boot-wedge). See [[sess27-PROVEN-root-durable-inode-alloc-revert-not-leafhole-not-fua]].
</body>
