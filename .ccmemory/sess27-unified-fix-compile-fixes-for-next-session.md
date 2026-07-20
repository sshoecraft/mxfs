---
name: sess27-unified-fix-compile-fixes-for-next-session
description: sess27: exact compile fixes for the skip-NL-dir unified fix (agbno = fsb % sb_agblocks, no agno needed; avoid XFS_DADDR_TO_FSB/pag_agno). Tree clean…
metadata:
  type: project
---

## sess27 (ccloop 8ddb16a2) — landing the UNIFIED FIX (compile gotchas)

The unified fix (skip-NL-released-DIR-inode sectors in mxfs_submit_partial_inode_write, pal/linux/xfs_buf.c) is fully designed in [[sess27-UNIFIED-bug1-bug2-tension-fix-skip-NL-inodes]]. It REPLACES the b_li_list "write-only-logged" predicate. I implemented it this session but hit 3 compile errors at the relay boundary and reverted to keep the tree BUILDING (0548BE0A clean). The logic is correct; just fix the inode-number computation:

### Compile fixes (this kernel = 6.8 headers, fork of 6.19-rc0 XFS) — in pal/linux/xfs_buf.c these are NOT available:
1. `XFS_DADDR_TO_AGBNO` — does not exist.
2. `XFS_DADDR_TO_FSB` — expands to `xfs_mask32lo` which is undeclared in this file → DO NOT use.
3. `pag->pag_agno` — field renamed in this tree (compiler suggested `pagl_pagino`); the xfs_group abstraction moved it. DO NOT use pag_agno.

### CORRECT computation (no agno needed — global_fsb % agblocks == AG-relative block, since fsb = agno*agblocks + agbno):
```c
struct xfs_perag *pag = bp->b_pag;        /* inode-cluster bufs have b_pag */
xfs_fsblock_t fsb = (xfs_fsblock_t)(bp->b_maps[0].bm_bn >> mp->m_blkbb_log);
xfs_agblock_t agbno = (xfs_agblock_t)(fsb % mp->m_sb.sb_agblocks);
xfs_agino_t   base_agino = (xfs_agino_t)agbno << mp->m_sb.sb_inopblog;
/* then: spin_lock(&pag->pag_ici_lock); for s in 0..ni-1:
   ip = radix_tree_lookup(&pag->pag_ici_root, base_agino + s);
   if (ip && ip->i_dlm_mode == MXFS_LOCK_NL && S_ISDIR(VFS_I(ip)->i_mode)) skip its spi sectors;
   spin_unlock. if (nskip==0) return false; dirty = all & ~skip; ... */
```
`(void)lip;` after removing the b_li_list loop (lip is declared up top — keep or delete its declaration). `all = (total_sects>=64)?~0ULL:((1ULL<<total_sects)-1)`. The downstream run-finder + submit reuse `dirty` + `nslots` unchanged.

### Then test (DEFAULT args, no partial_iwrite override): dir_reuse_coherency → expect P26-IGET-FAIL=0, lookup_fail=0, readdir=200 all rounds. Then full ./run.sh 2 tcp ×3 = 100% = CRITERION MET. Verify cache_coherency/strong_consistency/posix_multi/crash_consistency still pass (the skip is S_ISDIR+NL only = minimal blast radius). If the dir-inode skip alone doesn't fully fix BUG1's file-inode revert (it should: file clusters have no NL dir → whole-write), broaden carefully per the GPT design. Reboot cluster before runs (test2 boot-wedge). FUA DEAD on LIO.
</body>
