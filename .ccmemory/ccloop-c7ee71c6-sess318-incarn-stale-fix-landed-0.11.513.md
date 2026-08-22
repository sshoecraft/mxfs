---
name: ccloop-c7ee71c6-sess318-incarn-stale-fix-landed-0.11.513
description: sess318: D-INCARN-STALE-SHELL-UNGATED-FILE-READS-512 ledgered (#89) + full ruling fix set LANDED+BUILT 0.11.513 sv C774FEA614A2BB1AE74286F — NOT depl…
metadata:
  type: project
---

# sess318 — INCARN_STALE containment landed (0.11.513)

Ledgered the sess316/317 zsl regression as
D-INCARN-STALE-SHELL-UNGATED-FILE-READS-512 (critical). Took the RULE-5
consult (see ccloop-c7ee71c6-sess318-GPT-ruling-incarn-stale-fix-shape) and
landed the full required set in one build:

- xfs_inode.h: mxfs_inode_incarn_estale() central -ESTALE gate.
- xfs_inode.c retire arm: d_mark_dontcache (root fix — last iput now evicts
  the hashed shell) + invalidate_inode_pages2 (REG) + i_count/i_state/nlink
  in P34H-POISON-EVICT; FAIL CLOSED after 4 tries (P34H-POISON-UNRETIRED,
  -ESTALE via out_free_name).
- xfs_file.c: gates on open/read_iter/write_iter/splice_read/fallocate/
  remap_range/mmap(_prepare); SIGBUS on fault/page_mkwrite/pfn_mkwrite.
- xfs_iops.c getattr gate; xfs_super.c d_revalidate: INCARN_STALE now
  invalidates the dentry (was blessed in poison→first-relookup window).

Build: clean make, 0.11.513 sv C774FEA614A2BB1AE74286F. NOT deployed, NOT
verified. Next: deploy knob-on, zsl 2x (~60s/run+slack), then knob=0
regression board + full board. RULE-4 residual: .511-vs-.512 delta (who
holds the shell) — answered by the new i_count print on next occurrence.
