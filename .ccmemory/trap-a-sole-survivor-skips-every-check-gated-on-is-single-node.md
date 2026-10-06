---
name: trap-a-sole-survivor-skips-every-check-gated-on-is-single-node
description: TRAP (0.90.47): !mxfs_v5_dlm_is_single_node gates skip peer-state checks on the survivor of 2; a dead peer's files opened EISDIR. Test from the survi…
metadata:
  type: feedback
---

**What bit us.** `xfs_lookup`'s dirent-type check (INODE-REUSE-EVICT / P95-TYPEFLIP-RELOAD) was gated on
`!mxfs_v5_dlm_is_single_node()`. The survivor of a two-node cluster is single-node the moment its peer
is fenced, but its inode cache still holds shells cached while the peer lived. On
`path_fence_degraded` (2/net/mesh/mpath) the survivor opened 18 of 1256 of the killed node's fsynced
files as directories (EISDIR) 1.4 s after recovery completed; all read fine minutes later, so only a
row that reads the dead node's files *from the survivor, immediately* sees it.

**Why it hid.** At 3+ nodes survivors are never single-node. No earlier row read a dead node's
files from the lone survivor right after recovery. Direct-attach boards pass without it.

**How to apply.**
- A guard that skips peer-state validation must ask "has this mount ever had a peer"
  (`!is_single_node || mxfs_v5_dlm_sole_survivor`), not "is it multi-node now". ~80 guards in
  `xfs/xfs_inode.c` and `xfs/xfs_icache.c` still use the plain predicate; `MXFS_SOLE_SKIP_NOTE`
  (P952-SOLE-SKIP) is the census of the ones a survivor reaches.
- When a 2-node death row fails on the survivor with a transient wrong answer, check that gate first.
- `pathload.py verify` now prints per-file detail (`read_error=` vs `content`); read it before
  deciding whether a "bad" file is corruption or a refused read.
