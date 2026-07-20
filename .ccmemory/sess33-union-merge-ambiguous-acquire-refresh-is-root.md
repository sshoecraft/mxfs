---
name: sess33-union-merge-ambiguous-acquire-refresh-is-root
description: sess33 KEY: union-merge (graft disk-only dirents) is FUNDAMENTALLY AMBIGUOUS under dir_reuse's concurrent add+remove — a disk-only dirent is either a…
metadata:
  type: project
---

## sess33 — why write/drain-side merge is a dead end; the root fix is acquire-side refresh

### The loss-write is the EX-release drain's xfs_bwrite of a STALE BASE (PROVEN by P-WMERGE-STACK: mxfs_dir_flush_one_daddr→xfs_bwrite, disk_extra=1). Our in-core dir block was missing a peer's prior-tenure add (disk_extra>0) when we RMW'd our this-tenure adds onto it; the drain writes {stale_base ∪ our_adds} − {peer_add} → reverts the peer's dirent = 799.

### WHY write/drain-side UNION-MERGE cannot fix it (fundamental, not a bug):
The dir_reuse_coherency test does concurrent CREATE **and REMOVE** (rm-rf + recreate each round). At a write, a "disk-only dirent" (present on disk, absent in-core) is AMBIGUOUS:
 - it could be a PEER's ADD we never saw (correct action: graft it in = keep it), OR
 - it could be OUR REMOVE that the peer's disk copy hasn't caught up to yet (correct action: do NOT graft = let our remove stand).
NAME (or inumber) alone cannot distinguish these. The existing `mxfs_dir3_data_writemerge` grafts disk-only-by-name → resurrects removed dirents → readdir=803 over-count + leaf desync (REFUTED [[sess33-REFUTED-dir-write-merge-overgrafts-803]]). Any write-side merge has this ambiguity. So merge/graft is a DEAD END.

### THE ROOT FIX = acquire-side stale-base refresh (make disk_extra=0 at the drain):
We hold EX for the whole tenure, so the peer's missing dirent (disk_extra) was added in a PRIOR tenure (before our acquire). The acquire path MUST FUA-refresh every dir DATA block from the coherent LUN BEFORE the first RMW, so our adds graft onto the peer's CURRENT image. Then our block is a true superset (disk_extra=0), the drain write is correct, no merge, no ambiguity.
The refresh machinery EXISTS (mxfs_dir_evict_data_blocks soft-clear + xfs_da_read_buf gen-invalidation, gated by i_dlm_dir_gen / epoch / owned_ex) but MISSES this block. NEXT SESSION: instrument WHY a block stays a stale base across our acquire (disk_extra>0 at the drain): is i_dlm_dir_gen not bumping on the relevant handoff? is the read-path invalidation gated off under ILOCK_EXCL (owned_ex) on the modify path? is the bmap stale so the block isn't enumerated? Add a probe at the FIRST RMW of each block (P-RMWBASE: disk_extra of the base right before addname) to catch the stale base at its source, then fix the refresh to cover it. This is the sess20-26 dir-gen/epoch coherency family.

### Build 275EF4D4 keeper-equiv (all fix params default 0). [[sess33-HEAD-handoff]]
