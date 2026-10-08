---
name: trap-xfs-percpu-free-counters-are-node-local-so-a-peers-frees-never-reach-them
description: TRAP (0.90.104): m_fdblocks/m_icount/m_ifree move only by own transactions; peer frees never land -> false ENOSPC on an empty fs, df split
metadata:
  type: feedback
---

XFS's admission counters (m_free[XC_FREE_BLOCKS], m_icount, m_ifree) are percpu, set from the AG headers at mount, then moved only by THIS node's transaction deltas. In MXFS a peer's frees/allocs never reached them: host A fallocates 6 GiB, host B rm's it, host A is refused ENOSPC forever on an empty fs (tests/pve_freespace_drift.sh reproduces in one round; DF_EACH_ROUND=0 isolates the ENOSPC-retry path). Also: xfs_alloc_read_agf's upstream `atomic64_add(allocbt_blks, &mp->m_allocbt_blks)` runs at EVERY summary rebuild, and MXFS rebuilds at every fresh AG tenure, so "unavailable" space grew per handoff.

Fixed in xfs/xfs_mxfs_sb.c by folding the peer's net change per AG (in-core pagf/pagi + pag_mxfs_ext_* correction) at fresh-tenure rebuild, statfs medium reads (lineage closed + tenure unchanged under pag_dlm_lock), and a bounded-lock ENOSPC sweep.

Lessons:
- Any per-node cached aggregate of on-disk shared state (counters, summaries) drifts unless something folds peer changes in; an AG summary stale while the peer holds the AG is the same bug in the statfs path.
- An unlocked medium read of a peer-held AG lags the peer's LOG, not just its cache: a free that is only in the peer's log is invisible until its AIL pushes (log worker ~30 s). An ENOSPC decision must go through the AG lock so the peer's release drain writes it home.
- pag_dlm_lineage_open is the "this node may have AG changes not yet on the medium" flag; it closes only after the release drain.
- `grep '=p' /proc/dynamic_debug/control` counts 0 even when a format is enabled; check that the lines actually appear instead.
