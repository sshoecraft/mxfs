---
name: sess27-DECISIVE-loss-is-write-side-force-coherent-doesnt-help
description: sess27(ccloop) DECISIVE: dir_reuse 8/tcp loss is WRITE-SIDE, not read-side. force_coherent=1 (re-read every clean dir block from platter on every rea…
metadata:
  type: project
---

## sess27 — the lost dirent is WRITE-SIDE (force_coherent refutes read-side)

### The decisive experiment
Config `dir_gen_per_handoff=1 dir_modify_extent_adopt=1 force_coherent=1`. force_coherent (xfs_da_btree.c:3365, P0-FCOH-DIRINVAL) forces EVERY dir block read to invalidate+re-read from the platter (FUA), bypassing the gen check — maximal read-side coherency. Result: **FAIL round 1, readdir=788/800 (12 lost), wall=497s** (slow due to per-read FUA).

### Conclusion
Re-reading the platter on every read does NOT recover the lost entries → they are genuinely NOT on the platter. This is consistent with the verify-side DSCAN-MISS (entry absent in all on-disk data blocks). Therefore the dir_reuse residual is a **WRITE-SIDE durable loss** — the entry is committed in-core/log by its creator but never lands durably on the shared LUN (or is overwritten by a stale write) — NOT a read-side stale-base RMW.

### This unifies the sess27 refutations
Read-side mechanisms can't be the root: P60-GENMATCH-STALE=0, DIR-STALE-SKIP=0, all P-TDS-RMW stale_base=0, and now force_coherent=1 still fails. The write-side coverage gap (P11-FLUSH-UNCACHED, xfs_mxfs_dlm.c:1599-1625, dir data block UNCACHED at release-flush → skipped as 'already on disk') and/or a stale ABA writeback (mxfs_buf_xfsaild_skip_dir_write) are the remaining suspects. [[sess27-LEAD-P11-flush-uncached-release-drain-coverage-gap-create-path]] [[sess27-REFUTED-four-mechanisms-residual-is-undetectable-content-lostupdate]]

### NEXT (sess28) — write-side proof + fix (RULE 4)
1. PROVE which write loses the entry: instrument the dir DATA-block bio WRITE chokepoint (pal/linux/xfs_buf.c, where mxfs_buf_xfsaild_skip_dir_write runs) to log, per node-format data-block write (xfs_dir3_data_buf_ops, NOT just block-format — P-WRACT only covers block-format), a content fingerprint or the set of inumbers present, gated to ino<=256. Find the write where the lost entry's block goes from present→absent (an ABA writeback of a stale image), or confirm the entry's block was never written (P11 uncached-skip).
2. Likely fix sites: (a) P11 uncached-skip — don't treat uncached as durable; (b) extend mxfs_buf_xfsaild_skip_dir_write / the dir-data-durable release loop to cover the missing block; (c) the dir is fmt=2 EXTENTS, node-format (data + leaf + free blocks across multiple AGs).
3. Build/keeper unchanged: 965BDBD3. Working modargs: dir_gen_per_handoff=1 dir_modify_extent_adopt=1. Cluster left clean.
