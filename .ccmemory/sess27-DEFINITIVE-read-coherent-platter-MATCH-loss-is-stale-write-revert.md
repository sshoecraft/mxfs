---
name: sess27-DEFINITIVE-read-coherent-platter-MATCH-loss-is-stale-write-revert
description: sess27(ccloop) DEFINITIVE write-side proof: P28-PLATTER probe (FUA-read platter vs in-core buffer at every addname) = 76 MATCH / 0 DIFFER. The addnam…
metadata:
  type: project
---

## sess27 DEFINITIVE — the read is coherent; the PLATTER itself reverts (stale write)

### The decisive probe (build 164A6D5D, param dir_addname_epoch_refresh=1)
P28-PLATTER: at every node-format addname data-block pick (ino<=256), FUA-read the SAME daddr from the platter and memcmp vs the returned in-core buffer. Result on test1: **76 MATCH, 0 DIFFER**. The in-core buffer the addname uses to choose a free slot ALWAYS equals the platter. Combined with P28-CHECK (b_epoch==valid_epoch==master always → block fresh-FUA-read every addname).

### Conclusion (rules out read-side entirely)
The clobberer's bestfree reflects the PLATTER exactly. It picks off=1280 because off=1280 IS free on the platter at read time → the victim's dirent (node5_f46.md5) is NOT on the platter then. Since the victim DID add+flush it (sess27 P11-DATALOG/RELFLUSH showed it present+flushed), the platter slot was subsequently REVERTED to free by a STALE WRITE before the clobberer read. The READ is innocent (coherent); the bug is a WRITE that puts a stale (pre-victim-add) image of the block onto the platter — an ABA/stale-RMW writeback. force_coherent (read-side) made it worse, dirskip=1 (write-suppress) didn't help, dir_release_fua_write didn't help — consistent: it's a stale write that the current suppression predicates don't catch.

### REFUTED this session (cumulative): read-side staleness (force_coherent), the epoch/cache-hit-staleness model (P28 fix, inert — block is fresh-read), 5 mitigation levers. The loss is a WRITE-side stale-image revert of a dir data block on the shared LUN, with a fully coherent read path.

### NEXT (sess28): catch the reverting WRITE (RULE 4)
Instrument the dir DATA-block bio WRITE chokepoint (pal/linux/xfs_buf.c, mxfs_submit_io / where mxfs_buf_xfsaild_skip_dir_write runs) for NODE-format data blocks (xfs_dir3_data_buf_ops; P-WRACT is block-format-only, USELESS here): for ino<=256, log per write the daddr + #live dirents (walk the block: freetag==0xffff=free else dirent, mirror xfs_dir2_data.c:833-846) + comm + dlm_mode + b_mxfs_dir_gen/epoch + realns. Cross-node by realns: find the write to the victim's daddr whose live-dirent set REVERTS (drops the victim, count goes down on a create-only phase) — that write's mode/owner/gen identifies the stale writer. Likely a node that committed an OLDER image of the block (RMW on a base read before the victim's add, then its async xfsaild/release-drain writes it AFTER the victim's add landed). Fix probably: suppress/repair a dir-data write whose in-core image is a STALE SUBSET of the current platter for the same incarnation (a content-superset write-guard, NOT count) — sess22 CLAUDE.md head already flagged this exact design ("content-superset check at the dir-DATA-block bio write chokepoint"). Build 164A6D5D keeper-equiv at default (FUA probe + epoch fix both gated behind dir_addname_epoch_refresh=1). Cluster clean. See [[sess27-CORRECTION-block-is-fresh-read-not-cachehit-epoch-fix-refuted]] [[sess27-SMOKINGGUN-intrablock-slot-collision-off1280-node7-overwrites-node5]].
