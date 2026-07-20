---
name: sess18-FIX-LOCUS-reload-selfskip-sf-block-format-upgrade
description: sess18 PRECISE FIX LOCUS for 2/tcp sf→block transition loss: mxfs_dlm_reload_inode self-skip (xfs_mxfs_dlm.c ~5659-5722) keeps stale SHORTFORM base w…
metadata:
  type: project
---

## sess18 (ccloop 8ddb16a2) — PRECISE code locus + fix plan for the sf→block transition durable loss [[sess18-ROOT-NARROWED-shortform-to-block-transition]].

## LOCUS: mxfs_dlm_reload_inode (xfs/xfs_mxfs_dlm.c ~5490), the SELF-SKIP at ~5659-5722:
```
bool mxfs_dir_disk_superset = S_ISDIR && (post_release || peer_modified_since_load);
if (!mxfs_dir_disk_superset && ip->i_itemp && (IN_AIL||DIRTY||ili_fields||pincount>0)) {
    ... ip->i_dlm_stale=false; return;   // KEEP our in-core (skip reload)
}
```
where `peer_modified_since_load = ip->i_dlm_dir_gen > ip->i_dlm_dir_loaded_gen` (~5639).

## THE BUG: in the FRESH-shortform 2-node concurrent-create race, peer converts the dir sf→block on disk, but THIS node's i_dlm_dir_gen does NOT advance (i_dlm_dir_gen only bumps on OUR BAST-release/reacquire — sess37/43; in the concurrent race there's no clean serialized BAST between the conversion and our next modify). So peer_modified_since_load=FALSE, mxfs_dir_disk_superset=FALSE, and because our shortform dir has in-flight mods (a prior create's logged-unwritten entry), the self-skip KEEPS our stale SHORTFORM base → the create RMWs it → durably writes a SHORTFORM dinode over the peer's BLOCK dir → peer's block entries (and the conversion) clobbered. Corroborated: P62-RELOAD-FORK-SHRINK on failing iters showed `incore_fmt=1(sf) disk_fmt=2(block)` on ino=131; pre-grown-to-block probe = 0/30 loss vs sf-start ~1/8.

## FIX PLAN (cold-path — runs only in reload on stale/reacquire, NOT per-create hot path → RULE-0 safe): a directory NEVER reverts block→shortform in a create-only/growing workload (XFS only does block→sf via xfs_dir2_block_to_sf on REMOVAL below threshold). So **incore format LOCAL(shortform) while DISK dinode format is EXTENTS/BTREE(block) is DEFINITIVE proof the peer converted** — independent of the (laggy) i_dlm_dir_gen counter. Make mxfs_dir_disk_superset ALSO true (force adopt disk, no self-skip) when S_ISDIR && incore if_format==LOCAL && disk dinode di_format >= EXTENTS. Requires reading the disk dinode di_format before the self-skip decision (cheap inode-cluster read; reload already re-reads the cluster buffer at ~5732 — may need to peek di_format earlier, or read di_format via mxfs_inode_disk_* helper).

## TENSION TO HANDLE (why this needs care + a 4-node repro to validate): the self-skip exists to protect THIS node's in-flight (logged-unwritten) work. Forcing disk adoption on sf→block could DROP our pending entry if it isn't on the peer's block image. Two sub-cases: (a) we RELEASED before peer converted → our entry is durable, peer's block includes it, adopt is safe; (b) concurrent, we never released → our pending entry is NOT on disk → naive adopt loses it. For (b) the node must REPLAY its pending dirent onto the adopted block image after reload (a BOUNDED merge, but ONLY in the rare sf→block transition window — NOT the per-create steady-state merge that was perf-doomed [[sess18-merge-perf-doomed-pivot-to-format-transition]]). Since the transition is once-per-dir and early, this is perf-acceptable. ALT: ensure the reload's adopt path already replays in-flight log items (XFS log recovery semantics) — investigate whether adopting disk + keeping the AIL log item double-applies or loses.

## REGRESSION RISK: mxfs_dlm_reload_inode self-skip is HEAVILY layered (sess14/49/58/59 fixes protect unlink/rename in-flight work). A wrong change here regresses unlink_visibility/rename/cross_write_read. Develop on a 4/8-node DETERMINISTIC repro (user guidance), watch those canaries, validate on 2-node (criterion). Instrument first: confirm on a failing iter that the self-skip fires with incore=LOCAL + disk=EXTENTS + peer_modified_since_load=0 (add a one-shot detector reading disk di_format at the self-skip).

## STATE: cluster HEALTHY baseline (dir_merge=0). Marker NOT written. Next: instrument→confirm sub-case→implement format-upgrade-forces-adopt (+replay if needed)→validate. [[sess18-readside-ruled-out-writeside-clobber-confirmed]]
