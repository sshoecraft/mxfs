---
name: sess60-zsl-evict-gate-fix-and-stale-leafwrite-residual
description: sess60: evict-gate fix (8E495999, KEEP) stops iext-loaded leaf revert. Residual: on-disk dinode=N/leaf=N-1 still via a stale leaf WRITE clobber (P60…
metadata:
  type: project
---

## sess60 — evict-gate FIX landed; residual = stale leaf-WRITE clobber

Builds on [[sess60-zsl-writer-releases-inconsistent-dinode-bmbt]].
Current build **8E495999** (= 4AF64BDF enhanced P60-RELAUDIT + the evict-gate
fix + the P60 xfsaild-skip-bmbt guard that never fires).

### FIX THAT WORKED (KEEP) — evict-gate on need_iread
`mxfs_dir_drain_evict_data_blocks` (xfs_mxfs_dlm.c ~1685) called
`mxfs_dir_evict_bmbt_blocks(ip)` UNCONDITIONALLY for BTREE dirs. P60-RELAUDIT
proved that evicting (cold-re-reading) a bmbt leaf while the in-core iext tree
is LOADED (need_iread=0) REVERTS the leaf buffer to its stale on-disk image,
diverging it from the authoritative iext tree (measured `di=15 iext=15
leaf=14`).  FIX: only evict when `xfs_need_iread_extents(&ip->i_df)` is true
(extents dropped → cold-read repopulates coherently); when extents are loaded
the iext tree is authoritative, nothing to evict.  Preserves sess59 (its
stale-child corruption only manifests while READING extents = need_iread=1).
RESULT: the `iext=N leaf=N-1 need_iread=0` corruptor is GONE — that case now
audits `di=15 iext=15 leafsum=15 ok`.

### RESIDUAL (still FAIL, silent=1600, FS still shuts down)
Enhanced P60-RELAUDIT (fires ONLY in BAST-release drain) after the fix:
```
11×  di=18 iext=0  need_iread=1 leafsum=17 nleaves=1 mode=0 INCONSISTENT
 5×  di=18 iext=0  need_iread=1 leafsum=0  nleaves=0 mode=0 ok (vacuous)
 1×  di=15 iext=15 need_iread=0 leafsum=15 nleaves=1 mode=0 ok  (fixed case)
```
All INCONSISTENT cases are now need_iread=1 (extents NOT loaded) = RELOADING
nodes OBSERVING an already-inconsistent on-disk pair (disk dinode di=18, disk
leaf=17). mode=0 (NL) at audit — release bookkeeping sets i_dlm_mode=NL before
the durable drain. IREAD-MISMATCH still storms (test4/6/9/13/15: 80+ each) →
shutdown → silent=1600 cascade. Off-by-ONE persists (di=N, leaf=N-1, the LAST
extent).

### NEXT HYPOTHESIS (RULE 4) — stale leaf WRITE clobber
The node that grows di 17→18 has iext=18/leaf=18 in-core (consistent now).
Disk ends di=18/leaf=17 ⇒ a STALE 17-record leaf write clobbered the disk
18-leaf in the coherent SCST cache. The sess60 P60 xfsaild-skip-bmbt guard did
NOT fire (P60=0) — likely because the clobbering node either (a) still holds
the dir EX (i_dlm_mode!=NL) when its xfsaild pushes the stale leaf, or (b) the
owner inode ino=131 is NOT in-core (reclaimed) at push time, so P60's
"in-core dir + NL" predicate excludes it, or (c) the stale write is via the
release-drain xfs_bwrite (bmbt_scan flush of a dirty stale leaf), not xfsaild.
NEXT: add a probe that logs EVERY bmbt-leaf WRITE for ino=131 (in
mxfs_dir_bmbt_scan flush xfs_bwrite AND xfsaild iop_push) with numrecs +
owner hold-state (in-core? i_dlm_mode?), to catch the node writing leaf=17.
Then scope the skip/interlock to that path.

### Builds this session (chronological)
B24B321B(base) → 16FC7EC9(bmbt-FUA, inert/reverted: fua_disable=1) →
FD606B66(P60 xfsaild-skip-bmbt, never fires) → 503B10EC(P60-RELAUDIT) →
4AF64BDF(RELAUDIT+iext/need_iread/daddr/mode) → **8E495999(evict-gate FIX)**.

### INFRA reminder
Each shutdown run wedges ~8 nodes (umount D-state); virsh destroy+start them,
~12s to recover all 16 + NFS + module. Run the criterion via nohup>log, poll
≥480s. Outer timeout <480s truncates into a fake INFRA fail.
</body>
