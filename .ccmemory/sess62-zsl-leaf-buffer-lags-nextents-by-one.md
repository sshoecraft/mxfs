---
name: sess62-zsl-leaf-buffer-lags-nextents-by-one
description: sess62 PINNED: zsl skew = the bmbt leaf written carries numrecs=N-1 while di_nextents/if_nextents=N. Force-flushing the leaf (P60-BMBTWRITE landed) s…
metadata:
  type: project
---

## sess62 (ccloop 14d31183) — zsl skew PINNED to leaf-numrecs = if_nextents - 1

Supersedes the "leaf write never submitted" framing in
[[sess62-zsl-bmbt-leaf-write-never-submitted-confirmed]]. Builds confirm the bio
DOES land — it just lands a SHORT leaf. Criterion STILL FAILS. Marker NOT written.
Current build **663F1716** (force-write + always-on P62-IFLUSH-FORCE probe).

### DECISIVE EVIDENCE (build 663F1716, always-on probes)
On the EX-holder/writer nodes (test4, test6) at the moment xfs_iflush(131) runs:
- `P62-IFLUSH-FORCE ino=131 if_nextents=15 nheld=1 wrote=1` — my force-write found
  ONE cached bmbt leaf and xfs_bwrote it.
- `P60-BMBTWRITE owner=131 daddr=25048232 lvl=0 numrecs=14 incore=1 mode=5` — the bio
  that landed wrote a leaf with **numrecs=14** while **if_nextents=15**.
=> The on-disk leaf record sum LAGS di_nextents (=if_nextents) BY ONE. Flushing the
leaf does NOT help because the leaf buffer itself is short. The di_nextents written
(=if_nextents=15) is structurally ahead of the leaf content (14).

### Two live sub-hypotheses for WHY leaf < if_nextents (next session pin these)
1. **Post-split 2nd leaf not flushed/cached.** broot_lvl=1 (root over leaves). A leaf
   split allocates a NEW leaf block; di/broot updated to point to leaf0+leaf1 (sum=15),
   but only leaf0 (14 recs) is in this node's cache (nheld=1, my owner-walk found 1).
   The 15th record lives in leaf1 which is never destaged (newly allocated → maybe on
   pag_mxfs_alloc_buflist w/ _XBF_DELWRI_Q, the CLAUDE.md collision; or not yet in
   pag_bcache). Reloader cold-reads leaf0(14)+leaf1(stale/empty)=loaded short.
2. **In-core iext ahead of bmbt** (SIG3 corroborates: xfs_bmbt_lookup_eq can't find an
   in-core extent in the bmbt). if_nextents (iext skiplist count) advanced without a
   matching xfs_btree_insert into a leaf buffer. Suspect MXFS ILOCK-drop-across-CAW-poll
   in the dir-block alloc (xfs_bmap_btalloc) splitting the iext-insert from the
   btree-insert, OR the EXTENTS->BTREE conversion.
NEXT PROBE: in xfs_bmap_add_extent_hole_real (and/or after xfs_iread_extents), for
ino=131, log if_nextents vs SUM of ALL owner-matched level-0 leaf numrecs across the
buffer cache (not just one leaf). If sum==if_nextents but my force-write only flushed
1 of 2 leaves -> hypothesis 1 (find why leaf1 isn't flushed/cached). If sum<if_nextents
-> hypothesis 2 (iext ahead of bmbt; instrument the insert lockstep).

### Other confirmed facts
- xfs_iflush(131) runs ONLY on the EX-holder (test4/test6 here); other nodes never
  flush 131 (expected). So di=N is published by the holder's iflush — my hook covers it.
- total_fs_silent is variance-dominated (1600/375/1600/1600/1600 across builds) — judge
  fixes by per-SIGNATURE dmesg counts (SIG1 ir.loaded), NOT the RESULT line.
- Reload bmbt-eviction (in mxfs_dlm_reload_inode ~L5152) proved skew is ON-DISK; KEEP.

### Code in build 663F1716 (re-evaluate)
- mxfs_iflush_force_bmbt_durable (xfs_mxfs_dlm.c): now UNCONDITIONALLY xfs_bwrites every
  cached XBF_DONE bmbt block owned by ip, from xfs_iflush before xfs_inode_to_disk.
  Lands the leaf bio but writes the SHORT leaf — INEFFECTIVE alone. P62-IFLUSH-FORCE log
  now ALWAYS-ON (multinode). Consider: also flush the post-split sibling leaf, or fix
  the iext/bmbt lockstep so the leaf isn't short.
- P62-RELOAD-FORK-SHRINK probe + reload bmbt-evict: KEEP.

### INFRA
virsh -c qemu:///system destroy+start ALL 16, sleep 40, verify 16/16. Criterion:
./tests/criteria/zero_silent_loss.sh --iters 1 --dpn 100 --mode 1 (nohup, poll ~480s).
Grep dmesg: 'ir.loaded != ifp' (SIG1), 'P60-BMBTWRITE owner=131' (leaf bio numrecs),
'P62-IFLUSH-FORCE ino=131' (nheld/wrote), 'P59-IREAD-MISMATCH' (loaded vs nextents).
