---
name: sess61-DECISIVE-dirty-bufgen0-divergent-block0-kept-by-dirty-guard
description: sess61 DECISIVE: dir_reuse loss = DIRTY block0 buffer with bufgen=0 (stale tenure < i_dlm_dir_gen) materialized on a stale base, kept by the dirty-pr…
metadata:
  type: project
---

## sess61 DECISIVE buffer-level evidence — the clobber buffer

Build E658513F. P61-BLK0 (xfs_da_btree.c after block0 read) now logs the buffer's
b_mxfs_dir_gen (bufgen), b_mxfs_dir_incarn, dirty/inail/pin. At CREATE time
(comm=dd, dlm_mode=5 EX), the stale-base reads (in-core block0 behind disk):

  test4: core_node1=0 disk_node1=84 dir_gen=20 bufgen=0 incarn=3676479299 dirty=1 inail=0 pin=0
  test4: core_node1=0 disk_node1=88 dir_gen=34 bufgen=0 dirty=1 inail=0 pin=0
  test4: core_node1=0 disk_node1=63 dir_gen=24 bufgen=0 dirty=1 inail=0 pin=0
  test2: core_node1=0 disk_node1=8  dlm_mode=5

DECISIVE: the clobbering in-core block0 buffer is **DIRTY (dirty=1), bufgen=0**
while the inode i_dlm_dir_gen=20/24/34. So bufgen(0) < i_dlm_dir_gen — the MXFS
tenure-gen mechanism ALREADY FLAGS this buffer stale, but the read-hook +
mxfs_dir_evict_data_blocks **KEEP it because it is DIRTY** (undurable guard:
dirty/pinned/in-AIL kept to protect own un-checkpointed work). The buffer is
EMPTY of node1 entries (core=0) but disk has 63-88 — same incarnation, same
daddr, DISJOINT content (node4's own entries vs peers' node1 entries). Each node
independently MATERIALIZED block0 (data_init/conversion) from its own base; the
last writer's block0 wins on disk, clobbering the rest.

So the P60-LBMAP "daddrs agree, not a split" was about the EXTENT MAP; the CONTENT
at that shared daddr DIVERGES per node = the sess36/sess42 divergent-block0 root,
now precisely characterized at 4 nodes at the BUFFER level.

## ROOT (GPT-5.5 case A, confirmed) + WHY existing machinery misses it
A DIRTY buffer with a STALE tenure-gen (bufgen < i_dlm_dir_gen) is kept by the
dirty-protection guard. GPT's invariant: "dirty CURRENT-tenure buffers are
protected; dirty OLD-tenure (stale-gen) buffers are corruption — must NOT reach
disk." The gen bumps on slow-path EX re-acquire (xfs_mxfs_dlm.c:10161) and the
evict drops CLEAN stale buffers + sess41 refreshes in-AIL-clean ones, but a
DIRTY stale-tenure buffer (bufgen=0, freshly materialized on a stale base) slips
through.

## FIX DIRECTION (GPT-5.5, RULE-4 next)
GPT's recommended SAFE fix (do NOT union-merge; do NOT drop a dirty buffer joined
to the live trans = iflush-corruption shutdown risk):
  PREVENT block0 from being materialized/dirtied on a stale base.
Two options:
 (1) Tenure-cookie invariant: before logging/dirtying a dir buffer require
     bufgen == i_dlm_dir_gen; if stale-and-CLEAN invalidate+reread (already
     done); the failing case is the buffer being freshly INIT'd (bufgen=0)
     materialized on a stale base — so guard the MATERIALIZATION: in
     xfs_dir3_data_init / the sf->block + block->leaf grow for logical block 0
     of a multinode dir, FUA-check disk; if disk already holds a valid
     same-incarnation populated dir block at that daddr, ADOPT disk (read it in)
     instead of zeroing (sess36/sess42 "data_init zeroes live block0" /
     "second converter must adopt peer's block0").
 (2) Verify it is NOT a DLM double-grant first (GPT case B): add a DLM-master
     EX-overlap assert (never >1 EX owner) + per-buffer tenure cookie checked at
     first dirty. If two nodes hold EX concurrently, no dir-layer fix works
     (sess49 TCP double-grant residual). bufgen=0+dirty+disjoint content is
     consistent with A (independent materialization), but B not yet excluded.

My sess61 mxfs_dir_modify_adopt_disk_format() fix (format/nextents/size compare)
was REFUTED: in-core metadata is never behind disk under EX (P61-ADOPT-CHK
incore_fmt=2 disk_fmt=2 always). The staleness is CONTENT-level in the data
buffer, not the inode fork — so a metadata compare can't see it. KEEP the helper
disabled or repurpose; it never fires.

Instrumentation in tree: P61-BLK0 (xfs_da_btree.c, in-core vs FUA disk node1
count + bufgen/incarn/dirty/inail/pin), P61-ADOPT-CHK/DISK (xfs_mxfs_dlm.c),
per-failure dmesg snapshot (tests/suite/dir_reuse_coherency.sh ->
/root/drc_fail_r${round}_rank${R}.dmesg). See
[[sess61-REFINED-content-level-stale-block0-buffer-RMW-clobber]],
[[sess36-PROVEN-datainit-zeroes-live-block0-root]],
[[sess42-DECISIVE-clean-round19-block0-double-alloc-at-sf-to-block]].</body>
