---
name: sess48-DECISIVE-loss-is-reader-extentmap-staleness-not-writer
description: sess48(ccloop) DECISIVE: 8/tcp dir_reuse loss is READER-side extent-map staleness, NOT writer durability. dir_relverify=1 run: peers missed node8's E…
metadata:
  type: project
---

## sess48 (ccloop 4cb2d0a2) DECISIVE — the 8/tcp loss is READER-SIDE

### The decisive run (build FD6E4882, dir_relverify=1 lightweight writer-verify)
Round 14: test1 & test4 readdir=726/800, **missing ALL ~74 of node8's entries**
(node8_f1..f50 + node8_f*.md5). test8 (the writer) RDMISS=0 (sees its own entries fine).
Writer-side verify: **DIRREL_DIFFERS=0, P25-RELVERIFY-MISMATCH=0** — i.e. node8's blocks ARE
durable on the platter (in-core==disk at node8's release). dir_relverify is read-only
(diagnostic; line 1315/1328) — it only perturbs TIMING, exposing the MASS variant.

### CONCLUSION (writer-vs-reader split RESOLVED)
The durable lost-update is **NOT a writer release-durability gap** (writer verify clean +
writer node sees its data). It is **READER-side**: peers' in-core view is STALE and misses a
peer's just-grown dir blocks. The MASS variant = a peer's whole grow (node8's ~2 data blocks)
absent from readers' EXTENT MAP → readdir skips those blocks → all entries in them vanish.
The single-dirent variant (~1-2/24) is the same mechanism at the edge (one block/entry).
Matches the DABUF_MAP_HOLE storm (reader leaf refs blocks not in its stale extent map) and the
sess96 note ("the evict+reread does NOT reliably pull a peer's just-committed dir block").

### ROOT (to fix): reader dir EXTENT-MAP / block reload on handoff is incomplete
After a peer grows the dir + hands off EX, the reader must reload i_df (extent map) to include
the peer's new blocks AND cold-read those blocks. The reload (mxfs_dlm_reload_inode, triggered
by dir_gen>loaded_gen at the readdir/lookup/modify refresh) either does NOT fire for the reader
or reads a stale dinode. NEXT: probe at readdir for the storm dir — FUA-read on-disk
di_nextents vs in-core i_df.if_nextents; if in-core < disk → stale map not reloaded (proves
the reload gap). Then fix: force a reliable extent-map reload on every cross-node handoff
(grant_gen-based, like dir_grant_evict) BEFORE readdir/lookup, reading the durable dinode.

### Tools/state
Build FD6E4882 = 237F937D (config #1) + extended P-DIRREL-DIFFERS gate to also fire on the
existing dir_relverify param (lightweight writer-verify, no dirwr flood). Repro:
tests/drc_dirtyskip.sh "dir_relverify=1" 24 8. See [[sess48-FINAL-state-extentmap-staleness-is-next-root]].
</body>
