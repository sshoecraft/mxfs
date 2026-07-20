---
name: sess31-FACEB-FIXED-p116-grant-held-discriminator
description: sess31 FIX (build 5E706CBF, KEEP): dir_reuse FACE B (inode-revert/IGET-FAIL) FIXED. P116 self-clobber guard now keeps in-core when DLM grant held (i_…
metadata:
  type: project
---

## sess31 (ccloop 8ddb16a2) — dir_reuse_coherency 2/tcp FACE B FIXED

### FACE B = inode-revert / P26-IGET-FAIL / lookup_fail (one of 3+ intermittent faces)
A dirent points to inode X; iget(X) returns -ENOENT because in-core X mode==0, even though the coherent medium (cached buffer + FUA) shows X LIVE (0x81a4). PROVEN this session via two new detectors:
- **P31B-RELOAD-BUF** (xfs_mxfs_dlm.c, after the reload buffer read ~5990): for an in-core-FREE non-dir reload, logs reload's buffer dinode vs a coherent plain-read. Showed `BUF[mode=0x0 gen=G] COH[mode=0x0 gen=G]` then later `P-IGET-ENOENT cached_disk_mode=0x81a4` — SAME gen G across free+live = the node's OWN inode (sess28 gen fix already present, so RESURRECT-SKIP no longer the cause; gens match).
- The revert is **P-RELOAD-IOPS-REWIRE old_ifmt=0100000 new_mode=00**: a reload ADOPTS the stale-free on-disk image and reverts the node's OWN live inode to free in-core.

### Why the existing sess116 guard missed it
`P116-RELOAD-SELFCLOBBER-SKIP` (xfs_mxfs_dlm.c ~6276) kept the in-core inode (disk_mode==0, incore_mode!=0) ONLY when DIRTY (pin/ili_fields/in_AIL). By the VERIFY phase the node's own just-created file is CHECKPOINTED (clean) → guard fell through → reload adopted disk-free → self-clobber.

### THE FIX (build 5E706CBF, KEEP) — DLM grant ownership, not dirtiness
In the P116 block add `sc_grant_held = (ip->i_dlm_mode != MXFS_LOCK_NL)` and keep when `sc_dirty || sc_grant_held`. Per the i_dlm_epoch invariant (xfs_inode.h): while i_dlm_mode != NL the on-disk grant is HELD, so NO peer can have modified/freed this inode → a disk image reading FREE while we hold the grant + in-core ALLOCATED is provably STALE (our create not destaged / intra-node stale-cluster flush). Node-affine inode alloc (sess45, xfs_ialloc.c:2103 `node_slot % maxagi`) means a peer can't own this inode's cluster, so a held grant is authoritative. A genuine peer-free requires the peer to acquire EX (BASTs us to NL first), so i_dlm_mode==NL is the only state where disk-free is authoritative → no resurrection regression.

### RESULT (verified, build 5E706CBF, run 20260619T095321Z)
P116 held=1 fired 40× on test2; **P-RELOAD-IOPS-REWIRE new_mode=00 = 0×, P26-IGET-FAIL = 0×, lookup_fail = 0, P31B-RELOAD-BUF = 0×, dir3_block_verify = 0×.** FACE B gone.

### REMAINING blocker (now the dominant fail): dir-DATA-block dirent loss
Test now fails EARLIER (round 9) with `readdir=185/200 lookup_fail=0` (15 dirents missing from the shared dir's DATA blocks, all listed entries lookup-able). This is the sess29-PROVEN root: xfsaild flushes a STALE dir DATA block over a peer's committed dirents (or a stale-base RMW after EX acquire). The dir block is a genuinely SHARED object (one dir, both nodes add dirents) so node-affinity can't separate it. Pinned stale buffers can't be invalidated (sess29 blocker). See [[sess29-PROVEN-root-xfsaild-stale-dirblock-flush-at-EX]], [[sess28-ROOTFIX-inode-revert-fresh-gen-on-create-reuse]]. Criterion (./run.sh 2 tcp 100%) NOT yet met.

### Other faces seen this session (all from the same stale-cache-survives-reuse root)
FACE A: xfs_dir3_block_verify XDD3-vs-XDB3 (readdir=0, dir block holds leaf-data magic while reader uses block verifier). FACE C: inode-cluster corruption/shutdown (not seen this session). P31-FACEA detector added (xfs_dir2_readdir.c) to disambiguate inode-stale vs block-stale on that face.
</body>
</invoke>
<invoke name="TaskUpdate">
<parameter name="taskId">1
