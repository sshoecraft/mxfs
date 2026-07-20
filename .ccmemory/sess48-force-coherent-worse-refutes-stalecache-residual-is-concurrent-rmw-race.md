---
name: sess48-force-coherent-worse-refutes-stalecache-residual-is-concurrent-rmw-race
description: sess48(ccloop) FINAL refutation: force_coherent=1+dir_tenure_evict=1 (re-read EVERY clean dir block from the coherent write-through backing) made 8/t…
metadata:
  type: project
---

## sess48 (ccloop 4cb2d0a2) — force_coherent REFUTES stale-cache-serve; residual is a concurrent-RMW race

### The bulletproof re-read test FAILED (made it worse)
Backing is LIO FILEIO write-through (emulate_write_cache=0) = perfectly coherent. So I tested
`force_coherent=1 dir_tenure_evict=1` (invalidate+re-read EVERY clean cached dir block from the
coherent backing, for readers AND EX writers via mxfs_ex_reval). Result at 8/tcp: **13/22 rounds
FAIL** (vs ~1-2/24 baseline) — DRAMATICALLY WORSE. So serving a stale cached xfs_buf is NOT the
root: forcing always-fresh reads from a coherent backing exacerbates the loss.

### What this means
The residual durable dirent loss is a genuine CONCURRENT-RMW race, not a cache-staleness serve.
More re-reading widens it — consistent with a TWO-PHASE / TORN-UPDATE window: a re-read pulls a
dir block mid-way through a peer's multi-step update (data-block write vs leaf/free/bestfree
update vs log-commit vs block-write ordering), capturing an intermediate state that the RMW then
writes back, dropping an entry. OR the aggressive invalidation discards a committed-in-AIL block
whose content a concurrent path needed.

### COMPREHENSIVE ruled-out set this session (all instrumented):
writer data durability (DIRREL_DIFFERS=0), writer dinode/extent-map durability (P68 all
DURABLE), stale-bmap modify (P37=0), reader extent-map staleness/reload-bail (P48-RDRELOAD
bailed=0, nx_before==nx_after), split-brain (MX-DOUBLEGRANT=0), MHT batching (disabling worse),
fua_disable (worse), force_coherent re-read (worse), target-cache coherency (write-through
coherent backing). owner_scan+grant_evict+target_flush (config#1, baked) removes P13 multi-loss
and keeps 1/2/4 at 100% but leaves the ~1-2/24 single/few-dirent residual at 8 nodes.

### NEXT ANGLE (untested): the two-phase/torn dir-block update ordering
Investigate the dir create's multi-buffer transaction: data block + leaf + free/bestfree + dinode
are logged together but WRITTEN to the coherent backing in some order by xfsaild / the release
flush. A concurrent peer reading between those writes (or a peer's RMW based on a block written
before its companion leaf/free) could drop an entry. Look at whether the dir create's buffers are
made durable ATOMICALLY (all-or-nothing) at the EX boundary, or can be torn across the handoff.
Consider: does the data-block write land before the bestfree/free-list update that makes its slot
"used", so a peer sees the slot free and reuses it? (P13-COLLIDE off=64/free-slot reuse points
here.) Build state: config#1 (237F937D-equiv); diagnostic params force_coherent/dir_tenure_evict/
dir_relverify all default-off. See [[sess48-KEY-backing-is-coherent-writethrough-loss-is-bufcache-invalidation]].
</body>
