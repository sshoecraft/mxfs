---
name: compiled-sess44-45-data-over-inode-cluster-double-alloc-wedge
description: sess44-45: inode-cluster wedge — corrupt/all-zeros/data-over-inode slots crash iget; ROOT = partial-iwrite dropping fresh free inodes; FIXED C0554679.
metadata:
  type: project
tags: [compiled, inode-cluster, double-alloc, crash_consistency, xfs_buf, tcp-2node, coherency]
---

## sess44-45 — inode-cluster corruption wedge in 2-node/tcp suite (crash_consistency blocker)

Central topic: a family of `xfs_inode_buf_verify` read failures in the 2-node TCP suite where an inode
cluster on a node's OWN AG is read back with a corrupt/all-zeros/foreign slot → `-EFSCORRUPTED` → FS
shutdown → mid-suite cascade (run_coord needs BOTH nodes PASS, so one node's shutdown fails every
remaining test). Chased across sess44-45 through several hypotheses to a proven root and a KEEP fix.

### The symptom (sess44)
The wedge is a FRESH inode-cluster READ, not an xfsaild flush. Stack trace (probe P-ICLUSTER-BADVERIFY,
build 33E9694F): `xfs_inode_buf_verify <- xfs_inode_buf_read_verify <- __xfs_buf_ioend <- xfs_buf_iowait
<- _xfs_buf_read <- xfs_buf_read_map <- xfs_imap_to_bp <- xfs_iget <- xfs_lookup <- (mkdir)`. A path
lookup's `xfs_iget` cache-misses, reads the whole cluster, the verifier checks EVERY slot's magic, hits a
bad slot → shutdown. A dirty inode would keep its cluster buf cached (a flush writes stale-in-mem, it does
not read garbage) — so this is a cache-miss read of on-disk corruption. See
[[sess44-wedge-is-iget-lookup-coresident-cluster-write-corruption]].

Two on-disk corruption shapes observed, both DURABLE (survive reboot):
- **Garbage / foreign magic**: daddr 10466696 slot 27 magic=0xf6aa; `.dlm_fairness` DIR inode 0x200080
  (mode should be dir) overwritten with a REGULAR-FILE image (hexdump `49 4e 81 a4` = magic IN,
  mode 0x81a4=S_IFREG). A co-resident slot in a cluster clobbered with a reg-file/data image.
- **All-zeros**: `xfs_inode_buf_verify` on block 0x87e7e0 (AG8 = test1's OWN, slot0 owns agno%4==0,
  repeated 173×, first 128 bytes all 00) and block 0xa7ce88 (AG5 = test2's OWN, slot1 owns agno%4==1).
  Followed by `Found unrecovered unlinked inode 0x998..0x99f in AG 0x8` on remount = AGI unlinked list
  leaked entries. See [[sess44-deep-blocker-inode-cluster-allzeros-wedge]].

Key sess44 framing: each node corrupts its OWN AG (NOT a cross-node double-alloc across partitions).
This is PRE-EXISTING (the sess-tcp handoff already saw the "deep stale-inode duplicate-free wedge under
cumulative load, node's OWN partition AG"). `force_block=0` (build 9A10A077, sess44) FIXED the separate
dir-format shutdowns (dlm_fairness / cache_coherency / dir_reuse PASS standalone) and REVEALED this as the
now-final suite blocker; force_block=0 kept through sess45.

Reliable sess44 repro (~5 min): reboot; `./run.sh 2 tcp dlm_fairness rsync_paired crash_consistency` on one
prep. dlm_fairness is flaky (churn seeds it), crash_consistency then FAILs, wedge fires. DROP dir_reuse
from the repro — it hammers the wedged node ssh-unreachable (login hangs ~2min); without it the node stays
reachable to read dmesg.

### sess45 initial hypothesis — data-over-live-inode double-alloc (raw-disk PROOF, later refined)
Cheaper repro (~90s, keeps nodes reachable; crash_consistency does NOT crash, just drop_caches): reboot
both (virsh destroy/start); `./run.sh 2 tcp dlm_fairness crash_consistency`. dlm_fairness PASS (seeds
churn/fragmentation), crash_consistency FAIL 0/2 → wedge.

Raw-disk evidence (build 664F8E6C): both nodes `P-ICLUSTER-BADVERIFY daddr=2095208 slot=22 magic=0x0`
(AG1 agbno 248 = test2's OWN AG). Dump of the 32-inode/16KB/4-block cluster @ daddr 2095208 (ipc=32,
bpc=4): slots 0-21 valid inodes (magic IN, mode 0x81a4 S_IFREG, crash_consistency files); slots 22-23
zero; **slot 24 = ASCII `node2-d4-f24-pay` = FILE PAYLOAD** (from dlm_fairness, which ran first); slots
25-31 zero. A file DATA block sat at agbno 251 (block3 of the LIVE inode cluster 248-251, 22 allocated
inodes). Read the corrupt cluster raw via `device_byte = xfs_data_offset(100704256) + daddr*512`.

Why no verifier caught it: file DATA is written via the iomap/folio path STRAIGHT to the block device,
bypassing xfs_buf entirely — no `xfs_inode_buf` write-verifier runs (the inode-cluster write verifier only
guards xfs_buf inode writes, all clean here). sess45 first attributed this to the 90-session bnobt/AG-
free-space cross-node LOST-UPDATE family (sess39/81/89/90): a stale cached bnobt/AGF written back reverts a
peer's inode-chunk alloc → blocks reappear "free" → next alloc hands them to file data → data write
clobbers the inode cluster. Geometry: isize=512, bsize=4096, agblocks≈261653, cluster=32 inodes/4
blocks/16KB, chunk=64 inodes, inits always FULL (P45-INIT length=8 icount=64 nbufs=2, not sparse). See
[[sess45-PROVEN-data-over-inode-doublealloc-clobber-payload-visible]].

### sess45 REFINED ROOT (RULE-4 traced, refutes the clobber theory) + KEEP FIX
The clobber theory was disproven by probes: **P45-WR-CLUSTER = 0×** (no bad inode-buffer write),
**P45-WB-OVER-INODE = 0×** (neither real-extent NOR delalloc-convert file-writeback path clobbers the
cluster), while **P45-INIT** showed the chunk WAS fully init'd (agbno=248 length=8 icount=64 nbufs=2 ipc=32
bpc=4). Conclusion: the `node2-d4-f24` payload is LEFTOVER content the init never overwrote on disk — not
a clobbering write. See [[sess45-FIX-partial-iwrite-skips-fresh-free-inodes-INODE_ALLOC_BUF]].

Real cause: `mxfs_submit_partial_inode_write` (pal/linux/xfs_buf.c:1559, sess115 false-sharing
protection) writes only the inode-cluster sectors this node LOGGED this round; it SKIPS any slot that is
free-on-buffer (di_mode==0) AND not logged AND not held-in-core (~lines 1694-1716), to stop a stale free
copy reverting a peer's realloc (BUG1). But a freshly `xfs_ialloc_inode_init`'d chunk stamps every inode
magic-IN via an ORDERED buffer — v3 inodes are logged LOGICALLY via `xfs_icreate_log`, NOT physically — so
the brand-new FREE inodes have no inode log item and are not in-core → classified "free-not-logged" →
OMITTED from the bio. The omitted sectors keep the reused block's PRIOR content (leftover file data +
zeros from the just-freed extent). A later `xfs_iget` (lookup/stat/cat) reads the whole cluster, verifier
hits the stale slot (magic 0 / data) → -EFSCORRUPTED → shutdown. Allocated slots 0-N get logged on
file-create so they ARE written; only the FREE tail rots. Deterministic daddr per run; boundary slot
varied (22/23/24) = race in how many slots were logged-vs-free.

Proof chain (builds 664F8E6C → FF024789): corrupt cluster @ daddr 2095208 (AG1, test2's AG); P45-WR-CLUSTER
0×; P45-WB-OVER-INODE 0×; P45-INIT confirmed full chunk init in MEMORY but the partial-write submit dropped
the free tail.

THE FIX (pal/linux/xfs_buf.c, in `mxfs_submit_partial_inode_write`, after the b_addr check):
```
if (bp->b_log_item && (bp->b_log_item->bli_flags & XFS_BLI_INODE_ALLOC_BUF))
    return false;   /* whole-buffer write */
```
A freshly-allocated chunk has NO peer-owned slots (this node allocated the whole chunk under the AG lock; a
peer cannot concurrently own a slot), so false-sharing protection does not apply — write the WHOLE buffer
so every initialized inode reaches disk. `XFS_BLI_INODE_ALLOC_BUF` (set by `xfs_trans_inode_alloc_buf`) is
present for exactly the initial alloc write and gone for later co-resident flushes, so those keep partial-
write false-sharing protection. Geometry: isize=512, bsize=4096, cluster=32 inodes/4 blocks/16KB, chunk=64.

VERIFIED (build C0554679, also carried in EF006296, KEEP): reboot clean;
`./run.sh 2 tcp dlm_fairness crash_consistency` — BEFORE (FF024789) crash_consistency FAIL 0/2
(BADVERIFY daddr=2095208); AFTER (C0554679) dlm_fairness PASS, **crash_consistency PASS 2/2**,
P-ICLUSTER-BADVERIFY=0, forced-shutdown=0 on both nodes.

Residual (separate, pre-existing, did NOT shut down): test1 saw 1 `xfs_dinode_verify` on dir ino=0x200080
(`.dlm_fairness`) carrying a REG-file image (mode 0x81a4); `P-SFV-FAIL disk_differs=0` (durable) but
`P-RELOAD-IOPS-REWIRE` recovered it (new_mode=040755), no shutdown. This is the mechanism-B co-resident
dir-slot clobber from [[sess44-wedge-is-iget-lookup-coresident-cluster-write-corruption]] — watch in full
suite.

### sess45 NEXT BLOCKER (revealed after the fix, NOT the inode-cluster wedge)
With the inode-cluster wedge fixed and VERIFIED standalone, full `./run.sh 2 tcp` (17 tests) = 0 PASS / 17
FAIL from a NEW early wedge (P45-INIT/P45-WR-CLUSTER/P-ICLUSTER-BADVERIFY all 0× that run). test1 shut down
(~uptime 300.9s = early in suite, precond_readiness/cache_coherency), test2 stayed WRITE_OK; the all-fail
is the cascade. Root (test1 dmesg, build EF006296):
```
XFS Internal error !(flags & XFS_DABUF_MAP_HOLE_OK) at line 2814 of xfs_da_btree.c. Caller xfs_dabuf_map
XFS Internal error xfs_trans_cancel at line 1060 of xfs_trans.c. Caller xfs_create
XFS Corruption of in-memory data (0x8) at xfs_trans_cancel:1061. Shutting down filesystem.
```
An `xfs_create` maps a directory block via `xfs_dabuf_map` and bmapi returns a HOLE where a dir block must
exist — the dir's in-core extent map references an unmapped block; HOLE not allowed → corruption_error →
dirty trans cancelled → SHUTDOWN_CORRUPT_INCORE. This is the dir-coherency M2 family (stale in-core dir
extent map / block0 daddr divergence across reuse), likely the shared ROOT dir /mnt/shared whose extent
map is stale right after mount so the first cross-node create hits the hole. NEXT (RULE 4): repro standalone
`./run.sh 2 tcp cache_coherency` on fresh prep; instrument xfs_dabuf_map / xfs_da_read_buf (~2814) to dump
dir ino, requested bno / mapped fsb, in-core if_nextents vs on-disk, di_gen mismatch (stale prior
incarnation) vs genuinely-lost block; likely fix locus = dir-inode reload on EX acquire adopting peer's
fresh incarnation, or dir-data durability + extent-map coherency (mxfs_dir_data_durable / b_mxfs_dir_gen
invalidation). See [[sess45-next-blocker-dabuf-map-hole-dir-extent-xfs_create-shutdown]].

### Build/marker progression
- 33E9694F — P-ICLUSTER-BADVERIFY probe live (sess44).
- 9A10A077 — force_block=0, cleared dir-format shutdowns, revealed the inode-cluster blocker (sess44; kept).
- 664F8E6C — P45 probes; raw-disk data-over-inode evidence (sess45, initial double-alloc hypothesis).
- FF024789 — pre-fix baseline: crash_consistency FAIL 0/2.
- C0554679 — the INODE_ALLOC_BUF whole-buffer-write FIX; crash_consistency PASS 2/2. KEEP.
- EF006296 — carries the fix + cheap probes (P45-INIT, P45-WR-CLUSTER, P-ICLUSTER-BADVERIFY); heavy
  P45-WB disk-read-per-writeback probe REMOVED. Exposes the DABUF_MAP_HOLE dir-coherency next blocker.

### Recurring lessons
- Trust probe measurements over code-reading (RULE 4): the double-alloc/clobber theory looked proven from
  raw disk yet P45-WR-CLUSTER + P45-WB-OVER-INODE at 0× reclassified it as a dropped-write, not a clobber.
- Verifier blind spot: iomap/folio file-DATA writes bypass xfs_buf, so no buffer write-verifier can catch
  a data-over-inode overlap; only the later read-verify on iget surfaces it.
- False-sharing partial-inode-write protection must be OFF for the initial alloc write
  (XFS_BLI_INODE_ALLOC_BUF) — the allocating node owns the whole chunk, so partial write drops the freshly
  magic-stamped-but-unlogged free tail.
- Standalone-PASS ≠ suite-PASS: fixing one wedge unmasks the next (dir-extent HOLE); a 17-test 0/17 is
  usually one node's early shutdown cascading, not 17 independent failures.
