---
name: sess45-FIX-partial-iwrite-skips-fresh-free-inodes-INODE_ALLOC_BUF
description: sess45 PROVEN FIX (build C0554679/EF006296): mxfs_submit_partial_inode_write skipped freshly-init'd FREE inodes (di_mode=0, ordered-buf, unlogged) →…
metadata:
  type: project
---

## sess45 (ccloop 8ddb16a2) — the deep 2/tcp crash_consistency wedge FIXED

### ROOT (fully traced, RULE-4, not a guess):
`mxfs_submit_partial_inode_write` (pal/linux/xfs_buf.c:1559, sess115 false-sharing protection)
writes only inode-cluster sectors this node LOGGED this round; it SKIPS any slot that is
free-on-buffer (di_mode==0) AND not logged AND not held-in-core (lines ~1694-1716), to avoid a
stale free copy reverting a peer's realloc (BUG1). BUT a freshly-`xfs_ialloc_inode_init`'d chunk
stamps every inode magic-IN via an ORDERED buffer (v3 inodes: logged logically via
`xfs_icreate_log`, NOT physically) — so the brand-new FREE inodes have NO inode log item and are
NOT in-core → classified "free-not-logged" → OMITTED from the bio. The omitted sectors keep the
reused block's PRIOR content (leftover file data + zeros from the just-freed extent). A later
`xfs_iget` (lookup/stat/cat) reads the whole cluster, the verifier checks EVERY slot's magic, hits
the stale slot (magic 0 / data) → -EFSCORRUPTED → shutdown. The allocated inodes (slots 0-N) get
logged on file-create so they ARE written; only the FREE tail rots. DETERMINISTIC daddr per run;
boundary slot varied (22/23) = race in how many slots were logged-vs-free.

### PROOF chain (sess45, builds 664F8E6C → FF024789):
- Raw disk: corrupt cluster @ daddr 2095208 (AG1, test2's AG) = slots 0-21 valid inodes,
  slot 24 = ASCII "node2-d4-f24-pay" (FILE payload from dlm_fairness, ran first), rest zero.
- P45-WR-CLUSTER (inode-buffer write w/ mixed zero+alloc) = 0× → no bad inode write.
- P45-WB-OVER-INODE (file-data writeback, BOTH real-extent AND delalloc-convert paths) = 0×
  → no file write clobbers it. So the "node2-d4-f24" data is LEFTOVER the init never overwrote.
- P45-INIT showed the chunk WAS init'd (agbno=248 length=8 icount=64 nbufs=2 ipc=32 bpc=4, full chunk).
  => init wrote all 32 in MEMORY but the partial-write submit dropped the free tail.

### THE FIX (pal/linux/xfs_buf.c, in mxfs_submit_partial_inode_write, after the b_addr check):
```
if (bp->b_log_item && (bp->b_log_item->bli_flags & XFS_BLI_INODE_ALLOC_BUF))
    return false;   /* whole-buffer write */
```
A freshly-allocated chunk has NO peer-owned slots (this node allocated the whole chunk under the AG
lock; a peer cannot concurrently own a slot), so false-sharing protection does not apply — write the
WHOLE buffer so every initialized inode reaches disk. XFS_BLI_INODE_ALLOC_BUF (set by
xfs_trans_inode_alloc_buf) is present for exactly the initial alloc write and gone for later
co-resident flushes, so those keep partial-write false-sharing protection. Geometry: isize=512,
bsize=4096, cluster=32 inodes/4 blocks/16KB, chunk=64 inodes.

### VERIFIED: reboot clean; `./run.sh 2 tcp dlm_fairness crash_consistency`:
- BEFORE (FF024789): dlm_fairness PASS, crash_consistency FAIL 0/2 (BADVERIFY daddr=2095208).
- AFTER (C0554679): dlm_fairness PASS, **crash_consistency PASS 2/2**, P-ICLUSTER-BADVERIFY=0,
  forced-shutdown=0 on both nodes. KEEP THIS FIX.

### Residual (separate, pre-existing, did NOT shut down / test still passed): test1 saw 1
`xfs_dinode_verify` on dir ino=0x200080 (.dlm_fairness dir) whose on-disk image carried a REG-file
image (mode 0x81a4); P-SFV-FAIL disk_differs=0 (durable) but P-RELOAD-IOPS-REWIRE recovered it
(new_mode=040755), no shutdown. This is mechanism-B co-resident dir-slot clobber
([[sess44-wedge-is-iget-lookup-coresident-cluster-write-corruption]]) — watch in the full suite.

### NEXT: run full `./run.sh 2 tcp` (17 tests, the criterion). force_block=0 kept (sess44).
Cheap probes kept in build EF006296 (P45-INIT, P45-WR-CLUSTER, P-ICLUSTER-BADVERIFY); heavy
P45-WB disk-read-per-writeback REMOVED. [[sess45-PROVEN-data-over-inode-doublealloc-clobber-payload-visible]]</body>
