---
name: sess63-zsl-bmbt-fua-fix-eio-gone-but-incore-leaf-reverts
description: sess63: zsl bmbt-leaf write EIO FIXED via SCSI-FUA-passthrough (P133-RELFLUSH-ERR gone) but SIG1 persists — in-core leaf buffer reverts N→N-1 after i…
metadata:
  type: project
---

## sess63 (ccloop 14d31183) — zero_silent_loss: EIO fixed, in-core leaf-revert is the residual root

Criterion STILL FAILS. Marker NOT written. Current build **E277C0DA** (compiles).
Supersedes the sess62 "leaf-numrecs=N-1" framing with a sharper mechanism.

### What was PROVEN this session (all instrumented, RULE 4)
1. **On-disk torn state is REAL** (raw `dd` of platter, twice): dinode ino131
   `di_nextents=N` while bmbt leaf `numrecs=N-1`. Not a reader-cache artifact.
   (dinode @ device byte 100771328 = xfs_data_offset 100704256 + AG0 fsblk16*4096 +
   slot3*512; di_nextents @ +76 4B BE, di_format @ +5; leaf numrecs @ +6 2B BE,
   leaf device byte = 100704256 + leaf_daddr*512.)
2. **Insert path is consistent**: new probe P63-INSERT-DESYNC (xfs_bmap.c after
   xfs_btree_insert @~2870, fires only if single-leaf & leaf_numrecs!=if_nextents)
   NEVER fired. So leaf==iext at every insert.
3. **The producer is a TORN FLUSH**: new probe P63-TORN-FLUSH (in
   mxfs_iflush_force_bmbt_durable, non-ratelimited, fires when broot_nrecs==1 &&
   leafsum!=if_nextents) FIRED: `if_nextents=15 leafsum=14 nheld=1 wrote=1
   comm=xfsaild`. The in-core LEAF buffer is one behind the in-core IEXT skiplist
   at flush; writer durably persists di=15/leaf=14.
4. **The bmbt-leaf WRITE was failing -EIO** (P133-BMBT-RELFLUSH-ERR rc=-5, the
   sess60-known writer root): the plain REQ_OP_WRITE|REQ_META bio for the bmbt leaf
   intermittently EIOs on the iSCSI/SCST stack; the Nth-record write never landed
   (P60-BMBTWRITE max=N-1 cluster-wide).

### Fixes LANDED this session (re-evaluate)
- **FIX A (KEEP, WORKS for its target): route bmbt-leaf WRITES through SCSI FUA
  passthrough.** In pal/linux/xfs_buf.c `xfs_buf_submit`, just before
  `xfs_buf_submit_bio`, for multi-node WRITE of `xfs_bmbt_buf_ops` (single map):
  `mxfs_buf_write_fua(bp)` then `xfs_buf_ioend`+return (mirrors the surgical-inode
  block). RESULT: **P133-BMBT-RELFLUSH-ERR GONE, no P63-BMBT-FUAWR-FALLBACK** — the
  EIO is eliminated, leaf writes now durable. (Side effect: P60-BMBTWRITE no longer
  fires — bmbt writes bypass submit_bio; use new P63-LEAFWR instead.)
- **FIX B (FUA-read bmbt, KEEP-for-now but INSUFFICIENT): added `xfs_bmbt_buf_ops`
  to `mxfs_buf_needs_fua_read`** (xfs_mxfs_dlm.c ~12507). sess60 reverted this but
  that predated FIX A + the read-over-logged guards (P91/P61-BIO-OVER-LOGGED-BMBT).
  This time it did NOT regress (no `i != 1` corruption). But SIG1 PERSISTS: reader
  FUA-reads the leaf and still gets N-1 → the DISK leaf is genuinely N-1 (FIX A made
  it durable, but durably TORN).

### THE RESIDUAL ROOT (next session, pin this)
The in-core bmbt LEAF buffer reverts **N→N-1 AFTER the (consistent) insert, BEFORE
the flush**, while the iext skiplist keeps N. Writer then durably flushes the torn
pair. P63-INSERT-DESYNC silent + P63-TORN-FLUSH firing localizes it to this window.
NOT a write-durability problem (fixed), NOT an insert problem (consistent), NOT a
reader-cache problem (platter is torn).

### NEXT STEP (instrumentation already built into E277C0DA, just deploy+run)
Build E277C0DA adds two timeline probes:
- **P63-LEAFWR** (in the FIX-A write block): every durable leaf write's numrecs+comm.
- **P63-LEAFRD** (in mxfs_buf_read_fua after a successful FUA read): every leaf read's
  numrecs+comm.
Deploy E277C0DA, run zsl --iters 1 --dpn 100 --mode 1, grep both + P63-TORN-FLUSH on
all 16 nodes, merge by realns for ino131's leaf daddr. Expect to see: insert→N, then
a **P63-LEAFRD numrecs=N-1** (the reverting read DMA over the in-core buffer) landing
between, then the torn flush writes N-1. Identify the comm/context of that read — it's
either (a) mxfs_dir_evict_bmbt_blocks clearing XBF_DONE on the leaf then a re-read
pulling a not-yet-propagated image, or (b) a reload (mxfs_dlm_reload_inode) rebuilding,
or (c) a plain-bio read NOT caught by the logged-guard because the leaf is momentarily
clean. Then fix that revert (e.g. refuse to re-read a bmbt leaf whose in-core numrecs
exceeds the disk image; or treat the iext skiplist as authoritative and rebuild the
leaf from it at flush instead of trusting the reverted buffer).

### INFRA
virsh -c qemu:///system destroy+start ALL 16, sleep 40, verify 16/16. Local
/src/mxfs/mxfs.ko is NFS-visible to nodes; workload insmods it directly (no copy).
zsl is variance-dominated on total_fs_silent (always ~1600) — judge by per-SIGNATURE
dmesg (P59-IREAD-MISMATCH, P63-TORN-FLUSH), NOT the RESULT line. Platter ground-truth
read recipe above. Pass file /tmp/.mxfs_pass; SSH tools/mxfs_sshpass.sh <h> <P> <cmd>.
Links: [[sess62-zsl-leaf-buffer-lags-nextents-by-one]]
[[sess60-zsl-writer-releases-inconsistent-dinode-bmbt]].
</body>
