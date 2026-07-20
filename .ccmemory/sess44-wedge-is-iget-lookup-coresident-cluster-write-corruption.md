---
name: sess44-wedge-is-iget-lookup-coresident-cluster-write-corruption
description: sess44 PROVEN: suite wedge = iget-during-lookup reads an inode cluster corrupted by cross-node CO-RESIDENT cluster-WRITE (stale slots clobber peers/d…
metadata:
  type: project
---

## sess44 — the deep 2/tcp blocker PROVEN via stack trace (build 33E9694F, P-ICLUSTER-BADVERIFY probe)

### Reliable reproducer (~5 min, build w/ probe): reboot; `./run.sh 2 tcp dlm_fairness rsync_paired
crash_consistency [dir_reuce]` on ONE prep. dlm_fairness is FLAKY (churn seeds it); crash_consistency
then FAILs; the wedge fires. DROP dir_reuse from the repro — it hammers the wedged node ssh-UNREACHABLE
(login hangs 2min); without it the node stays reachable to read dmesg.

### THE WEDGE — stack trace (decisive, overturns the earlier "stale-inode flush" guess):
`P-ICLUSTER-BADVERIFY daddr=10466696 slot=27 magic=0xf6aa comm=mkdir`
  `xfs_inode_buf_verify <- xfs_inode_buf_read_verify <- __xfs_buf_ioend <- xfs_buf_iowait <-
   _xfs_buf_read <- xfs_buf_read_map <- xfs_imap_to_bp <- xfs_iget <- xfs_lookup <- (mkdir)`
=> a `mkdir`'s path lookup does xfs_iget, which FRESH-reads the inode cluster; the read verifier
finds slot 27 has **magic=0xf6aa (GARBAGE, non-inode data)** -> EFSCORRUPTED -> shutdown. It is a
FRESH READ (iget cache-miss), NOT xfsaild flush (a dirty inode keeps its cluster buf cached, so a
flush would write stale-in-mem, not read garbage).

### CORRUPTION IS ON-DISK / CO-RESIDENT CLUSTER WRITE (multiple clusters, same run):
- daddr 10466696 slot 27 = garbage 0xf6aa (data-over-inode / freed-reused = block double-ownership).
- `P-SFV-FAIL ino=0x200080 err=-117 disk_differs=0` (DURABLE on-disk) — the `.dlm_fairness` DIR
  inode (0x200080=2097280) on-disk image was OVERWRITTEN with a REGULAR-FILE inode
  (hexdump `49 4e 81 a4` = magic IN, mode 0x81a4=S_IFREG). A co-resident slot in the dir's cluster
  got clobbered with a regular-file image.
- INACT-SKIP-STALE storm (ino 131-140 AG0: disk_mode=00 disk_gen=0 incore=0100644 local_unlink=1
  dlm_mode=5/EX) — test1's OWN just-unlinked inodes, already free on disk; guard skips (working).

### UNIFYING ROOT = cross-node inode-cluster WRITE coherency (sess88/90 family): when a node flushes
ONE dirty inode, XFS writes the WHOLE cluster buffer (4K/16K). If that cached buffer holds STALE
images of CO-RESIDENT inodes (slots modified by a peer, or freed/reused, not merged from coherent
disk), the write CLOBBERS them on disk -> garbage/type-flip in those slots -> a later iget of any
inode in that cluster verify-FAILs -> shutdown. Existing partial mechanism:
`mxfs_iflush_cluster_merge_dirs` (xfs/xfs_inode.c:5071, called ~5518) merges DIR slots from disk
during iflush — likely insufficient (covers dirs only / not firing for these slots / itself writing
stale). 

### STATUS: force_block=0 (build 9A10A077) FIXED the dir-format shutdowns (cache_coherency,
dlm_fairness, dir_reuse PASS standalone). This cluster-write corruption is the REMAINING suite
blocker (contaminates rsync_paired+ in the full suite via mid-suite shutdown). It is the 90-session
deep inode family. NEXT: instrument/fix the cluster WRITE to never persist stale co-resident slots —
on inode-cluster write (xfs_inode_buf_write_verify / iflush_cluster), FUA-reconcile every slot NOT
owned by a locally-dirty inode against the coherent on-disk image before bwrite; OR write only the
flushing inode's slot. Probe P-ICLUSTER-BADVERIFY is live (build 33E9694F). [[sess44-deep-blocker-inode-cluster-allzeros-wedge]] [[sess44-force-block-0-suite-sweep]] [[sess44-BREAKTHROUGH-force-block-1-is-the-regression]]</body>
