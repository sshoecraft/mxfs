---
name: sess44-deep-blocker-inode-cluster-allzeros-wedge
description: sess44 DEEP BLOCKER (post force_block=0): node reads its OWN-AG inode cluster as ALL-ZEROS under churn → xfs_inode_buf_verify fail → FS shutdown; + A…
metadata:
  type: project
---

## sess44 — the SUITE blocker that survives the force_block=0 fix (build 9A10A077)

### force_block=0 cleared the dir-format shutdowns (dlm_fairness/cache_coherency PASS). The
full `./run.sh 2 tcp` then wedges MID-SUITE at rsync_paired (EIO) — root captured:

### WEDGE = inode-cluster buffer read as ALL ZEROS → `xfs_inode_buf_verify` fail → shutdown.
- test1: `Metadata corruption at xfs_inode_buf_verify, xfs_inode block 0x87e7e0` (repeated 173×).
  "First 128 bytes of corrupted metadata buffer" = **all 00**. Block 0x87e7e0 is in **AG8 =
  test1's OWN partition** (slot0 owns agno%4==0). Amid storm of P82-ADD (AGI iunlink add) +
  P25 sync-inactive + P9 ifree in AG8.
- test2: same, block 0xa7ce88 in **AG5 = test2's OWN** (slot1 owns agno%4==1), at uptime 167s
  (early), preceded by INACT-SKIP-STALE storm (b4_noauth + disk-free/gen-mismatch skips).
- After: `Found unrecovered unlinked inode 0x998..0x99f in AG 0x8. Initiating recovery` (remount
  iunlink recovery) = the AGI unlinked list LEAKED entries.

### MECHANISM (hypothesis, RULE 4 next): under heavy create+unlink+inactivate churn in a node's
OWN AG, either (a) a freshly-(re)allocated inode cluster's init write is not yet destaged on the
SCST/LIO target and a FUA/coherent read of that cluster pierces to the platter returning PRE-INIT
ZEROS, and/or (b) INACT-SKIP-STALE skips ifree of inodes already P82-ADD'd to the AGI unlinked
list → they leak on the list → later read of the (freed/zeroed) cluster fails verify. The
all-zeros buffer (not garbage, not stale-valid) points strongly at (a): reading an inode cluster
block that was never written / freed-and-not-reinit, i.e. a FUA-read-before-init-durable ordering
hole for inode clusters, exposed by reuse churn.

### THIS IS PRE-EXISTING (sess-tcp HANDOFF saw it: "deep stale-INODE duplicate-free wedge under
CUMULATIVE load ... node's OWN partition AG"). force_block=0 did NOT cause it — it REVEALED it as
the now-final 2/tcp suite blocker. NOT a cross-node double-alloc (each node corrupts its OWN AG).

### NEXT (RULE 4): (1) reproduce with a single heavy metadata test (rsync_paired standalone) or
a tight create+unlink+stat loop; (2) instrument the inode-cluster READ path (xfs_inode_buf_verify
/ xfs_imap_to_bp / _XBF_FUA_FRESH gate) to catch the all-zeros read — is it FUA-reading an
un-destaged-init cluster, or reading a leaked-iunlink freed cluster? (3) fix = ensure inode-cluster
init write is durable before any coherent read, AND/OR stop INACT-SKIP-STALE from leaving inodes
on the AGI unlinked list (remove-from-list even when skipping the block free). [[sess44-force-block-0-suite-sweep]] [[sess44-BREAKTHROUGH-force-block-1-is-the-regression]]</body>
