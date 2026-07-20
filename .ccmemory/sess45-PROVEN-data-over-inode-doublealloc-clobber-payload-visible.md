---
name: sess45-PROVEN-data-over-inode-doublealloc-clobber-payload-visible
description: sess45 DEFINITIVE: the 2/tcp wedge = file DATA extent double-allocated over a LIVE inode chunk; data write (iomap/folio, bypasses all xfs_buf verifie…
metadata:
  type: project
---

## sess45 (ccloop 8ddb16a2, build 664F8E6C) — ROOT PROVEN with raw-disk evidence

### Reliable repro (~90s, keeps nodes reachable — crash_consistency does NOT crash, just drop_caches):
reboot both nodes clean (virsh destroy/start); `./run.sh 2 tcp dlm_fairness crash_consistency`.
dlm_fairness PASS (seeds churn/fragmentation), crash_consistency FAIL 0/2 → wedge fires.
Then read the corrupt cluster raw from a node: device_byte = xfs_data_offset(100704256) + daddr*512.

### THE EVIDENCE (build 664F8E6C, P45 probes):
- Both nodes: `P-ICLUSTER-BADVERIFY daddr=2095208 slot=22 magic=0x0` (AG1 agbno 248 = test2's OWN AG).
- Raw dump of cluster @ daddr 2095208 (32-inode/16KB/4-block cluster, ipc=32 bpc=4):
  - slots 0-21: valid inodes (magic IN, mode 0x81a4 = S_IFREG, crash_consistency's files)
  - slots 22-23: ZERO
  - **slot 24: `6e 6f 64 65 32 2d 64 34 2d 66 32 34 2d 70 61 79` = ASCII "node2-d4-f24-pay" = FILE PAYLOAD DATA**
  - slots 25-31: ZERO
- So a file's DATA block (payload "node2-d4-f24-...", from dlm_fairness) sits at agbno 251 (block3 of
  the inode cluster 248-251). The chunk is LIVE (22 allocated inodes) yet its block was handed out for data.

### WHY no verifier caught the clobbering write (P45-WR-CLUSTER fired 0×):
File DATA is written via the iomap/folio path STRAIGHT to the block device — it does NOT go through
xfs_buf, so NO xfs_inode_buf write-verifier runs. The inode-cluster write verifier only guards xfs_buf
inode writes (all clean here). So the clobber is invisible to every buffer-level check. The corruption is
ON-DISK + DURABLE (survives reboot); read-verify (xfs_imap_to_bp → iget on lookup/stat/cat) then fails on
the zeroed/garbage slot → EFSCORRUPTED → shutdown → tests fail (crash_consistency "durable count 82/100",
dir_reuse "Structure needs cleaning").

### ROOT = block double-allocation: bnobt (AG free-space) handed out a LIVE inode chunk's block for file
data. = the 90-session bnobt/AG-free-space cross-node LOST-UPDATE (sess39/81/89/90 family). A node with a
stale cached bnobt/AGF writes it back, reverting a peer's inode-chunk allocation → those blocks reappear as
"free" → next alloc takes them for data → data write clobbers the inode cluster. Geometry: isize=512,
bsize=4096, agblocks≈261653, cluster=32 inodes (4 blocks/16KB), chunk=64 inodes, inits are always FULL
(P45-INIT length=8 icount=64 nbufs=2 — NOT sparse, no partial-init bug). force_block=0 (sess44 default kept).

### NEXT (RULE 4): catch the data-extent allocation that overlaps a live inode chunk. Probe idea: at
xfs_alloc result for USERDATA allocs (args->datatype & XFS_ALLOC_USERDATA), inobt-lookup the allocated
agbno in the (already-locked) AG; if it falls inside an existing inode chunk → log agno/agbno/startino.
That proves M2 (bnobt stale-free) vs M1 (stale data buffer write to a correctly-reused block) and names the
path. Then fix the AG-free-space coherency so a stale bnobt can never be written back / read.
[[sess44-deep-blocker-inode-cluster-allzeros-wedge]] [[sess44-wedge-is-iget-lookup-coresident-cluster-write-corruption]]</body>
