---
name: sess22-DECISIVE-daddr-doublealloc-dirblock-vs-filedata
description: sess22 DECISIVE: dir_reuse_coherency clean-slate shutdown root = AG free-space DOUBLE-ALLOCATION (daddr 0x78 holds urandom FILE DATA, read as dir blo…
metadata:
  type: project
---

## sess22 DECISIVE root of the dir_reuse_coherency 2/tcp clean-slate shutdown

The round-2 FS shutdown is `Metadata CRC error (error 74 EFSBADCRC) at xfs_dir3_data_read_verify, dir block daddr 0x78`. The dmesg "First 128 bytes of corrupted metadata buffer" for daddr 0x78 shows **HIGH-ENTROPY RANDOM bytes** (`d2 d8 0e 56 54 45 89 7c 4c 31 ...`) — i.e. `/dev/urandom` FILE DATA (the test does `dd if=/dev/urandom of=node*_f*`), NOT a dir data block (no XDD3 magic), NOT an inode cluster, NOT zeros.

=> **daddr 0x78 is DOUBLE-ALLOCATED**: the AG free-space allocator gave the SAME daddr to BOTH ino 131's dir data block 0 AND a regular file's data block. The file's urandom write clobbered the dir block (or vice-versa); reading it as a dir block fails the CRC verifier → shutdown.

This is the **AG free-space double-allocation** family — the long-standing core blocker (see sess24/sess39/sess42/sess43/sess44/sess46/sess47 memories; sess39: "AG free-space double-allocation under concurrent rename → dir block shares a daddr with an inode cluster → EFSBADCRC shutdown"). It is NOT a dir-format bug. The torn-shortform-flush and leaf-hash-hole are DOWNSTREAM/parallel symptoms; the daddr double-alloc is the fatal one.

### Mechanism (to confirm)
Under concurrent 2-node rm-rf (frees blocks) + mkdir/create (allocates blocks), the AG free-space metadata (bnobt/cntbt/AGF) is not coherent between nodes at allocation time, so two allocations (dir block on one node, file block on the other — or across the rm-free/realloc reuse) both pick daddr 0x78. The AG-DLM is supposed to serialize AG allocation + the drain pipeline flush AG-meta before release, but a stale AG free-space view on the allocating node lets it hand out an already-allocated/just-freed-elsewhere block.

### Where to look
- xfs/libxfs/xfs_alloc.c (bnobt/cntbt alloc+free), xfs/xfs_mxfs_dlm.c AG-DLM acquire/release + AG-meta drain/invalidation (bast_work_fn, drain_alloc_buflist, pag_mxfs_alloc_buflist, b_mxfs_ag_gen, pag_dlm_meta_gen), xfs/xfs_buf.c AG buffer coherence (FUA read of AGF/bnobt).
- Prior proven fixes that may have regressed or be incomplete: sess42 (`C6970FF9` only advance b_mxfs_ag_gen when genuinely fresh), sess43 (`BB54A138` in-AIL AG-meta must not be discarded), sess47 (`29977E5D` stale cached inode inactivation FUA-check).

### Status of sess22 fixes (KEEP both; neither addresses the double-alloc)
- FIX1 torn-SF flush skip (xfs_inode.c) — prevents the torn-SF shutdown.
- FIX2 data-scan lookup fallback (xfs_dir2_leaf.c) — heals the leaf-hash hole; but it READS data blocks on lookup-miss so it reaches the double-allocated bad-CRC block FAST (exposes the real corruption). Don't mask it there.

### NEXT
Root-cause + fix the AG free-space double-allocation under 2-node rm-rf+create churn. Reproduce: `bash tests/reboot_cluster.sh 2; MXFS_TEST_ENV="DRC_ROUNDS=15" timeout 460 ./run.sh 2 tcp dir_reuse_coherency` (round 2 shuts down). Confirm via daddr-0x78 hexdump = urandom file data.
</body>
