---
name: sess30-ready-detector-build-and-next-run
description: sess30 relay: build 01E60C6E = AB435ACC baseline + ONLY an un-gated capped P-DBLALLOC detector (log-only). Next: reboot cluster, run dir_reuse, grep…
metadata:
  type: project
---

## sess30 relay handoff — ready-to-run FACE C detector build

### Build at relay = `01E60C6E` (NOT the clean baseline AB435ACC)
Delta from baseline AB435ACC = ONE change only: the existing **P-DBLALLOC** detector in `xfs/libxfs/xfs_alloc.c` (`xfs_alloc_vextent_finish`, ~line 4214) was UN-GATED (was `mxfs_instr_enabled||mxfs_dirwr_enabled`) and CAPPED at 40000 reads via a static atomic. It is **LOG-ONLY (no behavior change)** — safe to run functionally. Purpose: catch FACE C's cross-node double-alloc WITHOUT instr=1 (which is 100x slower and HIDES the race).

P-DBLALLOC fires when: a DATA-fork allocation's just-allocated block ALREADY holds live dir-block (XDB3/XDD3) / dir-leaf (0x3df1/0x3dff @off8) / inode ('IN'=0x494e) magic on the coherent (LIO write-through) medium. It logs: `agno agbno len new_owner_ino daddr holds=<dir-block|dir-leaf|inode> magic0 tenure node=<slot> wasfromfl comm`.

### NEXT SESSION — run this FIRST (decisive RULE-4 step for FACE C):
1. `bash tests/reboot_cluster.sh 2` (cluster FS is SHUT DOWN from sess30's corruption → `/dev/sda` busy → prep fails without reboot).
2. `cd /src/mxfs && timeout 500 ./run.sh 2 tcp dir_reuse_coherency` (NO MXFS_EXTRA_MODARGS — run WITHOUT instr/dirwr so the race is preserved).
3. On both nodes: `dmesg | grep -E "P-DBLALLOC|Structure needs cleaning|xfs_inode_buf_verify|P26-IGET-FAIL"`.

### INTERPRETATION:
- **P-DBLALLOC FIRES** (holds=inode, node=<slot>): cross-node allocator double-alloc CONFIRMED — a data block was allocated over a live inode cluster the peer (or this node) owns. `node`=allocating slot; `comm`=allocating process. FIX → cross-node AG free-space coherency: the inode-CHUNK alloc path or the data alloc used a STALE bnobt that didn't reflect the peer's allocation. Investigate why the bnobt cold-read (mxfs_ag_meta_invalidate_stale, wired into xfs_btree.c:1420) didn't refresh for this AG (agno=1 contended). Candidate: AG-DLM double-grant (both nodes EX on agno=1) — add an on-disk AG-slot-held check at the bnobt-modify point (analogue of sess107/P108 mxfs_v5_dlm_inode_held for inodes).
- **P-DBLALLOC does NOT fire** but corruption still happens: the double-ownership is NOT at alloc time → STALE FILE EXTENT MAP under inode reuse (a file's in-core bmap points at a reused daddr now backing an inode cluster; the data-path iomap write — which BYPASSES the xfs_buf chokepoint — clobbers it). FIX → invalidate the file inode's extent map on reuse (sess40/47/48 reused-inode family), or evict-on-free.

### Full sess30 context (3 faces; FACE C = cross-node daddr-reuse clobber, intra-node M1 ruled out P55=0×): see [[sess30-FACEC-bnobt-double-alloc-deep-dive]], [[sess30-three-faces-FACEC-double-alloc-is-root]], [[sess30-GPT-NL-refresh-design-and-superset-refuted]], [[sess30-LIO-coherent-and-acq-pin-drain-fix]]. Refuted fixes (don't repeat): pin-drain-extend, NL-pin-drain, write-side superset-discard, merge. Criterion (./run.sh 2 tcp 100%) NOT met — only dir_reuse_coherency fails. Tool: scripts/drc_parse.sh.
