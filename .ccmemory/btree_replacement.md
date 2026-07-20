---
name: btree-engine-replacement
description: Plan to replace hand-rolled btree code in alloc.c with XFS-based cursor engine. Phase 1-5 plan in /home/steve/.claude/plans/curious-cooking-tome.md
type: project
---

## Btree Engine Replacement (Session 60+)

Replacing alloc.c's hand-rolled btree manipulation (~4937 lines) with XFS's cursor-based btree engine. Root cause of Bug 138 (stale bnobt records → double allocation in multi-node mode).

**Why:** alloc.c zeros records instead of deleting, never updates parent keys, has no cursor abstraction, no atomic dual-tree updates. 138+ bugs are symptoms.

**How to apply:** Full plan at `/home/steve/.claude/plans/curious-cooking-tome.md`. XFS reference code cached in /tmp/xfs_btree_*.txt during sessions.

### New Files
- `libmxfs/mxfs_btree.h` — cursor, ops vtable, key/rec/ptr types
- `libmxfs/mxfs_btree.c` — ported XFS btree engine (~2400 lines, AG short-form only)
- `libmxfs/mxfs_btree_io.h/.c` — I/O shim mapping btree buf ops to block_cache
- `libmxfs/mxfs_alloc_btree.h/.c` — bnobt/cntbt ops vtables + AGFL
- `libmxfs/mxfs_inobt.h/.c` — inobt/finobt ops vtables

### Phases
1. Btree engine + I/O shim (builds, no behavior change)
2. Replace block alloc/free with cursor-based fixup_trees
3. Replace inode alloc/free with cursor-based ops
4. Multi-node validation with guard map
5. Cleanup + tools + version bump

### Key XFS Functions to Port
- `xfs_btree_lookup` → `mxfs_btree_lookup` (binary search + cursor positioning)
- `xfs_btree_insert` → `mxfs_btree_insert` (insert with auto-split)
- `xfs_btree_delete` → `mxfs_btree_delete` (delete with auto-merge)
- `xfs_btree_update` → `mxfs_btree_update` (in-place record change)
- `xfs_btree_update_keys` → `mxfs_btree_update_keys` (parent key propagation — THE missing piece)
- `xfs_alloc_fixup_trees` → `mxfs_alloc_fixup_trees` (atomic dual-tree update for all 4 cases)
- `xfs_free_ag_extent` → adapted free logic with proper merge + fixup_trees

### XFS Dependencies Replaced
- `xfs_buf` → `mxfs_btree_buf` (wraps block_cache entry)
- `xfs_trans` → eliminated (dirty tracking in I/O shim, flush on BAST/AG-switch)
- `xfs_mount` → `mxfs_btree_mount` (sb + bcache + DLM flags)
- `xfs_perag` → AGF/AGI read from block_cache as needed
- AGFL → implementing (currently ignored, using steal_bnobt_blocks instead)

### Progress
- [ ] Phase 1: mxfs_btree_io.h/.c created
- [ ] Phase 1: mxfs_btree.h created
- [ ] Phase 1: mxfs_btree.c ported
- [ ] Phase 1: mxfs_alloc_btree.h/.c created
- [ ] Phase 1: mxfs_inobt.h/.c created
- [ ] Phase 1: Kbuild updated, builds clean
- [ ] Phase 2: alloc_blocks_from_ag rewritten
- [ ] Phase 2: free_blocks_in_ag rewritten
- [ ] Phase 2: mxfs_alloc_fixup_trees ported
- [ ] Phase 2: Single-node test pass
- [ ] Phase 3: inode alloc/free rewritten
- [ ] Phase 4: Multi-node test pass
- [ ] Phase 5: Tools + cleanup
