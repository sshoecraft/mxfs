---
name: ccloop-c7ee71c6-sess95-step5.3-wire-landed-cert-design
description: sess95: step 5.3 wire half landed (0.11.428, builds clean, NOT deployed) — ICLUS class closes the epoch-namespace blocker, 5 new statuses. Cert desig…
metadata:
  type: reference
tags: [sess95, step5.3, authority-token, foreign-replay, D-FOREIGN-REPLAY-UNGATED-IMAGES, wire]
---

# sess95 — step 5.3 wire half LANDED (0.11.428), producer half designed

Build: 0.11.428, `srcversion 5F32C0A9659593C792644E1`, builds clean (only the tree's
pre-existing `struct iomap` / `_mxfs_ioend_bioset_compat` warnings). **NOT deployed, NOT
rig-verified.** Wire size unchanged at 40B — no v3, no proto_gen bump.

## What landed (xfs/libxfs/xfs_log_format.h + xfs/xfs_log_recover.c)

1. **`MXFS_AUTH_CLASS_ICLUS = 4`** + `MXFS_AUTH_CLASS_MAX = 5`. This closes the ruling's
   largest release blocker. An inode's grant is backed by EITHER the per-inode CAW slot
   (`MXFS_LTYPE_INODE`) or the inode-CLUSTER slot (`MXFS_LTYPE_ICLUSTER`), chosen at
   acquire and recorded in `ip->i_dlm_routed_iclus`. Durable epochs from those two slots
   live in DIFFERENT NAMESPACES and are not comparable, so `class=INODE, resource=ino`
   was not self-describing — recovery could compare an epoch against the wrong slot. Now
   the CLASS names the resource TYPE and `mba_resource` carries that type's exact id:
   INODE→ino, ICLUS→**cluster base ino**. Reconstructs the CAW resource with zero
   inference. The logical owner is not lost by ICLUS: the replayed image carries its
   owner in its own v5 header, which recovery must cross-validate anyway.
2. **Five new non-proving statuses** (ruling Q5): `OWNER_UNKNOWN(9)`,
   `AUTH_NOT_CACHED(10)`, `AUTH_NOT_HELD(11)`, `EPOCH_UNAVAIL(12)`, `AUTH_RACED(13)`,
   `ST_MAX → 14`.
3. **`mxfs_auth_st_proves(st)`** — VALID is the ONLY status that asserts provenance, so a
   gate can never be written as "not one of the bad ones" (which silently admits every
   future status an older node has not heard of).
4. **Parser rejects an out-of-range CLASS as MALFORMED.** An unknown class makes
   `mba_resource` uninterpretable, not merely unproven — same reasoning as the
   reserved-bits rejection.

## The ruled producer design (NOT yet written)

Immutable per-grant certificate `{ino, grant_epoch, local_seq, backing_resource,
backing_kind, active}` behind ONE RCU pointer `ip->i_mxfs_auth`. Published only after a
durable EX acquire succeeds; unpublished at the FIRST release-begin boundary; never
reactivated (a reacquire mints a new one). **The registry is already there**: the per-AG
inode radix tree `pag_ici_root` IS an RCU registry keyed by inode number. Format-time
peek = `rcu_read_lock` → `radix_tree_lookup` → validate `ip->i_ino == ino` (the standard
XFS RCU-lookup pattern; XFS inodes are RCU-freed) → `rcu_dereference(i_mxfs_auth)` → copy
→ recheck same certificate. No reference, no iget, no iput, no torn tuple, non-blocking.

## Exact remaining edit list

- `struct mxfs_inode_auth` + `struct mxfs_inode_auth __rcu *i_mxfs_auth` on `xfs_inode`;
  publish / clear / peek helpers.
- **Publication-lifecycle audit.** ~15 `i_dlm_mode` writers. The 9 sites bumping
  `i_dlm_epoch` (`ip->i_dlm_epoch++; i_dlm_epoch_src = __LINE__; mxfs_relbar_epoch_check`)
  are ALMOST the grant-loss chokepoint, but they do NOT cover everything:
  `xfs_mxfs_dlm.c:27404` and `:31924` set `mode = NL` WITHOUT bumping, and `:41334` bumps
  with no adjacent `mode = NL`. Each needs individual handling.
  **Publish must be SKIPPED for `i_dlm_unpublished` / `i_mxfs_self_created` grants** —
  those hold EX locally with NO on-disk slot ever claimed, so there is no durable epoch
  and a certificate would be a false claim.
  Acquire-success sites to publish at: `xfs_mxfs_dlm.c` ~28370, ~28634, ~29418.
- **Owner derivation**, at buffer offset 0 ONLY (`xfs_buf_offset(bp,0) == bp->b_addr`,
  valid for discontiguous buffers too): `xfs_dir3_blk_hdr.owner` (dir data/block/free),
  `xfs_da3_blkinfo.owner` (leaf1/leafn/da-node/attr leaf), `xfs_attr3_rmt_hdr.rm_owner`,
  `xfs_dsymlink_hdr.sl_owner`, `xfs_btree_block.bb_u.l.bb_owner` (bmbt). Derive ONCE PER
  BUFFER LOG ITEM and cache it — never per segment; all segments of a discontiguous
  buffer must carry identical fields. Validate hard: b_ops family, magic, header fits,
  UUID, plausible ino, magic-vs-BLFT agreement, and for bmbt that it is a LONG-format
  inode-owned block, not an AG btree admitted through the generic `XFS_BLFT_BTREE_BUF`.
- Producer ladder; then the parser/reporter names the new statuses.
- **NO AG FALLBACK**: if owner derivation or the peek fails, keep a non-proving status —
  never the containing AG's epoch, which is exactly how the 29% got mislabelled.

## Why the first landing is unambiguous

The measured mislabel population (0.11.427 rig: `P228-TOKCLASS n=16384 ag=11613
mislabel=4770 unknown=0 incomplete=0`, `mis_blft t10=106 t11=1675 t12=1299 t13=376
t14=1309 t15=5`) is **100% directory blocks**, and directories route per-inode, not
iclus. So the whole measured population has one unambiguous backing resource even before
the ICLUS path is exercised.
