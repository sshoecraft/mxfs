---
name: ccloop-c7ee71c6-sess82-step5.1-SHIPPED-mislabel-27pct-MEASURED
description: sess82: step 5.1 SHIPPED (0.11.419) and the sess81 ruling's hypothesis (A) PROVEN BY MEASUREMENT — 27.2% of authority tokens carried the wrong resour…
metadata:
  type: reference
tags: [foreign-replay, authority-token, step5, sess82, rule4, measured, shipped]
---

# sess82 — step 5.0 + 5.1 SHIPPED (0.11.419, srcversion `4A60BCF3FAAA80055570F20`)

Implements exactly the sess81 RULE-5 ruling's landing order. Producer-side
only; **no replay decision changed** (v1 stays report-only, blanket taint
intact), so it is independently safe.

## What landed

**5.0 — v1 marked report-only PERMANENTLY** (`xfs_log_format.h` at
`MXFS_BLF_AUTHORITY_V1`, `xfs_log_recover.c` above
`mxfs_report_replay_authority`). The old comment still pointed the next
session at the refuted exact-match gate; it now records *why* v1 can never
gate an apply: `mba_resource` is a `__be32` agno (cannot name an inode),
`mba_owner_boot` is memset 0 and never filled (cannot bind to a victim
incarnation).

**5.1(a,b) — grant-state lifecycle.** `pag_mxfs_grant_epoch` now has a stated
invariant (documented at its declaration in `xfs/libxfs/xfs_ag.h`):
*nonzero ⇔ this node positively holds the AG EX grant at that durable epoch
AND no release of it has begun.* All writes under `pag_dlm_lock` via
WRITE_ONCE; sole lock-free reader is the format site via READ_ONCE.

- publish: `xfs_mxfs_dlm.c` fresh-acquire (unchanged site, now WRITE_ONCE)
- clear: **`pag_dlm_demoting = true`** (bast_work_fn Phase 2 — the release
  COMMIT point, strictly before every drain/flush/unlock of that release)
- clear: `mxfs_dlm_ag_force_release_all` (unmount) where `cached=false`
- clear: the single→multi administrative surrender (next to the P130
  `pag_dlm_lineage_open = false`)

Cached fast-path re-acquire deliberately does NOT touch it — the slot was
never yielded, so the epoch still stands.

**5.1(c) — classification conjunction** (`pal/linux/xfs_buf_item.c`, new
`mxfs_buf_ag_authorized()`). `b_ops` is the PRIMARY discriminator against an
allowlist of nine genuinely AG-authorized ops (agf/agi/agfl/bnobt/cntbt/
inobt/finobt/rmapbt/refcountbt), **AND** `xfs_blft_from_flags()` must agree,
**AND** the epoch must be nonzero. Anything else ⇒ `MXFS_AUTH_CLASS_NONE`.

**5.1(d) — the measurement**, new probe `P228-TOKCLASS` (same build).

## THE MEASUREMENT — hypothesis (A) PROVEN, not code-read

40960-token sample, one node, ordinary metadata workload (nested tree, 3000-
entry dir, symlinks, xattrs, fragmented files):

    P228-TOKCLASS n=40960 ag=29814 sb=2 mislabel=11144 noepoch=0
      mis_blft: t4=27 t10=2116 t11=3188 t12=2500 t13=688 t14=2511 t15=114

- **mislabel = 11144 / 40960 = 27.2%** of all authority tokens were being
  stamped `class=AG{containing agno}` for buffers the AG grant does not
  authorize. Under the refuted step-5 scope every one was exact-APPLY
  eligible against the victim's AG grant — i.e. eligible to revert a
  survivor's committed write.
- **t4=27 is the decisive detail**: BLFT `XFS_BLFT_BTREE_BUF` on inode
  **bmbt** blocks. A BLFT-only discriminator would have accepted them as AG
  btrees. This is GPT's conflation warning, measured.
- t10/11/12 = DIR_BLOCK/DIR_DATA/DIR_FREE, t13/14/15 = DIR_LEAF1/LEAFN/
  DA_NODE — all inode-authority, all previously mislabelled.
- **noepoch = 0** across 40960 tokens: the lifecycle clear has ZERO
  false-negative cost. Confirms the reasoning that `holders > 0` blocks the
  demote for the life of any transaction touching AG metadata.
- ATTR_LEAF/SYMLINK never appeared (small xattrs + short targets stay in the
  inode fork) — unmapped types, correctly rejected, just not exercised.

## Consumer side — confirmed on a REAL foreign replay

`tests/foreign_replay_ab.sh 32 5 0` (victim test5, replay on test1 at t+64s):

    P227-TOKEN blkno=54423826 len=1 class=1 res=26 epoch=1 slot=26
    P227-TOKEN blkno=54423896 len=8 class=0 res=0  epoch=0  slot=26   <-- was AG
    P227-TOKENSUM buf_items=4 tokened=4 ag=3 sb=0 classless=1 untagged=0

`classless=1` is a record the old rule would have shipped as
`class=1 res=26 epoch=1`. `VISIBLE dirs=40/40 files=40/40 size_ok=40/40`.
`tests/openunlink_deaths.sh unlinker_death` → PASS, shutdowns=0.

## Still open on defect #1

Steps 5.2–5.6 per the sess81 ruling. **The dir-image false-SKIP that makes
this defect critical does not close until 5.4** (inode authority class);
5.3 (audited AG-metadata-only apply) is real progress but does not touch it.
