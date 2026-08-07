---
name: ccloop-c7ee71c6-sess49-STEP3b-SHIPPED-VERIFIED-token-parser
description: sess49 STEP-3b SHIPPED+VERIFIED (0.11.398): recovery-side authority parser decodes tokens live on a real foreign replay — class=AG, agno arithmetical…
metadata:
  type: project
tags: [foreign-replay, authority-token, D-FOREIGN-REPLAY, step3b, verified, 0.11.398]
---

# Step 3b SHIPPED AND VERIFIED — 0.11.398 (build 75912159E01100C0AAF4769)

Report-only recovery-side parser for the sess48 authority trailer.
Campaign context: [[compiled-foreign-replay-authority-tokens]].

## Code (xfs/xfs_log_recover.c, immediately before xlog_recover_items_pass2)

- `mxfs_blf_parse_authority(item)` → `const struct mxfs_blf_authority *` or NULL.
  Order matters: `ri_cnt<1 || !ri_buf` → `xfs_buf_log_check_iovec()` (safe for any
  iov_len; it length-checks before touching blf_map_size) → `ITEM_TYPE()==XFS_LI_BUF`
  → `blf_flags & XFS_BLF_MXFS_AUTHORITY` → `blf_map_size <= XFS_BLF_DATAMAP_SIZE`
  → **recompute** `base = offsetof(blf_data_map) + blf_map_size*4` → require
  `iov_len >= base+24` → `be16(mba_version)==1`. NULL == "no authority", fail closed.
- `mxfs_report_replay_authority(log, trans, item_list)` — called from the top of
  `xlog_recover_items_pass2` under `xlog_is_mxfs_untrusted_replay(log)` **regardless
  of the apply knob**, so both foreign_replay_ab.sh arms are comparable. Emits
  per-item `P227-TOKEN` (cap 400) + per-transaction `P227-TOKENSUM` (cap 2000).
  **Decides nothing** — the ATOMIC-SKIP and P223 gates below are byte-identical.
- `tests/foreign_replay_ab.sh` step 6 now harvests P227_ATOMIC_SKIP,
  P227_TOKEN_DETAIL/AG/SB/NONE, P227_TOKENSUM, P227_UNTAGGED.

## Verification — live 32/caw foreign replay, victim test9 (`tests/foreign_replay_ab.sh 32 9 0`)

Replayer test1, t+77s: `foreign replay of dead slot 18 (slice 2/4)`.

    P227-TOKEN blkno=37678033 len=1 class=1 res=18 epoch=1 slot=18 boot=0
    P227-TOKEN blkno=37678048 len=8 class=1 res=18 epoch=1 slot=18 boot=0
    P227-TOKEN blkno=37678040 len=8 class=1 res=18 epoch=1 slot=18 boot=0
    P227-TOKENSUM lsn=0x1000001c0 buf_items=3 tokened=3 ag=3 sb=0 classless=0 untagged=0
    P227-FR-ATOMIC-SKIP lsn=0x1000001c0 items=43
    VISIBLE dirs=40/40 files=40/40 size_ok=40/40

Independent corroboration, not just self-consistency:
- **agno is arithmetically right.** geometry (`chk_mxfs -v` on the backing img):
  blocksize=4096, agcount=50, dblocks=13082614 → agblocks=261653. AG18 starts at
  fsblock 4709754 = daddr 37678032. The three images are daddr +1 (len=1 sector,
  **AGF**), +8 (fsblock 1, **bnobt root**), +16 (fsblock 2, **cntbt root**) — a
  free-space allocation in AG 18, all carrying AG 18's epoch. Semantically correct.
- **owner_slot=18 == the dead node's disklock slot**, reported independently by the
  foreign-replay banner. The token binds to the right node instance.
- `untagged=0` — every buffer image of the foreign transaction was tokened; the
  step-3a emission has no coverage hole on this path.
- `boot=0` as designed (owner_boot lands with the step-4 descriptor).

## What this proves for step 5

That transaction was ATOMIC-SKIPped **even though all 3 of its buffer images were
authorized** — it has 43 items and the taint scan trips on item *type*, not on
authority. That is precisely the case the step-5 gate converts to APPLY.

## Caveat for step 4/5 measurement (not a defect)

One 40-dir+40-file workload + syncfs left only **1** dirty foreign transaction with
buffer items. That is a thin exercise for a gate. Step 5's A/B needs a workload that
leaves many dirty buffer transactions in the victim's slice (no syncfs, or a
long-running dirty writer killed mid-flight), or the gate will look "verified" on
a single sample.

## Rig note (cost 3 attempts this session)

clyde had rebooted (uptime 3h37m); `scst.service` was **failed** because
`/etc/scst.conf` still names the long-deleted `/home/steve/disk-1.img`. The 32-node
CAW rig does NOT use scst.service — recover with
`sudo scripts/scst_setup.sh setup` (target on /home/steve/disk.img) then
`sudo -E scripts/mpath_up.sh up 32`, then prep. See
[[rig-recovery-after-clyde-reboot-scst-mpath]].
