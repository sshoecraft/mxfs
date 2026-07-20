---
name: sess128-ailstuck-single-node-many-files-wedge
description: sess128 part 2: posix_semantics blocker = single-node test_many_files AIL wedge. Stuck INODE item ino=6291584 libuf attached, pushable-looking, never…
metadata:
  type: project
---

# sess128 part 2 — posix_semantics wedge (single-node, deterministic repro)

## Context
cache_coherency now PASSES 4/4 (see [[sess128-root-fix-phantom-ex-rearm-unpublished]], fix build `CA701441`). Full `verify_ship.sh` then ran: **9/19 PASS**, first FAIL = `posix_semantics --nodes 1` via its 600s wall watchdog (the watchdog persists FAIL to JSON but prints no RESULT → verify_ship says "script crashed").

## The wedge (deterministic, single node)
`tests/run_tests.sh --nodes 1 --phase single --test test_many_files` on test1 wedges 100% (3/3 runs, ~40-50s in):
- 4× inodegc kworkers D-state in `xfs_ail_push_all_sync` (called from MXFS block in `xfs_inactive_ifree`, xfs_inode.c ~2202, "per-inode and bounded so the heavy push is safe" — refuted).
- test process D-state in `xfs_iget` (xfs_icreate; waits on inodegc flush).
- Subsequent `rm -rf`/dir opens block on ILOCK. Node needs virsh power-cycle.

## Probe evidence (P128-AILSTUCK in xfs_trans_ail.c push_all_sync wait loop, build `47FFBBC0187429F5375F6F1`)
AIL head NEVER advances past ONE inode item:
`INODE lsn=0x100000623 liflags=0x1(IN_AIL) ino=6291584 iflags=0x20000(MXFS_IF_FIRST_FLUSH) libuf=ffff... libuf_flags=0x30 pincount=0 ili_fields=0x1(ILOG_CORE)`
Items behind it: BUF liflags=0x9 (IN_AIL|DIRTY) bflags=0x30/0x200030.
- li_buf IS attached, not ISTALE, pincount 0, not IFLUSHING → xfs_inode_item_push should proceed to `xfs_buf_trylock(bp)` → `xfs_iflush_cluster` → delwri_queue. Yet the item sits IN_AIL forever and xfsaild idles (stack = top-of-loop schedule).
- ino 6291584 = 0x600000 (first inode of an AG). The sess118/sess119/sess17b iflush ghost-skips are all multi-node-gated → not it (and would detach item anyway).
- sess128's rearm fix is multi-node-gated → inert here. Wedge is PRE-EXISTING (posix_semantics never had a recorded completion in .criteria_results.json).

## NEXT (RULE 4)
Probe `xfs_inode_item_push` outcome for the stuck item: which branch fires (trylock fail → LOCKED? iflush_cluster error → LOCKED? delwri_queue false → FLUSHING?) and who holds bp's semaphore. Candidate suspects: cluster buffer held/locked by something that never releases (pag_mxfs_alloc_buflist Phase-2-only drain never runs single-node — the `_XBF_DELWRI_Q`+`_XBF_MXFS_ALLOC_QUEUED` design tension); or xfs_iflush_cluster erroring on the FIRST_FLUSH/resurrection guards. Decode libuf_flags 0x30 and 0x200000 bit against xfs_buf.h. Repro procedure: power-cycle test1 (D-state), insmod fresh, mkfs, mount, run the one test with timeout 150 (rc=124 = wedged), dump `P128-AILSTUCK`.

## Infra fixed this session (keep)
- test5–16 VMs redefined: shared-LUN source `/dev/sdc` → `/dev/disk/by-path/ip-127.0.0.1:3260-iscsi-iqn.2026-05.local.mxfs:disk1-lun-0`; NFS `/src` added to fstab; all 16 up, kernel 6.8.0-101.
- Bare `virsh` → `virsh -c qemu:///system` in tests/criteria/{lib.sh,fence_during_write.sh,crash_consistency.sh} (was silent no-op → fence/crash criteria would never kill the victim).
- `MXFS_NODE_OFFSET=16` exports in criteria scripts are VESTIGIAL (node naming uses MXFS_HOST_OFFSET, default 0) — not a bug, don't chase.
- RULE 5 rewritten (CLAUDE.md): Gemini/GPT = last resort per user directive.
