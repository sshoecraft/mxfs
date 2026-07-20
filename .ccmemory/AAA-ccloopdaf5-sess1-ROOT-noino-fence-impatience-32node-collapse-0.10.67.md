---
name: AAA-ccloopdaf5-sess1-ROOT-noino-fence-impatience-32node-collapse-0.10.67
description: SOLVED 2-layer: noino fence impatience (0.10.67) + REAL AIL freeze on _XBF_MXFS_ALLOC_QUEUED cluster bufs, PROVEN P-AILMIN, repaired by fence listdra…
metadata:
  type: project
tags: [ccloop-daf50d34, noino-fence, alloc-buflist, FLUSHING-deadend, root-cause, 0.10.68, PROVEN]
---

# ccloop daf50d34 sess1 — 32/caw posix_multi collapse: TWO layered defects, both fixed (RULE-4 complete)

## Layer 1 (0.10.67 = 27ACCECF): fence impatience
run69 (20260712T152205Z, 0.10.66): posix_multi rank1's 3200-file `ls` fans a noino BAST per file inode to every peer; the release fence gave the whole-AIL push 5×2s and treated "not landed in 10s" as a wedge → 5 nodes self-shutdown simultaneously → withdrawals → downstream wreckage (test18 EFSBADCRC inode cluster w/ prior-tenant file data "delete_me_14_18"; test1 P56 0x8; 31-node "pm barrier count" collapse from rank1 ls >120s COORD_TIMEOUT).
FIX: mxfs_noino_drain_fence() — progress-based: keep pushing while AIL min MOVES; wedge only on frozen min or 45-try (~90s) hard wall (<120s peer acquire timeout). Both work-fn and inline-OOM paths.

## Layer 2 (0.10.68 = 462A3DB0): the freeze was REAL — FLUSHING dead-end
run70 (0.10.67) still collapsed: 9 shutdowns, min FROZEN (min=0x100000780 static, stall=4 across dozens of works on test19). NOT impatience.
**PROVEN by P-AILMIN dump (stall==2) in run71:** frozen AIL-min item = `BUF len=32 bflags=0x500020 pin=0 ops=xfs_inode liflags=0x1` on multiple nodes = fresh inode-cluster buffer with **XBF_DONE(0x20) | _XBF_MXFS_ALLOC_QUEUED(0x100000) | _XBF_DELWRI_Q(0x400000)**. xfs_ialloc_inode_init queues fresh clusters on pag_mxfs_alloc_buflist with _XBF_DELWRI_Q preset → xfsaild's xfs_buf_item_push → xfs_buf_delwri_queue returns false → XFS_ITEM_FLUSHING forever (xfs_buf_item.c:697). These land ONLY via AG-release Phase-2 drain_alloc_buflist. A create-only stat-storm (posix_multi: 3200 creates, no rm) never fires AG BASTs → buffers sit → AIL min freezes at their BLI → every noino fence on the node stalls → (pre-fix) mass self-shutdown. dir_reuse never hit it: rm-churn constantly fires AG drains. The landmine armed when the whole-AIL noino fence was built (sess6-9 a864, 0.10.5x); posix_multi@32 was the first post-fence create-only test.
FIX: mxfs_noino_drain_mxfs_buflists() — at stall==3 the fence drains ALL AGs' pag_mxfs_alloc_buflist (bounded; only non-empty pay; drain submits sync + flushes). This COMPLETES invariant #1's contract: committed icreate state IS "everything this node committed". Wedge threshold now 8 stalls (repair gets 2 pushes to show effect). Probes: P-AILMIN (cap 24), P-NOINO-LISTDRAIN.
**VALIDATED run71 (20260712T160412Z, 0.10.68): posix_multi 32/32 PASS + mmap 32/32 PASS + zsl 32/32 PASS**; test29 shows dump→LISTDRAIN ags=1→fence completed, 0 shutdowns; cluster P-NOINO-DRAIN-RETRY=0 (repair fires before try=4 print).

## Un-landed-icreate corollary (explains run69 test18 corruption)
The alloc-buflist buffer IS the cluster init. A node shutting down/withdrawing with it undrained leaves the platter holding the PRIOR TENANT's bytes at the new cluster's daddr — peers then EFSBADCRC (or worse, adopt garbage). Any future "node died with alloc-buflist non-empty" scenario must rely on foreign journal replay of the icreate; worth a dedicated crash test later (not part of current criteria).

## State (16:10Z): run71 g1 6/12 PASS, remainder in flight (fairness, scaling_curve, dlm_scaling, rsync, soak, dlc). Then g2, dir_reuse@32 on 0.10.68, then 16/8/4/2/1 ladder. Epoch for matrix_check --since: 2026-07-12T16:04:00Z (0.10.68 first run).
