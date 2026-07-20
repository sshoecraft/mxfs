---
name: sess5-END2-run37-dirent-loss-epochplace-unestablished
description: sess5 END2 (build E2599275): ABBA CLOSED (runs 34/36/37 zero shutdowns/-110). Last correctness bug pinpointed: P13-STALEREAD add onto near-empty reus…
metadata:
  type: project
---

# sess5 END2 — final state @ build `E259927545EBA17A6CCCE6A` (deployed on cluster, in tree)

READ WITH: [[sess5-THREE-ROOT-FIXES-p5f-p91bast-abba-plus-remaining]] and [[sess5-END-abba-grow-stack-proven-design-next]].

## Landed this session (all verified live, in order):
1. P5F-FRESHSRC-SELFCLOBBER-SKIP (`5EEF85D0`) — class-B creator self-clobber closed.
2. P91-BAST-PROTECT (`19E885B1`) — iflush-strand wedge closed (P113=0 since).
3. AG wire probes (`F560EC18`) — P5B/P5R/P5U(+P5N/P5W dirwr).
4. P5D-PREWAIT-DEFERRED-BAST (`6E8DFC0C`) — ABBA edge-1 (clean-trans dialloc side).
5. **mxfs_ag_dlm_lock_bounded + dirty-trans routing in xfs_alloc_vextent_prepare_ag (`E2599275`)** — ABBA edge-2: dirty-trans blocking AG acquires (dir-grow btalloc, stack-proven) now bounded 40×100ms → -EAGAIN → existing skip-to-next-AG path (iterate_ags `!agbp → continue`); sweep terminates at an own-held AG. Total-sweep-failure worst case lands in the existing xfs_inode.c:1560 dialloc-ENOSPC orphan bailout (no dirty cancel). New header decl in xfs_mxfs_dlm.h; P5G-AGLOCK-BOUNDED-BUSY names exhausted bounds.

## Result across runs 34/36/37: shutdown + -110 family GONE (0/0/0). P5G never even needed yet.

## THE ONE remaining correctness bug — single durable dirent loss (~1 per 15-20 rounds)
run37 r18 victim node6_f30, 799/800 unanimous. THE ADD ITSELF IS INSTRUMENTED (ungated probes, fired t512.26 test6):
```
P13-LADD ino=131 use_block=2 daddr=16745864 aoff=288 grown=0 name=[node6_f30]
P13-STALEREAD ... bf0len=3784 — REUSED data block read near-EMPTY (stale/reverted read of a should-be-full block)
P2-EPOCHPLACE ino=131 daddr=16745864 master_ep=0 valid_ep=1390 b_ep=1390 unestablished=1 stale_base=0
```
⇒ test6 placed its dirent onto a STALE NEAR-EMPTY image of dbno=2 during an EX tenure whose **dir epoch was UNESTABLISHED (master_ep=0)** — every epoch-gated coherence guard inert. Its stale image later lost the write race to a peer's fuller image → net loss = exactly the victim's own entry. This is the RESIDUAL of sess1's grant-epoch-visibility-order fix ([[sess1-ROOT-FIX-grant-epoch-visibility-order]]): some EX grant path still delivers/arms dir_epoch=0.
NEXT: on test6 run37 t505-513, trace how its dir-131 EX arrived (P37-GRANT-RECV gen/handoff, P64-MASTER-HANDOFF, promote vs local-immediate vs upgrade path) → find the grant path that leaves mxfs_v5_dlm_inode_dir_epoch()==0 → make EX unusable-for-modify until epoch established (or force FUA re-read of dir data when P2-EPOCHPLACE unestablished — the P13-STALEREAD condition itself (reused block reading near-empty) is a strong guard candidate: refuse + re-read coherent).
run37 ledger: scratchpad/run37 (default modargs). For write-ledger confirmation catch it under dirwr=1 (P35E-DIRWR/P50-WR/P29-DATAWRITE).

## Remaining blocker 2 — pacing: 26-28s/round; need ≤20s (480s/24rds); healthy ref 14s
Zero-failure runs now reach r18-20 of 24. Attack: P36-RETRY 1.02s dir-handoff stalls (~92/run/node); measure P37-GRANT-RECV matched=0 rate (grant arrives after pending timed out ⇒ wasted 1s per event); DRCph create/verify/rm phase split.

## Ladder: dirent-loss fix → pacing → 8/tcp ×5 clean → 4/2/1 → full suites N∈{1,2,4,8} → YES.
Cluster: 8 VMs up, build E2599275 loaded. Awareness doc xfs.md updated (sess5 section).

## Addendum — grant path NAMED (run37 test6 t512)
```
512.247 P37-GRANT-RECV ino=131 mode=PR  gen=31728 matched=1
512.249 P37-GRANT-RECV ino=131 mode=NL  status=10 gen=0     ← PR→EX upgrade DENIED (MXFS_ERR_UPGRADE_CONFLICT → EDEADLK, P109/P-CONVBLK design)
512.260 P37-GRANT-RECV ino=131 mode=EX  gen=31736 matched=1  ← fresh re-acquire after drop
512.263 P2-EPOCHPLACE master_ep=0 unestablished=1            ← 3ms later: epoch NOT established
```
⇒ The **post-EDEADLK drop-and-fresh-reacquire path delivers EX without establishing the dir epoch** (sess1's mirror-reconcile-before-signal fix covered the normal grant path; this flow bypasses it — check dg_grant_ex/handoff propagation and the receiver mirror update for this path, plus process_remote_grant's have_mirror update branch: it updates gen/handoff/dir_epoch only if dir_epoch>existing — a 0-epoch grant leaves mirror stale-0 if the mirror was fresh-inserted...).
FIX CANDIDATES (next session): (1) make the deny→reacquire EX carry dir_epoch like promote path (master side: the fresh WAITING→grant goes through dg_grant_ex — verify it does for this flow and that the receiver reconciles when the PRIOR mirror was just dropped); (2) belt+braces receiver gate: if P2-EPOCHPLACE unestablished AND P13-STALEREAD condition (reused block reads near-empty), refuse placement + force coherent FUA re-read of the dir data block before addname proceeds.
