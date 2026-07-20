---
name: sess9run-FIX25-widen-ioend-admit-under-PR-wedge
description: sess9: test2 900s wedge = FIX-25 3-task cycle recurring with mirror at PR; widened admit (g2 EX or PR, no mode elevation on PR). Build ECEB2494.
metadata:
  type: project
---

# FIX-25 widening — ioend admit under PR (test2 fence/tds wedge)

## Live evidence (suite run 20260703T153340Z-era, test2 wedged 900s+)
- kworker/3:1 (xfs-conv): `xfs_end_ioend → xfs_iomap_write_unwritten → xfs_trans_alloc_inode → xfs_ilock → mxfs_dlm_ilock_begin` waiting EX on ino=4196260, `P73-WAITSTALL req=5 mode=3 state=3 ex=0 pr=0 work_busy=3` every 30s forever. P47-FILEBLOCK "fast path did not admit" — admit_ioend failed because granted mode g2==PR (old check required EX).
- kworker/u12:15 (mxfs-ino-bast ORDERED wq head): `bast_process → filemap_write_and_wait_range → folio_wait_writeback` — waits the folio whose ioend is above.
- ino's own queued bast: P76-QW-FALSE "work already pending" — can never run behind the stuck ordered-wq head.
- Cascade: bash truncate + sync also in D on folio_wait; fence_during_write 0/4 "fdw barrier survived" + tcp_dlm_scaling 0/4 "tds barrier churn" (test2 log EMPTY in both).

## Fix (mxfs_ilock_admit_ioend, xfs_mxfs_dlm.c ~15789)
Accept g2 == EX **or PR** (PR excludes any peer EX ⇒ no remote mutator can race the conversion; pending writeback is by construction our own tenure's data). Do NOT elevate i_dlm_mode in the PR case — the nested admit is scoped to the in-ioend task via ex_holders; other local threads stay off the EX fast path (avoids two-PR-nodes-both-self-elevating).

## Open deeper root (NOT yet fixed)
How does a pending unwritten conversion coexist with mode==PR at all? EX→PR should transit NL via a full bast drain (which waits conversions). Suspect: a write ran on a phantom/stale EX — see repeated `P78-PUB-PHANTOM ino=… master EX claimed while FS layer not EX` around `P9-NLEDGE reset4create` (create-reuse local-grant machinery). Same mirror/mode-divergence family as FIX-26. If wedges recur with the admit in place, chase P78.

## Also armed this build (CE3B/ECEB)
- P9-NLEDGE ledger at from_disk edges / reinit0 / reset4create with live s_remove_count — for the racy soak-failing `WARNING fs/inode.c:289 __destroy_inode` counter-underflow flood (7224 hits in run r2/A5DB, 0 in r3). xfs_reinit_inode recycle-at-zero is a PROVEN +1 inflation site (comment in code); the underflow source is still unidentified.
