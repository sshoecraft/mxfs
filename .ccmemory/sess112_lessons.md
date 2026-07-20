---
name: sess112_lessons
description: sess112 — cache_coherency wedge ROOT pinned: root-dir inode left post-iflush_cluster/pre-bwrite (locked+DONE+off-list+IFLUSHING+in_ail, LEAKED b_sema…
metadata:
  type: project
---

## sess112 — cache_coherency drain wedge: ROOT pinned, force-unlock recovery FAILED

### PROVEN (RULE 4, direct live evidence)
The cache_coherency blocker on the current path = release-side drain wedge in
`mxfs_ail_drain_inode_sync` for the **root-dir inode (sb_rootino, ino=128)**.
Enhanced probe (`lb_*` fields, build A39E1130) + full task-stack dump nailed the
buffer state:
- `lb_flags=0x20` = **XBF_DONE ONLY** (NOT XBF_WRITE, NOT _XBF_DELWRI_Q, NOT
  XBF_STALE), `lb_onlist=0` (off ALL lists), `lb_pin=0`, `lb_locked=1`
  (b_sema.count==0), `lb_hold=4`. Inode: `in_ail=1 pin=0 ili_fields=0x0`
  (IFLUSHING, committed, flushed).
- **This is EXACTLY the state right after `xfs_iflush_cluster()` returns 0 and
  BEFORE `xfs_bwrite()`** — an abandoned flush.
- Full `/proc/*/stack` dump: **NO thread holds the buffer** (only the drain
  kworker spinning in msleep); **no SCSI/blk I/O errors** → not hung I/O →
  **b_sema is genuinely LEAKED**.
- Trigger: NEWARCH chokepoint `P109-EDEADLK ino=128 req=5` (PR→EX upgrade hits
  -EDEADLK, self-queues bast_work → drain). Preceded by `SESS50-STARVE ino=128`.
- SECOND face still present: 8× `P93-REVERT-CLOBBER` from xfsaild (stale bnobt
  nr=2 over disk_nr=3, all 4 AGs) at mount — one-time burst.

### Ruled OUT as leak site (code-read)
`xfs_inode_item_push` (always relse), `xfs_iflush_cluster`+`merge_dirs` (clean),
both durable paths `mxfs_inode_cluster_durable` (L438) and reg-durable (L2155)
ALWAYS pair iflush_cluster==0 → bwrite+relse. `bast_process` does NOT lock the
cluster before the drain. ⇒ leaker is a **RACE on the SHARED cluster buffer**
(ino=128 shares its cluster w/ siblings): a flush set IFLUSHING then abandoned
the write. NOT YET pinned to an exact call site.

### FAILED FIX (reverted)
Build 5B40B6AA added `P112-DRAIN-RECOVER`: force `xfs_buf_unlock`(leaked sema)→
re-lock→`xfs_bwrite`→relse. **REGRESSED**: test1 HARD-HUNG (ping alive, ALL
shells dead, VM running) the moment it would fire; test2/3/4 stayed clean
(P112=0). Force-`up()` on a sema with any real holder corrupts. REVERTED.
Confirms both Gemini+Grok: do NOT bolt recovery hacks onto the drain-in-BAST
locus — re-architect where the drain runs (GFS2 glock workqueue).

### Current build: `6403DE59` (built, NOT deployed)
- Enhanced P109 probe (li_buf direct read) KEEP.
- Force-unlock recovery REMOVED.
- NEW safe **leaker-capture**: `xfs_iflush_cluster` (xfs/xfs_inode.c, right after
  `__xfs_iflags_set(ip,XFS_IFLUSHING)`) logs `P112-IFLUSH-CALLER ino=128
  caller=%pS %pS` (rate-limited, root-dir only, NO lock manipulation).

### NEXT
Cluster was hard-reset (test1 was hung) — verify all 4 back up, `reset4.sh 4`,
confirm 6403DE59 deployed, run `tests/criteria/cache_coherency.sh --nodes 4`,
grep `P112-IFLUSH-CALLER` → the LAST caller before the P109 wedge = the path that
abandons the flush. Fix THAT site (ensure it always bwrite+relse, or never sets
IFLUSHING without completing). Then decide: targeted source-fix vs commit to the
GFS2-style drain-out-of-BAST re-arch (both AIs' strong rec; full writeup in
`/src/mxfs/CACHE_COHERENCY_ISSUE.md`). Marker NOT written — criterion FAILS.
</body>
