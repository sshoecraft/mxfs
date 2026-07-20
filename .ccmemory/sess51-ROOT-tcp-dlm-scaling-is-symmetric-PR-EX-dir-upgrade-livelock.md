---
name: sess51-ROOT-tcp-dlm-scaling-is-symmetric-PR-EX-dir-upgrade-livelock
description: sess51 PROVEN ROOT (live dmesg, 3/3 reliability fails): tcp_dlm_scaling residual = symmetric PR→EX dir-upgrade livelock on the hot shared dir. NOT th…
metadata:
  type: project
---

## sess51 (ccloop 8ddb16a2) — tcp_dlm_scaling residual ROOT FOUND (live-dmesg PROVEN)

### Symptom
Reliability loop (`tests/tcp/reliability_loop.sh 3`, clean reboot+reformat/run) = **0/3 runs 17/17**; the ONLY
failing test every run is `tcp_dlm_scaling` (nodes_pass 0/2, 1/2, 1/2). All other 16 tests pass reliably.
Build E67385C9 (Fix B kept). Test body (`tests/tcp/tcp_dlm_scaling.sh`): each node does 150 rounds of
`echo>f; mv f f.done; rm f.done` in a SHARED dir; must finish 150 rounds within a 60s WINDOW. Fail =
`completed rounds got=45/150` + `within window`(>60s).

### ROOT (PROVEN — captured 5+ min of LIVE thrash dmesg on test1 during run3 stall)
**Symmetric PR→EX directory-inode UPGRADE livelock on the hot shared dir.** NOT the sess13 inode↔AG
cross-resource deadlock (that yield exists + fires; irrelevant here). Evidence (test1 = MASTER, sender=test2):
```
P-CONVBLK-DENY sender=<test2> ino=<shareddir> held_mode=PR req_mode=EX (keep grant; deny->EDEADLK)
DLM inode lock failed: ino=128 mode=5(EX) rc=-35(EDEADLK)
P35-DIRHONOR ino=128 (bast_process drain+unlock)
P62-RELOAD-FORK-SHRINK ino=128 post_release=1
P112-IFLUSH-CALLER ino=128 ... mxfs_inode_cluster_durable <- mxfs_dlm_dir_inode_durable
```
cycling every ~6s, zero forward progress. ino=128 = `/mnt/shared` ROOT dir (confirmed `find -inum 128`).

### Mechanism
bash `open(O_CREAT)` does lookup(dir **PR**) then create(dir **EX**). mxfs CACHES the PR (holds till BAST),
so create becomes a PR→EX UPGRADE. Both nodes cache PR + both want EX → master's upgrade path
(`dlm/dlm.c:2574` CONVBLK-DENY, INODE-scoped) DENIES with -EDEADLK and does NOT bast the conflicting
holder. Sender (P109, xfs_mxfs_dlm.c:9370) drops PR→NL **through the full bast_process drain pipeline**
(mxfs_dlm_dir_inode_durable → mxfs_inode_cluster_durable: log_force SYNC + iflush_cluster + blkdev_flush)
and re-requests — re-colliding. ~440ms/op handoff (run1 got=45 rounds/60s). The MHT defer
(`mxfs_inode_mht_ms=300`, mxfs_dlm_mht_defer_bast 5719) only engages when WE hold **EX** — useless here
since the loser holds PR. The drain runs even on a CLEAN PR release (PR = read-only = nothing dirty) =
pure waste that AMPLIFIES the livelock.

### FIX DIRECTION (two complementary levers; fix one+measure per RULE 4)
1. **Cheap bounce**: skip the bast_process durability drain (mxfs_dlm_dir_inode_durable + dir-data drain)
   when the inode is provably clean (held PR, xfs_inode_clean, !in_ail, pin==0). SAFE — cannot regress the
   sess-tcp resurrection fix (that needs dirty/in_ail). Capture held mode at bast_process entry
   (ip->i_dlm_mode before line 4744 sets NL).
2. **Forward progress / break symmetry**: proactively demote cached PR→NL before an EX request on a DIR
   (convert deadlock-prone upgrade → clean FIFO NL→EX), OR deterministic node-id tiebreak in the P109
   EDEADLK recovery, OR loosen P35-ACQBAST-BATCH so the EX winner reliably gets the MHT hold window.

### NEXT
Instrument P106-EXREL drain_ms/tail_ms ALWAYS-ON (ratelimited) + decompose mxfs_inode_cluster_durable
(logforce/iflush/blkdev) at instr=0; reboot clean; `./run.sh 2 tcp tcp_dlm_scaling` standalone to confirm
it fails standalone too (or only in-suite), measure dominant cost, then apply lever 1 gated by module param
(A/B). Build E67385C9 on both nodes. Cluster free (loop done).
Related: [[sess50-ROOT-resurrection-is-fastpath-sfmerge-readd-FIX-B]] [[sess34-6s-dir-handoff-is-LOCK_ACQUIRE_WAIT_MS-deferred-bast]] [[sess13-cross-resource-dir-inode-ag-deadlock]]
