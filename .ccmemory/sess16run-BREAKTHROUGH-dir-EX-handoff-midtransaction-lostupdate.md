---
name: sess16run-BREAKTHROUGH-dir-EX-handoff-midtransaction-lostupdate
description: sess16(ccloop) BREAKTHROUGH (PROVEN via P-DIRWR count timeline): dir_reuse loss = EX grant handed off MID-TRANSACTION. Node reads dir block under EX…
metadata:
  type: project
---

## sess16 (ccloop 4cb2d0a2) — PROVEN ROOT of dir_reuse 8/tcp leaf/block lost-update

### The decisive evidence (P-DIRWR count timeline, dirwr=2, 8 nodes, daddr=120 block-format dir block)
Round 1, sorted by realns:
```
865112 test1 cnt=2  (xfsaild)
865159 test4 cnt=126 (dd)   <- test4 grew block to 126 entries
865384 test2 cnt=77  (dd)   <- 225us later test2 writes only 77  *** REVERT 126->77 ***
865388 test2 cnt=78..92    <- test2 grows from its stale 77 base
865440 test1 cnt=93 ...
```
test2 durably wrote daddr=120 with 77 entries 225µs AFTER test4 committed 126 — dropping ~49 of test4's entries (the durable multi-dirent loss incl node1_f1). Two nodes RMW'd the SAME shared dir block from DIVERGENT bases essentially concurrently.

### Mechanism (unifies the whole 90-session dir-coherency saga + the mht knob)
A dir-modify (xfs_dir2 addname) holds the dir **ILOCK** for the whole transaction, reads the dir block into the transaction (base=77), then commits. mxfs's DLM EX **grant** is separate from the ILOCK: on a peer BAST the grant is released to the peer WHILE the local transaction still holds the dir buffer joined/dirty. The peer (test4) then modifies the block (→126). When this node (test2) re-acquires and commits, its buffer is still based on the stale 77 — it never re-read → durable clobber. NOT a read-cache staleness ([[sess16run-mht50-dirreuse-loss-durable-survives-forcecoherent]]: survives force_coherent/postread_reread) and NOT a literal double-grant — it's serialization broken by **mid-transaction grant handoff**.

### Why mht is the speed/correctness knob (RESOLVED)
`inode_mht_ms` (EX min-hold-time) defers the BAST by a fixed time. mht=300 keeps the grant long enough that the dir-modify transaction COMMITS before the grant is handed off → no mid-RMW loss → dir_reuse PASS (but slow → tcp_dlm_scaling FAIL). mht=50 releases the grant mid-transaction → lost update → dir_reuse FAIL (but fast → tcp_dlm PASS). Time-based mht is a CRUTCH; the window between "long enough to be correct" and "short enough to be fast" is EMPTY.

### THE FIX (next: transaction-scoped grant hold, frequency-independent)
Defer honoring a BAST on a dir inode while a LOCAL transaction has that dir's buffers in-flight (uncommitted): i.e. hold the EX grant until the dir-modify transaction COMMITS (the dir inode unpins / its dirty BLIs clear), regardless of mht. This is correct (no mid-RMW handoff) AND fast (hold only as long as the actual transaction, not a fixed 300ms). Check mxfs_dlm_mht_defer_bast / mxfs_dlm_bast_process (~5719): make the defer condition "dir inode pinned / has dirty joined buffers / transaction in progress" instead of (or in addition to) the time window. Likely signal: ip->i_pincount>0 or an in-core "dir modify in progress" marker set across xfs_dir2 addname/removename. ALTERNATIVE: on EX re-acquire after a handoff, force-invalidate+re-read any dir buffers still joined to an in-flight transaction (harder — buffer is mid-txn).

### VALIDATE
Set mht LOW (e.g. 50) + the transaction-scoped hold → dir_reuse 8/tcp PASS (no daddr count regression in P-DIRWR) AND tcp_dlm_scaling ≤60s → then full ./run.sh 8 tcp = 17/17, then 1/2/4. Repro/trace: `MXFS_EXTRA_MODARGS='inode_mht_ms=50 dirwr=2' MXFS_TEST_ENV='DRC_ROUNDS=2' ./run.sh 8 tcp dir_reuse_coherency`; merge P-DIRWR owner=131 across nodes, sort by realns, grep daddr=120 count regressions. Build BAB5566E. See [[sess51-ROOT-tcp-dlm-scaling-is-symmetric-PR-EX-dir-upgrade-livelock]] (the PR→EX upgrade is the same grant-vs-ILOCK split).</body>
