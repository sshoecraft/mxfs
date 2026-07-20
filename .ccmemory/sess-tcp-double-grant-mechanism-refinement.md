---
name: sess-tcp-double-grant-mechanism-refinement
description: REFINEMENT of the tcp_dlm_scaling double-grant: holder never released (no EXREL) → it's a NON-release removal (Bug-51 stale-removal promoting a waite…
metadata:
  type: project
---

## Refines [[sess-tcp-tcp-dlm-scaling-DOUBLE-GRANT-proven]] — narrows the double-grant mechanism.

### KEY OBSERVATION from the P106 proof: the holder NEVER RELEASED.
test2 EXGRANT at realns ...482023 and its NEXT EXREL is ...488247 (~6.2s later) — NO EXREL in
the window where test1 acquired EX (...482400, ...482456). So test2 held EX continuously and did
NOT release. EXGRANT/EXREL are logged at the XFS layer (mxfs_dlm_ilock_begin ACQ-FRESH / BAST
release) = each node's belief it holds EX.

### THEREFORE (rules out a whole class of fixes — do NOT pursue these):
- NOT a stale/duplicate LOCK_RELEASE removing a live grant (the holder sent no release). A
  grant-sequence/fencing-token-on-RELEASE fix would patch a DISPROVEN hypothesis (RULE 4 violation).
- NOT the -ETIMEDOUT retry re-firing a release.

### REMAINING MECHANISM (strongest, unverified — needs non-perturbing trace): a NON-release
removal of the holder's master-table entry while the holder still holds it cached. Prime suspect =
the Bug-51 STALE-REMOVAL paths in dlm/dlm.c that remove a GRANTED entry on a RE-REQUEST and then
promote_waiters immediately:
  - local master: ~dlm.c:890-911 ("lock contention detected, re-queuing").
  - remote master: ~dlm.c:2081-2134 ("stale re-request ... conflicts with other holder", removes
    entry, then promote_waiters at ~2116 → grants the WAITING peer).
Hypothesis: the HOLDER (test2) re-requests its own lock (a PR->EX conversion, or a re-acquire
where i_dlm_mode transiently != EX so the XFS fast-path is missed), the master finds test2's
GRANTED entry AND a waiter (test1), REMOVES test2's entry, and promotes test1 to GRANTED — but
test2 was never BAST'd and still believes it holds EX (cached) → BOTH hold EX → concurrent dir-block
RMW → durable revert (the tcp_dlm_scaling leftover). The Bug-51 fix correctly handles "sender
re-requests after its own release"; the HOLE is "holder re-requests/converts while a waiter exists"
— removing+promoting without first BASTing/confirming the holder relinquished.

### NEXT SESSION (RULE 4): build a LOCK-FREE per-CPU event ring in dlm.c (record
{ts,action,ino,owner,mode} to memory, NO printk — printk/P-LKT logging HIDES this Heisenbug,
proven 6/6 pass with mxfs.lockwr=1). Dump the ring at the tcp_dlm_scaling leftover. Confirm WHICH
removal (890 / 2102 / 2116-promote) fires for the dir ino while the holder still holds, then fix:
likely make the stale-removal NOT promote a conflicting waiter until the holder is BAST'd and
actually releases (or skip removal when owner==current EX holder with no genuine release). TEST
empirically: standalone `./run.sh 2 tcp tcp_dlm_scaling` ~20x → fail rate must drop ~50%→0, then
full suite for regressions (esp. posix_multi which the original Bug-51 fix made pass).
Build deployed = 98EC6332 (B4 + dormant traces). KEEP B4.
