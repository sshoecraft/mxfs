---
name: sess36-timing-solved-mht300-and-stall-fixes
description: sess36: dir_reuse 2/tcp TIMING SOLVED (284s<300) via inode_mht_ms=300 + 4 stall fixes (build BC6D7A5E). Remaining blocker = dir-block lost-update (co…
metadata:
  type: project
---

## sess36 — dir_reuse_coherency 2/tcp: TIMING solved, correctness is the last blocker

### CRITERIA: only `dir_reuse_coherency` blocks 2/tcp (showstat: 16 PASS, 1 PENDING). Must record nodes_pass=2/2.

### THE TEST has TWO faces: (1) TIMEOUT (300s budget) and (2) CORRECTNESS (drc-FAIL=0).
24 rounds; both nodes write 100 entries (50 data + 50 md5) into ONE shared dir, barrier, both
cold-read (drop_caches) + assert readdir==200 AND every name lookup-able; rank1 rm-rf+recreates
the dir each round (inode/daddr REUSE stressor).

### TIMING — SOLVED. Root = dir-EX lock THRASHING (~20 handoffs/round; XFS drops/re-acquires the
dir ILOCK per file). Fix levers landed this session (all KEEP, build `BC6D7A5E`):
1. **inode_mht_ms=300** (was 50) — THE timing fix. Bigger MHT batching window → each node holds
   the dir-EX across its whole burst → ~2-4 handoffs/round not 20. Span 314s→**284s** (<300!),
   create totals 40s→14s. SET VIA `MXFS_EXTRA_MODARGS='inode_mht_ms=300'` (module_param, no
   rebuild). **NOT yet the code default — make `mxfs_inode_mht_ms=300` default OR pass the modarg
   in prep.** (xfs_mxfs_dlm.c:3510)
2. **dwork re-arm** (xfs_mxfs_dlm.c mxfs_dlm_bast_dwork_fn ~5306): the sess35 batching dwork, when
   it fired mid-burst (holders>0), CONSUMED i_dlm_bast_pending + set state=BAST and bailed; a
   re-acquire reset state→CACHED, losing the BAST → holder held EX IDLE 6s. FIX: keep bast_pending,
   stay CACHED, RE-ARM the dwork until quiescent (logs P36-MHT-REARM). Eliminated test2's 6s stalls.
3. **collect_post_promotion_basts unconditional** (dlm.c process_remote_release ~2935 + mxfs_dlm_unlock
   ~1597): was inside `if (grants)`, so a release with promoted=0 (waiter BLOCKED behind a holder
   that re-acquired ahead of it) fired NO BAST → 6s strand. Now fires whenever this node is master.
4. **MXFS_LOCK_ACQUIRE_WAIT_MS 6000→1000** (mxfs_dlm.h:268) + retries 10→60 (dlm.c:1385, keeps ~60s
   budget). Residual stranded waiters recover in ~1s not 6s. test1 stalls 6s→~1s.

Result with all 4 + MHT=300: test1 P34-ACQ-SLOW=0, test2=1 (one residual mutual-standoff 6s), span
284s. **Timing PASSES.**

### CORRECTNESS — THE REMAINING BLOCKER (flaky drc-FAIL 0..10 across runs; =1 in the MHT=300 run).
ROUND 15 both nodes: readdir=188/200, **missing exactly node1_f1..node1_f12** (rank1's first 12
DATA files; their .md5 sidecars + f13..f50 + all node2 entries survived). lookup_fail=0 → DURABLE
on-disk dir-DATA-block loss (both nodes agree after drop_caches), NOT a leaf-hash hole. The earliest
entries in the reused dir's first data block get clobbered. Smoking gun marker: **P31E-DATAINIT-ABA**
("get_buf/init about to ZERO a block holding live peer dirents") — a data block being ZEROED
(initialized) while it holds live dirents, on the REUSED daddr. Likely acquire-side stale dir-block
RMW: a node creates into round-15's reused dir using a STALE cached round-14 block. GPT plan item 6 =
invalidate the WHOLE dir data fork at the DLM-acquire boundary (blocking-safe) instead of the lazy
read-time TRYLOCK hook. NEXT SESSION: instrument P31E-DATAINIT-ABA in the failing round; the
data-init-over-live-dirents is the durable loss.

### TOOLING (sess36, RULE 3): `tests/drc_cap2.sh` (robust HOST-side dmesg streaming → tests/_cap/
<host>.log, survives prep; the sess35 node-side follower lost the file). `tests/drc_analyze.py t1 t2`
= per-round per-phase critical-path timing. Run: `export MXFS_EXTRA_MODARGS='inode_mht_ms=300';
bash tests/drc_cap2.sh`. Note: `make clean` DELETES tools → `make tools` after. Marker NOT written.
[[sess35-batching-fix-and-next-steps]] [[sess34-dirreuse-acquire-side-stale-rmw-trylock-skip]]
