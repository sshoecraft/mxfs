---
name: sess-tcp-tcp-dlm-scaling-DOUBLE-GRANT-proven
description: PROVEN: tcp_dlm_scaling leftover = TCP DLM DOUBLE-GRANT of dir-EX (P106 timeline). It's a HEISENBUG — per-lock logging hides it. Fix = DLM mutual-exc…
metadata:
  type: project
---

## STATE: 2/tcp = 15/16. tcp_dlm_scaling ~50% flaky. CRITERION NOT MET (no YES).
DEPLOYED BUILD = **98EC6332DCE76B24C5E1038** (both nodes). Behaviorally == 73B0809D at default
params: carries the B4 inode guard (KEEP, [[sess-tcp-B4-noauth-guard-fixes-fast-repro-wedge]])
+ THREE dormant diagnostic gates (all OFF by default, no perf cost):
  - mxfs.instr (heavy, 100x), mxfs.dirwr (dir coherency probes), mxfs.lockwr (NEW: P-LKT DLM
    lock-table entry-lifecycle trace in dlm/dlm.c), P-RDDIAG (readdir grant mode, instr-gated).
prep_node.sh MODARGS reverted to clean `force_transport=1`.

## PROVEN ROOT: TCP DLM DOUBLE-GRANT of the parent-dir inode EX.
FAST REPRO: `./run.sh 2 tcp tcp_dlm_scaling` STANDALONE ~50% FAIL (a fail wedges the FS →
reboot+reset between attempts). Leftover = 1 dirent, EITHER node's file, both nodes agree,
on-disk, nlink=1 (rename+rm reverted) or nlink=0. P-REG-DURABLE-FAIL=0 (releases ARE durable —
the node durably wrote the WRONG content because a peer concurrently RMW'd the same dir block).
PROOF (P106-EXGRANT/EXREL cross-node, both UTC, dir ino): one node held EX ~6.2s while the OTHER
acquired+released EX TWICE inside that window = BOTH hold dir-EX → concurrent RMW → one durably
reverts the other. The master granted node B EX while node A's holder entry was (transiently)
absent from the master table.

## IT IS A HEISENBUG: enabling mxfs.lockwr=1 (per-lock-op P-LKT logging) made it 6/6 PASS — the
small per-op delay closes the race. So in-kernel per-op tracing CANNOT catch the removal. The
6.2s hold ≈ MXFS_LOCK_ACQUIRE_WAIT_MS (6s -ETIMEDOUT retry interval,
[[sess-tcp-FIX-etimedout-retry-posix-multi-PASS]]) → the lost-grant TIMEOUT+RETRY is implicated:
a holder's master-table entry is removed (lost LOCK_RELEASE / Bug-51 stale-re-request removal at
dlm.c:2081-2176 / 890-911) while the holder still has it cached, then the retrying peer is
granted. The -ETIMEDOUT retry fixed STALLS but introduced/exposed this CORRUPTION race.

## FIX DIRECTION (next session): a DLM-protocol mutual-exclusion fix, NOT a cache trick (eviction
REFUTED: both holders' blocks are dirty; gen-bump-on-release REVERTED, regressed crash_consistency).
Options: (1) FENCING/GRANT GENERATION token — master stamps each grant with a monotonic gen;
a holder carries it; any re-grant bumps it; a stale-gen holder must re-validate before modifying
(robust, implementable without catching the race). (2) Make the holder's entry removal SAFE: never
remove a GRANTED holder's master entry except via that holder's OWN authenticated LOCK_RELEASE
(audit the Bug-51 stale-removal + membership purge + duplicate-release paths). (3) On -ETIMEDOUT
retry, the master must re-BAST the current holder and NEVER grant while a holder entry exists;
verify the retry can't race the holder's entry to absent. To DEBUG without perturbation: a
lock-free per-CPU event ring (record grant/remove, NO printk in hot path) dumped only at the
leftover — printk-based tracing is fatal here.
See [[sess-tcp-tcp-dlm-scaling-flaky-dir-lostupdate-root]] [[sess-tcp-posix-multi-FINAL-root-lost-dlm-grant-msg]].
