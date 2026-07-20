---
name: sess4-ROOT-FIX-unlock-fallback-eats-live-request-concurrent-EX
description: sess4(a16ec5f2) ROOT FIX: mxfs_dlm_unlock WAITING-fallback ate concurrent live request → dangling newlk → timeout freed recycled LIVE grant → concurr…
metadata:
  type: project
---

# sess4 ROOT CAUSE + FIX: dir_reuse dirent loss = DLM unlock fallback eating live requests

## The full proven chain (runs 19/20, P29 ledger + P4L pointer trace)
1. `mxfs_dlm_unlock` (dlm/dlm.c) has a fallback: if no GRANTED/CONVERTING local entry, it reaps ANY same-owner WAITING/BLOCKED entry. Bucket chains are LIFO → it eats the NEWEST — a **concurrent local thread's live in-flight request** (queued ms earlier by another op's dlm_lock_impl). Trigger: unlock paths that run with no GRANTED entry (orphan-release P135, double-release races).
2. The requester's `newlk` pointer dangles; kmalloc recycles the memory for a peer's entry (P4L-ALLOC/FREE trace proved: alloc ino=132 owner=local WAITING → 2.7ms later P4L-FREE ret=mxfs_dlm_unlock+0x165 → realloc to another node's entry).
3. The requester's pending is never signalable (entry gone) → guaranteed 1000ms `-ETIMEDOUT`; the timeout path's `lock_free(newlk)` then freed the RECYCLED LIVE entry. In run19 that was **test5's GRANTED EX gen 8210** (P52-GRANT-FREE ino=131 owner=623623663 ret=dlm_lock_impl+0x10cd, = dlm.c:1542) → holder vanished from master table → P36-RETRY → immediate re-grant to self (gen=0, immediate-grant path assigns no gen) → P-DOUBLEGRANT → **concurrent EX**.
4. test1 (phantom grantee) did a proper refresh + add node1_f34.md5 + write (P29 chain shows its write landing, Δxor=0x797=cino1943); test5 (real holder, never BAST'd/re-acquired, gg=8210 const) RMW'd its **stale pre-add base** and durably erased the add (P29: test5's buf = prior 103-entry image + own ino 0x2007BC while disk had 104). r=6 readdir=799.

## The fix (build 131347C2ACD739EEFEAE3BB, in-tree)
- `struct mxfs_lock.pend_waiter` (dlm/dlm.h): identity link to the local waiter's `mxfs_dlm_pending`. Set when dlm_lock_impl queues WAITING (pend now allocated BEFORE entry becomes visible), cleared at promote_waiters promotion and at the requester's own timeout-unlink.
- `mxfs_dlm_unlock` fallback SKIPS entries with `pend_waiter != NULL` (P4U-SKIP-INFLIGHT logs; fired 25× in run21 = the bug was recurrent, now blocked). Truly-abandoned leftovers (pend_waiter NULL) still reaped.
- Timeout path guard: only free newlk if owner==local && WAITING/BLOCKED && `pend_waiter == pend` (P4G-TIMEOUT-FREE-ALIAS logs otherwise; fired 2× in run20 with the interim guard, 0× post-fix).
- Probes added: P4L-ALLOC/FREE/PROMOTE %px lifecycle (dlm.c, capped 400k, ino<=256).

## Verification status
- run21 (fix build): **0 drc-RDMISS, 0 drc-FAIL, 0 P-DOUBLEGRANT/MX-DOUBLEGRANT, 0 P4G** through 9 rounds — but the run only reached ~9/24 rounds because round 8 took 143s: test2 (master) whole-guest silent 324.7→436.8s (112s; even non-mxfs kernel log silent, backlog drained instantly at wake → looks like host-side VM stall; host swap 6/7GB used, 16d uptime). Added guest hung_task_timeout=30s + all_cpu_backtrace in prep_node.sh for recurrence.
- NOT yet a full clean 24-round run. Class B failure still open (run19 r14-17, run20 r~10+): leaf-index loss — name IS in readdir but lookup ENOENTs (`lookup_fail=1 missing=[node8_f22.md5]` / run19 `node3_f21.md5 node4_f42`), durable across rounds. Suspect: same concurrent-EX root also corrupted leaf updates in those runs (both predate the fix) — re-measure post-fix before digging.

## Infra (sess4)
- prep_node.sh now streams `dmesg --follow > /root/dmesg.stream` per node (ring rolled at 17MB+ in dirwr runs; run18's failing round was unrecoverable).
- P29 cap 4000→100000, P56L→50000, P51-MOD→40000 (xfs_buf.c, xfs_dir2_data.c).
- P68-EVDECIDE/P4R-RELSTALE/P4O-OWNEVICT now log content fingerprint + in_cil + realns (xfs_mxfs_dlm.c).
- scripts/p29_replay.py: cross-node per-daddr write-chain replay (dsum/dxor of write i+1 must equal bsum/bxor of write i; NOTE cross-VM realns skew ~tens of ms — order by chain, not time, when interleaved <50ms).
- dir_reuse rounds ~24s healthy; run.sh 8-node budget 480s = 60*N.

Links: [[sess3-END-run18-evict-cil-window-hypothesis]] [[sess3-ROOT-FIX-sftorn-skip-consumed-ili-fields]]
