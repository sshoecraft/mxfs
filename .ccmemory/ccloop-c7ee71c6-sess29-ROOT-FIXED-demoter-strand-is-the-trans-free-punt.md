---
name: ccloop-c7ee71c6-sess29-ROOT-FIXED-demoter-strand-is-the-trans-free-punt
description: ROOT PROVEN+FIXED: the stranded demoter claim is the P152 trans-free punt's deliberate retention that nothing ever ended. Same-build A/B, 0 strands.
metadata:
  type: project
tags: [mxfs, demoter, D-MOUNT-DEGRADES-WITH-USE, rule4, sess29, fixed]
---

# sess29 — the stranded demoter claim: root proven, fixed, A/B verified

Builds 0.11.247 → **0.11.251** (`1A742CB987396CF308AA038`).

## The chain, every link measured

1. `mxfs_inode_dlm_defer_bast` does `igrab` + `MXFS_SET_DEMOTER` and appends to
   `tp->t_mxfs_inode_unlocks`. This is the ONLY claim in the tree whose CLEAR is
   in a different function.
2. `mxfs_trans_drain_inode_unlocks` (from `xfs_trans_free`) has exactly one exit
   that skips the clear: the **P152-TRANSDRAIN-PUNT**, taken when the committing
   task still owns ILOCK-EXCL. It deliberately RETAINS the claim so the task
   stays exempt across its post-commit `xfs_iunlock`, and hands the release to
   the dwork.
3. Nothing ever ended that retention. The dwork's own `MXFS_SET_DEMOTER` finds
   slot 1 still held by the syscall task, lands in **slot 2**, and its trailing
   clear releases slot 2 only.
4. `mxfs_foreign_demoter()` then stays true for the life of the in-core inode:
   every reload pays `mxfs.reload_demote_wait_ms` and abandons with
   `i_dlm_stale` set → hundreds of bails on ONE inode (224/290/300/354) while
   healthy nodes show exactly 1.
5. **Second propagation step**: the inode is eventually freed *still claimed*
   (`P217-FREE-DIRTY-CLAIM`). `xfs_inode_alloc` → `alloc_inode_sb` →
   `kmem_cache_alloc_lru` does **not zero** the object, and the initializer
   cleared via `MXFS_CLEAR_DEMOTER`, which *refuses a non-owner clear*. So the
   next inode on that memory was born stranded, carrying a dead task's stamps.
   That is the `punt=0x0`, dead-pid, same-pid-across-8-inodes population.

Decisive counters: `P215-DEFER set=2 clear=0 retain=2` on four nodes — **every
deferral punted and the inline drain-clear never ran at all**. The retained path
is the normal path, not an edge case.

## The fix (all in 0.11.251)

- **Owner-driven end** (the real fix): `mxfs_dlm_ilock_end` — the exact unlock
  the retention exists to cover — consumes the retention. No grace, no liveness
  heuristic, no foreign clear.
- `i_dlm_punt_n[2]` **counts** retained acquisitions per slot, not a bit: the
  claim nests and one tp can defer the same inode twice (P130-DEFERBAST-DUP), so
  both entries can punt. A single clear would only decrement depth.
- **Sweep** (`mxfs_demoter_punt_reclaim_check`, from the two bast workers and
  the reload demote-wait) as a net for a task that never returns to its unlock.
  Grace **5000 ms** — see the trap below.
- **Recycle hardening**: force both slots NULL in the initializer; new
  `mxfs_dlm_inode_final_release()` immediately before `kmem_cache_free`.
- Fixed two real **use-after-free reads**: `P76-DEMOTER-FOREIGN-CLEAR` and the
  legacy-clobber path both dereferenced `ip->i_dlm_demoter->pid`, a
  reference-less `task_struct *` that dangles once the holder exits — which is
  exactly the observed state. Now print the stamped scalar.
- Gave **slot 2** the forensic stamps slot 1 had (pid/comm/line/set_ns).

## Same-build A/B, both arms from a fresh prep, identical workload

| arm | punt (exposure, knob-INDEPENDENT) | strand | bail | freed-still-claimed |
|---|---|---|---|---|
| `demoter_punt_reclaim=0` (pre-fix) | 4 | **1** | 15 | **1** |
| `demoter_punt_reclaim=1` (fix) | 6 | **0** | 3 | **0** |

Across builds: control 3 strands / 13 punts; fix **0 strands / 6 punts** with
`recl=0` (the owner-clear caught every one, the sweep never fired).
**Full board on 0.11.251: 4 punts, 0 strands, 0 dirty frees, balance=0.**

## Harnesses (RULE 3)

- `tests/demoter_strand_census.sh <n> [mark|full]` — window-scoped cluster
  census (bail/strand/punt/recl) + the P214 lines + the P215/P216 balance.
- `tests/demoter_punt_ab.sh <n> <arm> <iters>` — the A/B; stamps the window,
  runs a fixed exposure workload, honours `MXFS_EXTRA_KNOBS`.

## Still open

`D-MOUNT-DEGRADES-WITH-USE` stays OPEN: `rmrf` is 5-15 ms on a fresh mount and
~1050 ms after a full board — ~100x residual degradation, no longer fatal
(sustained_load 10 s / 180 s budget) but real and unattributed.
