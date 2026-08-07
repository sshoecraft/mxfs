---
name: ccloop-c7ee71c6-sess28-ROOT-demoter-claim-outlives-its-holder
description: ROOT PROVEN: i_dlm_demoter claim leaks — holder PID is GONE while the claim is still set, so every reload on that node waits 50ms and bails forever.
metadata:
  type: project
tags: [mxfs, demoter, leak, D-MOUNT-DEGRADES-WITH-USE, rule4, sess28]
---

# sess28 — the demoter claim outlives its holder

Root of D-MOUNT-DEGRADES-WITH-USE's remaining component (after the readdir fix
cleared the setup phase).

## The proof

| node | P34J-RELOAD-DEMOTE-BAIL | distinct inode | distinct demoter_pid | P198 (successful waits) |
|---|---|---|---|---|
| test21 | **300** | 1 (8926798) | 1 (208840) | 0 |
| test22 | **290** | 1 (46675531) | 1 (17409) | 0 |
| test5 | 0 | — | — | 49 |
| test13 | 0 | — | — | 49 |

**Both demoter PIDs no longer exist** — `/proc/<pid>` is gone on both nodes
while the claim is still set and still being observed. The claim **leaked**:
some exit path in the release/BAST drain returned without
`MXFS_CLEAR_DEMOTER`.

`mxfs_foreign_demoter()` is then true for the life of the in-core inode, so the
sess22 demote-wait (`xfs_mxfs_dlm.c:19160`, bounded 50 ms) is paid in full by
**every** reload of that inode, then `P34J-RELOAD-DEMOTE-BAIL` abandons the
reload with `i_dlm_stale` still set, so the next syscall repeats it. That is
literally "a mount that must be remounted to stay in budget".

## How it was caught — the capture method matters as much as the finding

A node that blows the budget produces **no terminal record**, so the criterion's
aggregate line describes only the healthy majority. That is how `sustained_load`
reported `per_op=198ms` while nodes were stuck.

- `tests/suite/sustained_load.sh` now emits per-op progress to `/dev/kmsg` **as
  it happens** (`MXFS_SL BEGIN/SLOW/HB/CREATED/READDIR/REMOVED/SYNCED`).
  Trail: 30 nodes reach `SYNCED elapsed=1638..4760`; test21/test22 stop at
  `SLOW phase=rmdir k=8 ms=801/803`. **Reproduced 3×, same two nodes, same op.**
- `tests/sl_straggler_capture.sh` sweeps every node for non-heartbeat D-state
  stacks **during** the run. Post-mortem is useless — run.sh kills the test at
  its budget and the state is gone; the only D-state left afterwards is the
  normal bounded disklock heartbeat (`mxfs_pal_cond_timedwait` in
  `disklock_hb_fn`), which **must never be convicted** (state.md records that
  false positive).

## Why it is not a deadlock

5 samples over ~60 s: always `msleep` inside `mxfs_dlm_reload_inode+0x127`, but
from **different PIDs** (210880, 210999, 211113) and **different syscalls**
(83 mkdir, 217 getdents64, 257 openat, 262 newfstatat) and different callers
(`mxfs_dlm_dir_consumer_refresh`→`xfs_lookup`;
`mxfs_dlm_ilock_begin`→`xfs_ilock_data_map_shared`→`xfs_dir_lookup`;
`mxfs_dlm_dir_modify_reload_prelock`→`xfs_create`→`xfs_vn_mkdir`).
Not one stuck syscall — **every** syscall on the node pays the wait.

## Latent hazard found en route

`ip->i_dlm_demoter` is a bare `struct task_struct *` held **without a
reference**, so once the holder exits it dangles. `mxfs_foreign_demoter()` only
compares it (safe), but `MXFS_SET_DEMOTER`'s legacy-clobber A/B path
dereferences it (`(ip)->i_dlm_demoter->pid`) — a use-after-free, reachable only
under `mxfs.demoter_legacy_clobber=1`.

## Next

Build **0.11.246** (`303E25202F73654C4F056E2`) makes P34J print
`demoter_comm` / `demoter_line` / `demoter_age_ms`. `i_dlm_demoter_line` is
already stamped at every claim, so **one reproduction names the exit path** that
failed to clear it. Fix that path; a dead-holder reclaim is a safety net, not
the root fix.
