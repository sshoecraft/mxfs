---
name: ccloop-c7ee71c6-sess28-leaking-demoter-site-is-line-34955-trans-defer-unlock
description: The leaked demoter claim is set at xfs_mxfs_dlm.c:34955 (mxfs_trans_defer_inode_unlock) and cleared in a DIFFERENT function 127 lines later.
metadata:
  type: project
tags: [mxfs, demoter, leak, D-MOUNT-DEGRADES-WITH-USE, sess28]
---

# sess28 — the leaking demoter claim is line 34955

Build **0.11.246** (`303E25202F73654C4F056E2`). `P34J-RELOAD-DEMOTE-BAIL` now
prints `demoter_comm` / `demoter_line` / `demoter_age_ms`, and the first
reproduction separates two populations cleanly across 32 nodes:

| population | nodes | bails | line | comm | age |
|---|---|---|---|---|---|
| **healthy, transient** | test8, test20, test25, test30 | **1** each | 16541 | `kworker/u1x:x` | **150–156 ms** |
| **LEAKED** | test23 | **224** (one inode) | **34955** | **`mkdir`** | **179907 ms** |
| leaked | test15 | 354 | — | — | — |

A claim held by a **syscall thread** for the **entire 180 s run**, whose PID no
longer exists.

## The site

`xfs/xfs_mxfs_dlm.c:34955` — `MXFS_SET_DEMOTER(ip)` in
`mxfs_trans_defer_inode_unlock`, immediately after
`if (!igrab(VFS_I(ip))) { mxfs_pal_free(pending); return false; }`.

Its own comment: *"Cleared after bast_process completes in
`mxfs_trans_drain_inode_unlocks`"* — **set in one function, cleared in
another**, with the whole remainder of the transaction in between.

That is the **widest SET→CLEAR span in the file** (34955 → 35082, 127 lines,
across a function boundary). Every other pair is 6–75 lines inside one function:

    471   -> 477     6      26579 -> 26587    8
    28325 -> 28335   10     16870 -> 16882   12
    17961 -> 18007   46     16541 -> 16616   75
    34955 -> 35082  127  <-- the leaker

If the transaction is cancelled/aborted, or `drain_inode_unlocks` is not reached
for that pending entry, the claim is never cleared — and because it was taken by
a syscall thread that then exits, `mxfs_foreign_demoter()` stays true for the
life of the in-core inode. Every reload of that inode then pays the full
`mxfs.reload_demote_wait_ms` and bails.

## Next

Audit every path from that success return to `mxfs_trans_drain_inode_unlocks`
for exits that skip the drain (trans cancel/abort, error unwind, shutdown) and
make the clear unconditional. **A dead-holder reclaim is a safety net, not the
root fix.**

**Beware:** `ip->i_dlm_demoter` is a bare `struct task_struct *` held with **no
reference** — it dangles once the holder exits. `mxfs_foreign_demoter()` only
compares it (safe); `MXFS_SET_DEMOTER`'s legacy-clobber A/B path dereferences it
(`->pid`) and is a use-after-free under `mxfs.demoter_legacy_clobber=1`.
