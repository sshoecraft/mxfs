---
name: ccloop-c7ee71c6-sess28-ROOT-readdir-200x-msleep-retry-that-can-never-land
description: ROOT PROVEN + FIXED: readdir's 200x msleep(1) reload retry can never succeed (caller holds ILOCK_SHARED). 1210ms -> 5ms, 242x, same-build A/B.
metadata:
  type: project
tags: [mxfs, pace, readdir, rule0, rule4, D-READDIR-PEER-CACHED-DIR-PACE, sess28]
---

# sess28 — the readdir retry loop that can never land

Build **0.11.245** (`6764F19681F7272375144DA`).

## The root

`xfs/xfs_dir2_readdir.c:1005`:

    for (p48_try = 0; p48_try < 200 && dp->i_dlm_stale && !shutdown; p48_try++) {
            msleep(1);
            dp->i_dlm_stale = true;
            mxfs_dlm_reload_inode(dp, XFS_DIR3_FT_UNKNOWN, true);
    }

200 × `msleep(1)` ≈ **1.2 s** at this kernel's timer granularity — exactly the
observed cost, and it explains the *stability* (1201–1215 ms on every sample:
the loop always runs its full bound).

**It can never succeed here.** `xfs_readdir` holds `ILOCK_SHARED` across
iteration, so the reload's write acquire is blocked by **this task** — sess14
proved that and made `mxfs_dlm_reload_inode` bail immediately with
`P173-RELOAD-SELFREAD`. It returns with `i_dlm_stale` still set, and **the loop
body re-arms the flag** before each attempt. All 200 rounds bail. (P173 was the
top probe in the capture: 110 lines over 32 dirs = the *ratelimited* count of
200/dir.)

The loop's own comment — "ILOCK holds here are sub-ms, so waiting is safe" — is
about *other* holders. It does not cover the caller being the blocker, which is
the case that actually happens on the readdir path.

## The fix

`mxfs.readdir_reload_retry_selfread` — ships **0** (skip the retry when the
caller holds `ILOCK_SHARED`); 1 = pre-sess28, kept as the negative control.
New probe `P212-RDRETRY-SKIP`.

Nothing is lost: the loop's documented exhaustion behaviour is "the old
consistent-stale behavior remains" — which is what we get 1.2 s sooner, with
`i_dlm_stale` left set and `MXFS_IF_DIR_RELOAD` armed so the next access from a
context that does **not** hold the read lock performs the reload.

## Same-build A/B (8/caw, 7 peer-created dirs per arm)

| arm | getdents per dir |
|---|---|
| `=1` pre-fix | 1208, 1208, 1210, 1210, 1212, 1212, 1215 ms |
| `=0` fix | **4, 4, 4, 5, 5, 5, 6 ms** |

**242×, no overlap.** 8-node correctness board with the fix on: all PASS.
32-node `dirent_durability`: **66 s**, down from 125 s.

## How it was isolated — three refutations along the way

1. **Batch attribution was wrong.** `rm -rf` of 32 peer-created dirs = 38344 ms,
   which I first recorded as ~1.2 s per *removal*. An explicit per-op `rmdir`
   loop over the identical shape = 993 ms total (31 ms/op). The cost was the
   readdir `rm -rf` does on each child.
2. **`exec 9<"$dir"` is not an open test** — bash returns EISDIR on a directory,
   so an earlier "open = 45 ms" row measured a *failed* open. Timed properly
   from python: `stat=4ms open=0ms getdents=1202ms close=0ms`.
3. **`pal/linux/xfs_file.c:1888`'s pre-readdir wait loop was REFUTED** — its
   probe `P95D-READDIR-WAIT` is present in the module (`strings`) and fired
   **zero** times.
4. A phase-split probe on P62 showed `mxfs_dlm_reload_inode` itself costs
   `tot_ms=0` — so the cost is the *sleeping*, not the reload.

## ⛔ The bottleneck MOVED — do not read this as closing sustained_load

On the aged 32-node mount `sustained_load`'s setup collapsed
`setup=38402→240 ms`, `rmrf=38379→6 ms` (6400×). **The criterion still FAILS
180 s/180 s**, now at `bar2=121028ms` with `NO_TERMINAL_RECORD=3`: 3 of 32 nodes
cannot finish a 20-op loop the other 29 finish in ~2.5 s. So
D-MOUNT-DEGRADES-WITH-USE has a **second, distinct component**, now localised to
the op loop on a minority of nodes. The stragglers are not wedged
(`node_responsive` `dstate=0` immediately before).
