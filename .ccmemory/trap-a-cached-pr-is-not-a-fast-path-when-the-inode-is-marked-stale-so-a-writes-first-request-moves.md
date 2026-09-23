---
name: trap-a-cached-pr-is-not-a-fast-path-when-the-inode-is-marked-stale-so-a-writes-first-request-moves
description: TRAP (s596g, D-0958): the PR fast path in mxfs_dlm_ilock_begin also needs !i_dlm_stale (set by ~20 signals); a harness that assumes a re-cached PR se…
metadata:
  type: feedback
tags: [D-0958, fast-path, i_dlm_stale, harness, fallible-acquire, trap]
---

# A cached PR is not a fast path when the inode is marked stale

s596g (0.84.14, WORKLOAD=held_fd_dio_unaligned, fails=3) had W re-read the file after H's rewrite so the direct write's first shared IOLOCK ride would fast-path on the cached PR and the mtime update's ILOCK_EXCL (the 0.84.14 site) would be the first request the fault met. The refusal landed on the first ride instead: `P958-WRITE-REFUSED stage=first mode=shared`, with the blocked stack in `xfs_file_dio_write_unaligned -> mxfs_ilock_fallible`.

Why: the cached-mode fast path in `mxfs_dlm_ilock_begin` (xfs/xfs_mxfs_dlm.c, "Cached-mode fast path checked BEFORE the DEMOTING wait") serves a PR request from a cached PR only when `!ip->i_dlm_stale` (the 2026-07-14 fix), and `i_dlm_stale` is set by ~20 coherency signals across the file. A cached EX serves anything. So "W holds PR" does not mean "W's next PR acquire sends nothing"; the reload clears the flag exactly once per staleness event, so which ride sends the request is not something a harness can arrange by a preceding read alone.

Consequences:
- Under the fallible model this is harmless: whichever registered acquire meets the discarded request refuses at its own boundary, nothing is written, and the disarm recovers. The s596g FAILs were harness expectations, not MXFS behaviour.
- A lap that must reach a LATER acquire (the timestamp EX, the unaligned-excl-retry) cannot rely on a cached PR for the earlier rides; it needs the earlier rides to be fast paths for a reason that holds (a cached EX — but then the later EX is a fast path too), or it must accept either stage and print which, as the harness does now.
- s596h's `got=2 want=1` pause count on the holder is the same family: with HOLDER=pr the holder's EX-to-PR demote from W's re-cache read was still draining in the bast worker when the pause knob was armed (RELPAUSE at 25813.24), and W's EX request 0.5 s later paused a second drain; both ended and the write landed. Arm-after-drain ordering for a file needs the demote to have completed, not just the read to have returned.
