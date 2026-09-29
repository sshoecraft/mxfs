---
name: trap-a-scratch-copy-build-chained-with-and-and-after-rsync-falls-through-to-the-tree-when-rsync-exits-23
description: TRAP (0.90.12): `rsync ... && cd $B && t0=..; make modules` — rsync exit 23 (root-owned bench.json) skipped the cd and make rebuilt the TREE under a…
metadata:
  type: feedback
tags: [build, rig, queue, rsync]
---

# A scratch-copy build must never be `rsync && cd && …; make`

**What bit (2026-09-28):** to compile a dlm.c change without touching the tree's `mxfs.ko` while a
rig queue was deploying it, the command was

    rsync -a --exclude … ./ "$B/" && cd "$B" && t0=$(date +%s); timeout 540 make modules -j16 …

rsync exited 23 (two files in the tree were root-owned and unreadable: `bench.json` and
`.xfs_fio_baseline.tcp.scst-fio.json`, left by a sudo'd bench run), so the `cd` never ran, and the
`;` let `make modules` run in the working directory — the tree.  The tree's `mxfs.ko` changed
srcversion mid-queue (20491955… → 48C041CB…), and the next prep of a running multi-lap chain
(sess475 chain116, 4/tcp) deployed the new build, so one verification chain straddled two builds.

**Rules that follow:**
- build in the copy with an explicit directory on the make itself: `make -C "$B" modules`, never a
  `cd` that a failed predecessor can skip; or `( cd "$B" || exit 1; make … )`.
- treat rsync's exit as a gate: `rsync … || { echo rsync rc=$?; exit 1; }` before any build.  Exit 23
  (partial transfer) is what unreadable files produce; it is not a success.
- fix the ownership once: `sudo -n chown steve:steve <file>` on anything a sudo'd run left root-owned
  in the tree (git shows them modified but nothing can read them).
- while a queue is deploying the tree's build, no command may write `mxfs.ko` in the tree at all;
  the queue's waiter rebuilds after `QUEUE DONE` (tests/evidence/lapq_*.out pattern).

`tests/full_verify.sh` is not exposed: it runs rsync and the make as separate statements and the
make is inside `( cd "$B" && … )`.
