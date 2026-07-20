---
name: sess12run-FIXB-igetmiss-cluster-reload-and-ladder-state
description: sess12 FIX-B (5BE16AA5): lookup-iget ENOENT/-117 sticky-stale cluster buf → invalidate+retry (mxfs_dlm_iget_miss_reload). Ladder: r11 16/17, r12 17/1…
metadata:
  type: project
---

# sess12 FIX-B + ladder state

## FIX-B (xfs_inode.c lookup fail path + mxfs_dlm_iget_miss_reload in xfs_mxfs_dlm.c, build 5BE16AA5)
- Face: dlm_scaling nodeX quota got=0 — first `: > nodeX/f1` ENOENT; the fresh `.dlm_scaling` dir (created by rank1 seconds earlier) stays un-igetable on ONE node for 60s+ (P26-IGET-FAIL err=-2 at teardown too) while other peers iget it fine → platter current, the failing node's CACHED inode-cluster buffer (XBF_DONE from when the inum was free) serves the stale FREE image forever (that node never acquires the AG → no gen-hook revalidation). r13 variant: err=-117 EFSCORRUPTED (garbage/torn dinode read) same family.
- Fix: on dirent-resolved iget failure (-ENOENT or -EFSCORRUPTED, ≤3 tries, multi-node): xfs_imap → xfs_buf_incore → if safe (DONE, !stale, !pinned, !delwri, !dirty, !in_AIL) clear XBF_DONE|_XBF_FUA_FRESH → msleep(10*try) → retry_iget. P12-IGETMISS-RELOAD (capped 400).
- Discriminator gap: if the face recurs WITHOUT the P12 print, the buffer wasn't incore → the read was already fresh → CREATOR-side destage bug instead (add no-buf print next build).
- Frequency jumped post-FIX-A (r11 node4, r13 node2 = 2 of 3 runs; historically ~2/30): FIX-A longer pinned tenures may shift inum-reuse/cluster timing. FIX-B is the consumer-side guard either way.

## Ladder (full 4/tcp, tests/suite_iter.sh — now with post-run probe harvest to /tmp/suite_iter_probes_*.log)
- r11 (FIX-A 99136941): 16/17 — dlm_scaling node4 got=0 (iget face). fence/drc PASS.
- r12 (FIX-A): 17/17.
- r13 (FIX-A): 16/17 — dlm_scaling node2 got=0 (iget face, -117 variant sighting on .mmap_coherency lookups too).
- r14 (FIX-A+B 5BE16AA5): running. Bar: 4-5 consecutive 17/17 → then 1/2/8 columns on same build (all 32 VMs exist; test5-8 shut off, suite_iter recycle starts them).
- AG re-adoption ping-pong measured mild (readopt≤19, ~5s) in r11 dlm_scaling — bounded, not the r5 frozen-hold face (that one had readopt=0 = single frozen holder; watch P12-HOLDERTASK stack if fence fails again).
- DLMTR transition ring armed (dumps via drc RDMISS on watch_ino) for any recurring dir double-grant.
- Editing tests/suite_iter.sh while an instance runs corrupts that instance (bash re-reads) — edit only between iterations.
