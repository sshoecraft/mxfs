---
name: sess1-FACE1-ROOT-FIX-torn-disk-skip-leaked-ilock
description: sess1(a16ec5f2) FACE-1 ROOT PROVEN+FIXED: P-RELOAD-TORN-DISK-SKIP bail (xfs_mxfs_dlm.c ~13010) returned holding raw down_write(i_lock)+leaking snap →…
metadata:
  type: project
---

# sess1 — FACE-1 (leaked i_lock EXCL on shared dir) ROOT CAUSE PROVEN + FIXED

## The bug (7+ sessions old, sess7's "FACE 1")
`mxfs_dlm_reload_inode`'s sess49b TORN-DISK RELOAD GATE (`P-RELOAD-TORN-DISK-SKIP`, xfs_mxfs_dlm.c ~12998-13010): when the on-disk dir extent map has a data-region HOLE (divergent-grow tear, DABUF_MAP_HOLE face), the gate refuses the adopt and bails — **while still holding the raw `down_write(&ip->i_lock)` taken at ~12510 and leaking `snap`**. Every sibling exit does `kfree(snap); xfs_buf_relse(bp); up_write(&ip->i_lock);` — this one only did relse.

## Why it presented as the mysterious FACE-1 hang
- The leaker (dd/ls/kworker running the reload) EXITS normally → dead write-holder → every later `mxfs_dlm_ilock_begin → mxfs_dir_drain_evict_data_blocks → down_read(&ip->i_lock)` blocks FOREVER (hung-task dd D-state at drain_evict+0xf4).
- The tear is observed CLUSTER-WIDE (sess49b comment: 6/8 nodes gate the same torn image) → **all 8 nodes leak the shared dir's i_lock in the same round** → the run3 round-12 all-node create wedge (barriers time out at COORD_TIMEOUT=120 → all nodes no-result → 0/8).
- PROOF: run3 dumps — `P-RELOAD-TORN-DISK-SKIP ino=131 disk_nx=5 incore_nx=9 gen=3004595044` fired on ALL 8 nodes at the exact wedge instant (t≈201.3-201.6 / 1138.9-1139.4 per boot-epoch). Live /proc inspection on test3: only D-task = the blocked reader; NO live task in any mxfs path = holder exited (leak, not ABBA).
- sess7's earlier P132 "wr_last=xfs_lock_two_inodes pid=rm(dead)" was a MISATTRIBUTION: the raw down_write at 12510 predated its note_lock (sess7 added it; the comment at 12511 even warns of exactly this).
- 4-node rarely tears → why FACE-1 was "8-node ~1/3 of runs".

## The fix (this session)
At the dgap bail: `kfree(snap); up_write(&ip->i_lock);` before return. Also converted the drain_evict raw `down_read` (7856) to `mxfs_drain_ilock_read()` (same indefinite blocking — NO trylock-skip per sess7 constraint — but P132 forensics after 5s, bails only on FS shutdown → return 1 "skipped").

## Builds
- `802D6565` = 890B1C41 + forensic drain waiter (pre-leak-fix; in test when leak was found by review).
- NEXT build (post-leak-fix) = the FACE-1 ROOT FIX build → rebuild after background run bjw2n56b8 completes, then drc 8 loop.

## Cross-links
Fix chain this session: [[sess1-run-a16ec5f2-AGdir-deadlock-root-and-fixes]] (AG-trylock allocator fix + FACE-2 4/tcp=6/6 + attribution instr). Remaining watch-items: 8/tcp pace (rounds 7+ = ~15s/round; budget 480s honored by run.sh run_coord tt=60*N — fits), -110 AG starvation recurrence (run2 only), rm inactivation per-file AG-EX sweep cost (~4s per rm-rf of 800).
