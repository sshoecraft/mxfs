---
name: sess47-FINAL-state-fixes-heal-and-decoded-release-wedge-data
description: sess47(ccloop) FINAL: 2 wedge fixes KEEP (E9D1B1CB). dir_tenure_evict=1 reduces but does NOT fully fix reused-dir holes. Decoded P47 release-block da…
metadata:
  type: project
---

## sess47 (ccloop 4cb2d0a2) FINAL STATE — criterion NOT met, but real progress

### Builds: E9D1B1CB = 2 KEEP wedge fixes. 45B640FF = E9D1B1CB + P47 instrument (on disk now).
Keeper fixes (see [[sess47-FIXED-two-8tcp-wedges-relsafe-lock-and-ilockend-defer]]):
1. relsafe lock at xfs_mxfs_dlm.c ~8676 (kills WARN-flood wedge).
2. ilock_end defer-to-bast-wq at ~15280 (kills inline-flush self-deadlock).
Both correct; test now COMPLETES instead of always-wedging. P47-FILEBLOCK is a
capped diagnostic (xfs_mxfs_dlm.c ~14622) — harmless, can stay or be removed.

### ENUM DECODE (for reading probes):
MXFS_LOCK: NL=0, CR=1, CW=2, PR=3, PW=4, **EX=5**.
ISTATE: NONE=0, CACHED=1, **BAST=2**, **DEMOTING=3**, ACQUIRING=4.

### dir_tenure_evict=1: PARTIAL heal, NOT a full fix.
- First run (it wedged early in cluster_durable): hole=0 (didn't reach holey rounds).
- Run that COMPLETED all 24 rounds: holes STILL occur (156-499/node) but mostly
  WITHOUT shutdown (shut=0) — the EFSCORRUPTED is returned to the caller without
  force_shutdown on the read/lookup paths. Still FAIL 0/8 (test5 readdir=0/800,
  others 751/800 missing test5's ~49 files). So tenure_evict reduces fatal
  shutdowns but does NOT eliminate the reused-dir leaf/extent incoherence.

### P47-FILEBLOCK data (why files block on the demote/BAST wait):
- DOMINANT (4000×, capped): `req=EX(5) mode=PR(3) state=BAST(2) comm=rm` — an
  unlink upgrading PR->EX while a BAST is pending. High-VOLUME (rm-rf storm); likely
  resolves (not a true deadlock), but worth confirming it isn't a slow upgrade stall.
- RARE: `req=EX(5) mode=NL(0) state=DEMOTING(3) comm=dd/awk` — the xfs_end_io
  unwritten-extent conversion (or a read) arriving AFTER bast_process already set
  i_dlm_mode=NL (xfs_mxfs_dlm.c:9266) but before state->NONE. Blocks until unlock
  completes. The earlier hard WEDGE (bast in filemap_write_and_wait +
  cluster_durable, [[sess47-DABUF-HOLE-healed-by-tenure-evict-next-wall-is-release-pipeline-wedge]])
  is intermittent — did NOT recur in the completing run.

### HONEST ASSESSMENT for next session:
The two wedge fixes are solid and necessary. But the CORE reused-dir leaf/extent
coherence bug (stale LEAF references freed data blocks -> DABUF_MAP_HOLE) is NOT
fully fixed — dir_tenure_evict=1 only reduces its fatality. The 8/tcp dir_reuse is
multi-fault: (a) reused-dir leaf incoherence (holes), (b) test5-style node going to
readdir=0 (mount/DLM stuck — investigate: why does ONE node read 0 with shut=0?),
(c) intermittent release-pipeline wedge (filemap_write_and_wait vs xfs_end_io).
NEXT: (1) instrument WHY test5 reads 0/800 (DLM state / mount health on the 0-node)
— that single dead node is what makes it 0/8. (2) The leaf-incoherence needs a
correctness fix beyond tenure_evict — revisit the acquire-side leaf/node index-block
eviction on incarnation change (the release/evict paths skip offset>=leafblk; the
stale NODE/LEAF index block is never cold-reloaded on a reused dir). Repro:
reboot-clean loop + `MXFS_EXTRA_MODARGS="dir_tenure_evict=1" MXFS_TEST_ENV="DRC_STREAM=1" ./run.sh 8 tcp dir_reuse_coherency`; harvest /src/mxfs/tests/tcp/drc_cap/stream_rank*.log.
</body>
