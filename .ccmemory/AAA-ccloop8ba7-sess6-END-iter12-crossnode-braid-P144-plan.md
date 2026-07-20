---
name: AAA-ccloop8ba7-sess6-END-iter12-crossnode-braid-P144-plan
description: sess6 END: fence 0.10.116 did NOT stop dbl-alloc (iter_12 cross-node braid, P143=0). Writer flushed (P12 full pipeline) yet reader regressed. NEXT: P…
metadata:
  type: project
tags: [ccloop-8ba7ae5c, sess6-end, double-alloc, P144, handoff]
---

# sess6 END state — double-alloc hunt after iter_12 (read FIRST with the two earlier sess6 memories)

## Criteria position (unchanged)
criteria.json: 1/2/4/8/16 caw = 100%. 32/caw rows currently reflect repro-iteration state, NOT a full ladder. Blockers: (1) the AG free-space double-alloc (~1-in-6 of the cc+pm repro segment; ALSO the likely cause of the 17:27Z ladder's cc uv-ghost), (2) Family-A post-rmmod panic timebombs (untouched).

## What's PROVEN fixed this session (builds 0.10.111-115, all in current tree)
P133 raw-FUA cluster init; site-11 igrab guard; P142 ident guard (drop-unless-last); iget_cache_miss out_destroy cancel_sync (placeholder phantom-work panics). Iterations 8/9/11 fully clean 32-node cc+sc+pm runs prove the cluster is otherwise healthy at 32.

## iter_12 (fence build 28B78CA1) — REPRODUCED, fence blind (P143=0)
Braid (logs tests/logs/dblalloc_repro/iter_12/full_test*.log):
- 22:58:06 test26 (bash) grows uv dir (ino 20971674) into AG29/agbno295 (daddr 60705856), writes dir data (P3L-BIRTH + P62-DWR owner=20971674).
- 22:58:36 test26 P12-AGBAST-RX ag=29 → P12-WORK COMMIT demoting (peer wanted AG29) → full Phase-2/3 pipeline ran: P117-AGMETA-STALE-CLEAN agno=29 bnobt daddr=60703504 + cntbt 60703512 (release-time stale+DONE-clear of CLEAN bnobt/cntbt, sess117 feature), log_force×2 + drain + UNCONDITIONAL mxfs_blkdev_flush_epoch (xfs_mxfs_dlm.c:29393) + Phase2b + sess43 re-drain (qd-conditional flush, fn at 26728) + Phase-3 wait + final flush. So writer-side media SHOULD have been current at unlock.
- 22:59:41 test7 (kworker delalloc) P-DBLALLOC agno=29 agbno=295 disk_owner=20971674 (live uv block on disk at alloc!) — 65s into test7's OWN AG29 tenure (it acquired ~22:58:36 via that BAST). No P143 anywhere (fence stamps are writer-local; test7 never completed AG29-meta writes before the fatal read, or no cold read occurred).
- Static: uv foreign content fsb 7602471 (AG29/295), no pm overlap this time. cc 31/32 (2 checks).

## Key open question
Where did 295-free re-enter test7's view: (a) test7's FIRST bnobt read at acquire was already stale (writer's bnobt write never actually landed/durable despite pipeline — e.g. the P117 stale-clean discarded a buffer whose delta had NOT really been written: 'clean' determination wrong for some CIL/ordered state), or (b) test7 read correctly then ITS in-core state regressed mid-tenure (needs cold re-read; fence saw none). P-PINNED-REREAD=0, P93=0, P124 instr-only (premise broken for sole-EX-holder), all handoff probes silent.

## NEXT STEP (designed, not yet implemented): P144 content fingerprints (GPT gpt-5.6-sol consult in sess6, full design in its reply — re-ask if needed)
- At AG-meta WRITE SUBMISSION (xfs_buf_submit_ex, beside P-DIRWR): record per-daddr crc32c(content past 56-byte btree hdr / whole block minus LSN+CRC fields) + bb_lsn + numrecs into a small per-AG ring (say 8 entries/AG) + print P144-WR (capped) with agno daddr crc nr lsn.
- At AG-meta COLD READ completion (xfs_buf_read_map after _xfs_buf_read success, ops in mxfs_agmeta_ops): compute same CRC, print P144-RD agno daddr crc nr lsn + MATCH/MISMATCH vs last local write if any.
- At P117-AGMETA-STALE-CLEAN: also print the buffer's content CRC+nr+lsn at stale time.
- Next reproduction then shows: writer's last image vs reader's first image directly (per-node journals joined by realns). If reader's first read MISMATCHES writer's last write → write lost on media/cache path (transport); if MATCHES → reader regressed later in-tenure (hunt the in-core reverter).
- ALSO instrument free-side per GPT: any bnobt/AGFL INSERT covering a watched agbno (295-ish) → print (proves/refutes 'a free re-added it' definitively).

## Env/harness crib (supplements earlier memories)
- Repro: `timeout 590 scripts/dblalloc_repro.sh <label>`; batches run RULE0_CALIBRATE=1; verdict 'hits' now excludes the P-DBLALLOC FP family (dblalloc_content_hits reported separately; NOTE: re-mkfs leaves old FS content on disk → disk_owner=<prev-FS inos> at alloc is NORMAL in early minutes; only disk_owner=<THIS-FS live ino> like the two red-handed captures is real).
- After wrapper timeouts: kill leftover chains (fuser -v /tmp/mxfs_run.lock; kill the timeout/sshpass PIDs) else next prep fails rc=3.
- Journal pull: per-node journalctl -k --since '<iter start>' | gzip | base64 (see dblalloc_repro or my inline loops); test1-8 rotate FAST — pull immediately after a reproduction.
- 32-node iteration wall: ~6min (prep 46-117s, cc ~90s, sc ~16s, pm ~65s under calibration).
- Serial consoles (panic evidence): sudo -n tail /var/log/libvirt/qemu/testN-serial.log.
- P143 fence (0.10.116): harmless to keep; fires only on local-write-then-cold-read windows.

## After the double-alloc is closed
Full ladder `MXFS_DEV=/dev/mapper/mpatha RULE0_CALIBRATE=1 ./run.sh 32 caw` (~75min, chunk it), spot-regress 16/8/4/2/1, update TIMEOUT_BUDGETS.md + manifest budgets from healthy walls (pm@32 measured 62-71s vs flat 30 — miscalibrated), THEN criteria marker. Family-A timebombs may need fixing if they strike ladder runs (see sess6 memory #1).
