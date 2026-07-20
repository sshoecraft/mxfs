---
name: sess12run-FIXA-pin-aware-release-abort-99136941
description: sess12 FIX-A (build 99136941): release-abort at xfs_mxfs_dlm.c:10401 ignored i_dlm_pin_count → idle-release stripped FIX3's pinned dir grant mid-dial…
metadata:
  type: project
---

# sess12 FIX-A — pin-aware release abort (the FIX3-pin-stripping hole)

## PROVEN mechanism (r10 round-4, t2 /root/drc_failverify_r4_rank2.dmesg)
Timeline (t2 kernel s):
- 220.162703 P74-GRANT ino=8388736 (round-4 drc dir) mode=EX gen=10298 — dd create's slow acquire grant lands.
- 220.162828 P-NONE-HELD-IDLE-RELEASE (idle ex=0 pr=0 pin=0 — legal entry) → 220.162838 P70-BP ENTRY qsrc=3.
- 220.163125 P71 begin-slow EX (dd) → 220.163130 P71 end pin=1 (FIX3: pin dp + iunlock before dialloc).
- 220.164115 P51-REL held_mode=5 + EXIT rel_gen=10298 — **the pipeline released the dd's just-granted, PINNED tenure**: abort check (10401) tests ex/pr/gen only; ex=0 (iunlocked), gen entry==rel (grant landed BEFORE pipeline entry) → passed. pin=1 ignored.
- 220.185796 P74-GRANT gen=10305 — dd's FIX3 re-lock does a REAL slow re-acquire (mode was NL'd) — mid-create the dir was up for grabs by peers.

## Why this is the shared root of BOTH 4/tcp blockers
1. fence/netpartition/tds triple-FAIL (r4/r5): with the pin stripped, the create's re-lock becomes a REAL dir-EX acquire executed WHILE HOLDING AG-0 EX from xfs_dialloc (t_mxfs_ag_unlocks holds to commit) = the AG→dir hold-and-wait edge FIX3 (D0151E9A) was built to eliminate; vs peer rm's dir→AG = 60s ABBA → rm rc=-110 → defer_finish shutdown. (r5 evidence: t1 holders=1 frozen 60s on AG-0 + t1 rm waiting ino-164 held by t4 whose rm waits AG-0.)
2. dir_reuse 1-name durable loss (r7 node1_f17.md5): same-slot double-alloc — t2 f12 & t1 f17 both LADD aoff=2416, 80µs apart, both built on base S91 (sum 1651881554), later fork lost. Concurrent-EX window from release-stripped tenures / mid-flight grant+release races of this family. (r10 round-4 face: 3 f1 names lost at dir birth with the pin-strip trace above; creators' watch-arm stat failed (-117 iget window) so add-path probes were blind — arm-retry TODO.)

## The fix (xfs_mxfs_dlm.c ~10401, build 99136941)
- Abort condition now: ex>0 || pr>0 || **pin_count>0** || gen_moved.
- pin_only abort (ex=0 pr=0 pin>0 !gen_moved) leaves state=**CACHED** (NOT BAST — BAST gates the dir fast path and would send the FIX3 re-lock down the P109 EDEADLK self-demote storm) + arms i_dlm_bast_pending; the unpin quiescent arm in pinned_resource.c (CACHED&&bast_pending, sess11) fires bast_process → release deferred to unpin, exactly like BASTs-defer-on-pin by design.
- gen_moved arm unchanged (CACHED + pending). ex/pr arm unchanged (BAST).

## Probe stack in 99136941 (all from this session)
P12-AGBAST-RX/READOPT/WORK/ULBP (AG bast pipeline, ungated) + pag holder pid/comm stamp + P12-HOLDERTASK (sched_show_task of stuck AG holder >15s, cap 6) + P36-STACK (waiter stack at first acquire-timeout, cap 8) + P12-DLMTR ring (1024-entry per-watch-ino mode/state transition ring, dumped by mxfs_dirdump on drc RDMISS) + P10-DIRDUMP-BLK lba= + drc raw-block dd capture (O_DIRECT) to /root/drc_blkdump_r<N>_rank<R>/.

## Ladder state (full 4/tcp suites, tests/suite_iter.sh per iter)
r4 FAIL(fence family, D0151E9A) r5 FAIL(fence, AFEF43B92) r6 PASS r7 FAIL(drc -1, 5126B737) r8 PASS r9 PASS (864C59A0) r10 FAIL(drc -3, 864C59A0) | r11+ = FIX-A build 99136941. Bar: sustained PASS streak (≥4-5 consecutive), then 1/2/8-node columns on the SAME build.
## TODO next if drc still fails: arm-retry for watch_ino stat in drc script; read P12-DLMTR dumps from all nodes.
