---
name: sess14run-MILESTONE-8tcp-17of17-sfmht40-build-8E654A57
description: sess14 MILESTONE: iter r8 = 17/17 FULL PASS 8/tcp (first ever). Root chain: floor batches rounds; in-suite op-inflation needs sf_mht=40 (tds 17-31s,…
metadata:
  type: project
---

# sess14 MILESTONE — first 17/17 full-suite PASS at 8/tcp (iter r8)

## The winning chain (all RULE-4 proven this session)
1. SF-TENURE FLOOR (keep young sf-dir EX across syscall-gap idles; dwork
   serves peer at expiry) — cut per-syscall handoffs.
2. dir_sf_mht_ms must cover the REAL per-round wall: 15ms passes
   standalone (41.7s) but in-suite per-op inflates ~2x (aged log/tail-push
   with 17 tests on one module+FS instance) → batching collapses → 80-86s.
   sf=40 re-covers: **r8 = 17/17 PASS, tds 17.3-30.9s, cc 8/8 clean**.
3. drc suite-killer was NOT (only) coherency: drop_caches per round
   interlocks with peer rm-storm evictions → node silently hangs
   (INTERRUPTIBLE — no hung-task/P73), whole-blob 700/800 "miss" = victim
   never created; barriers then timeout 120s×2/round (62s/round death
   spiral). Instrumented: bounded drop_caches + DCSTACK capture + proceed
   warm (dir_reuse_coherency.sh). drc passed r7+r8 after this.
4. drc 5-file miss face (795/800, one block: victims hash to one daddr,
   e.g. r6 daddr=62796800 losing 5 .md5 adds from 5 nodes) = REAL residual
   stale-base RMW face, all-node durable agreement, LOOKUP_ENOENT.
   NOT fixed — needs dirwr-armed repro + P50-WR count ledger (CRC-only
   always-on P-DIRWR can't finger the writer). Occurrence: ~1 in 2-3 iters
   pre-r7; r7/r8 clean (luck or dropcaches-fix interaction — the eviction
   hang may have SEEDED stale bases; watch recurrence).
5. gap-run wedge (test4 184s AIL-stuck EX → cluster convoy): corrupt SF
   fork (count=7/six entries) reloaded from platter; P14-SFSIZE-DESYNC
   tripwire now guards iflush (if_bytes vs i_disk_size) + P14-SFSTRIP/
   SFMERGE verify surgical images in the sf rebase. None fired r6-r8 (the
   producer is rare); tripwires stay as sentinels.

## Builds
- 8E654A57 = RC: floor + FIX-F (miss-reload li_list gate) + P14 tripwires
  + sf_mht=40 default. On NFS now.
- r8's run was 11FAB23A + modargs sf=40 (equivalent behavior).

## Next (in order)
1. r9 = plain full 8/tcp iter on 8E654A57 (no modargs) — confirm default.
2. 4/tcp, 2/tcp, 1/tcp full iters on 8E654A57.
3. Repeat all columns to demonstrate stability (criteria = 100% each).
4. If drc 5-file face recurs: dirwr=1 repro run + P50-WR ledger analysis.

## Runbook
- Launch: nohup bash -c 'cd /src/mxfs; timeout 3200 bash tests/suite_iter.sh <N> tcp > /tmp/iter<N>_rX.log 2>&1; echo SUITE-EXIT=$? >> ...' 
- Logs buffer via tail -25 — nothing until run.sh exits.
- tds PASS elapsed: node dmesg 'mxfs-TDS rank=' lines.
- suite_iter recycles VMs itself. Manual ./run.sh does NOT.
