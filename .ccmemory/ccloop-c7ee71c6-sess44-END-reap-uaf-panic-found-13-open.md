---
name: ccloop-c7ee71c6-sess44-END-reap-uaf-panic-found-13-open
description: sess44 END: 3 defects closed; P195 recalibrated (precursor-only, no loss; knobs deliberately off; endgame=adopt-at-EX-acquire); 13 OPEN of 37; rig 32…
metadata:
  type: project
tags: [ccloop, session-end, p195-map, three-closed]
---

# sess44 END (final v6) — state for next session

## THREE DEFECTS CLOSED (all RULE-6 verified on-build)
1. D-DESTAGE-TEAR-BUCKETLESS-ORPHAN (critical, 358): 4 race arms + boards.
2. D-REAP-WORK-UAF-PANIC-AFTER-UNMOUNT (critical, 359): gate fix, mechanism
   proven live, zero panics/~15 prep-equivalents (serial-log baselines
   test1=4 test24=1).
3. D-OUTAGE-REMOUNT-MUTUAL-IFREE-SKIP-STRAND (major, 360): agino%64
   fallback → 64-head scan; 3/3 arm + green 32-board (x2, second fully
   clean) + green 8-board.

## P195 TRAIL — RECALIBRATED (read the ledger entry FIRST, it has the map)
D-DIRENT-PUBLISH-STALE-BASE-P195-360 (now MAJOR): the one 32/caw board hit
was PRECURSOR-ONLY — test3 has ZERO P32E-DIREPOCH-FENCE (the loss tracker),
recovery held. Key facts so nobody re-derives 3 sessions of history:
- D-SILENT-MKDIR-LOSS (closed) fixed the LOSS via reload_demote_wait_ms=50
  (P34J-bail root). P195 = documented precursor.
- dir_lookup_freshness_gate=0: REFUTED fix (never engages, dirty_here=1
  always). creator_baseline_stamp=0: principled, NOT VALIDATED (sess27/28
  A/B counter-directional). Both deliberately off; confirmed 0 on rig.
- Residual defect = precursor state still reachable (aged/board-context
  ~1/8, NEVER fresh/standalone) with sentinel baselines (base_state=1
  SEEN, cached_gen=0) making tenure-vs-epoch disambiguation inert.
- ENDGAME (the closed entry's own blocking_fix): adopt at EX ACQUIRE so
  P195 never fires. Alternative: validate+default-ON the creator stamp.
  GPT consult before choosing. Repro protocol: board chunks 1-4 THEN
  dirent_publish_integrity loops (aged context required).

## LEDGER: 12 OPEN of 37 (teardown-wave DISPROVED late-session — see below). RIG: 32/caw on 0.11.360 (2A7A772688406716031635A),
all 32 mounted, boards green (32 x2 + 8 on 360). Tree matches.

## REMAINING OPEN (13)
criticals: FOREIGN-REPLAY-UNGATED-IMAGES (architectural certified-replay);
INODE-CLUSTER-PUBLISH-WITHOUT-AUTHORITY; CROSSNODE-OPEN-UNLINK-DATA-LOSS
(CAW verified 9/9; C9-tcp impl left — GPT hybrid blueprint in memory
...-C9-tcp-open-tracking-gpt-design; tcp rig UNWIRED, needs host LUN + VM
XML wiring); CACHE-COHERENCY-UV-COUNT-MISS-2332. high: DIRVIEW-NONCONVERGE.
major: P195 (above); 2x pace; CRASH-CONSISTENCY-32-NOTERMINAL-354;
TEARDOWN-WAVE (likely closed-UAF symptom — one disposition run needed).
minor: MATRIX-UNMEASURED; BOGUS-IMODE (zero P116 observed yet — keep
sweeping after death tests). unknown: AGI-UNLINKED-CROSSNODE (aged repro).

## TEARDOWN-WAVE: DISPROVED sess44 (4th disposition this session)
Measured: clean mass departures produce ZERO false expiries (4 watchers,
multiple 32<->2 cycles); zero 'release write failed' fleet-wide; UAF panics
confirmed in the original wave windows; zero recurrence in ~18 preps post-
UAF-fix. The wave was the designed fencing response to real UAF corpses.

## STANDING RULES (reinforced hard this session)
- ALL log detections = count-growth vs baselines (dmesg+ino reuse; 3x).
- sudo -n reads /var/log/libvirt/qemu/testN-serial.log — the ONLY guest
  crash capture; sweep after churn.
- prep_fs refuses claimed devices (near-miss guard, live).
- Aged-vs-fresh preconditions matter: P195 and AGI defects need BOARD-AGED
  context; never claim non-repro from fresh runs.
