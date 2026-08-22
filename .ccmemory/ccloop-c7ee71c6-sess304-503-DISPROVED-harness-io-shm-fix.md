---
name: ccloop-c7ee71c6-sess304-503-DISPROVED-harness-io-shm-fix
description: sess304: D-503 CLOSED DISPROVED — dmesg snapshot+stream moved /root→/dev/shm in dir_reuse_coherency.sh; b2b prediction confirmed 3/3 PASS (107/108/10…
metadata:
  type: project
---

# sess304 — D-POSTLOAD-SYNCWRITE-PACE-COLLAPSE-503 DISPROVED

## What closed it
The sess303 closure step executed exactly as pre-registered:
- `tests/suite/dir_reuse_coherency.sh`: per-round full-ring dmesg snapshot
  (was `/root/drc_create_r*` — 16.9MB/node/round = 540MB/round fleet) and the
  DRC_STREAM in-node `dmesg --follow` target moved to **/dev/shm** (tmpfs).
  Clean-slate rm extended; tmpfs also kills the sess14 stale-snapshot-across-
  reboot contamination class.
- Consumers updated to search BOTH paths: drc_detail8.sh, drc_cap4.sh,
  drc_cap8.sh, tcp/drc_catch2.sh, drc_trace.sh.
- Fail-path conditional dumps left on /root (rare, wanted persistent).

## Verification (prediction confirmed)
Back-to-back `./run.sh 32 caw dir_reuse_coherency` ×3 with NO idle gap:
PASS 107s / PASS 108s / PASS 109s (runs 20260815T041615Z, 041840Z, 042114Z),
32/32 nodes, 0 failed checks, flat pace — where run2 previously failed 7/7
deterministically. The create-phase +1.5s/round term vanished too (same host
collapse surfacing).

## Ledger
Status DISPROVED with full evidence chain in `disposition` field. Scope note:
any pace collapse observed WITH harness IO on tmpfs = NEW observation → new
entry. Open defects 36→35 (24 critical).

## Ops notes
- `tools/mxfs_sshpass.sh` takes a BARE host (adds root@ itself) — root@testN
  fails rc=5. (Second session to trip on this.)
- Node cleanup done: /root/synth_{A,B,C}_r*.dat + synth_sync.txt removed on
  all 32 nodes; test1 root fs at 17%.

## Next
Queue head: D-FOREIGN-REPLAY-UNGATED-IMAGES step 3b (sess175 plan of record;
see compiled-foreign-replay-authority-tokens). Owed: dlm.md awareness update
(sess299-304), pal.md refresh, D-488 leg8, NO_TERMINAL_RECORD capture defect,
memory compaction (234 unfolded).
