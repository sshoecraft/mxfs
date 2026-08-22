---
name: ccloop-c7ee71c6-sess294-503-wqdelay-DISPROVEN-direx-stall-proven
description: sess294: D-503 REPRODUCED on 0.11.506 P296 build; wq-queue-delay hypothesis DISPROVEN (0 in-window events x32); dir-EX acquire stalls 6-12.5s PROVEN
metadata:
  type: project
---

# sess294 — D-503 RULE-4 cycle: probe landed, collapse reproduced, hypothesis disproven

## Landed
0.11.506 sv 289E4A3F4164D39FFC7DF90: P296-BASTQLAT probe.
- `xfs_inode.h`: new `u64 i_dlm_bastq_qns` (expected-run ktime of last successful bast work/dwork arm; dwork stamps now+delay so delta=pure excess). Zeroed in mxfs_dlm_inode_init.
- `xfs_mxfs_dlm.c`: stamps in mxfs_bast_arm_queue/_delayed on queued==true (under m_mxfs_arm_lock); `mxfs_bastq_lat_probe()` at both work-fn entries after ident check; logs excess>100ms, capped 400/boot.
- NOTE: make clean wipes tools/ binaries — rerun `make tools` or prep fails "mkfs tool not found".

## Reproduction (32/caw, run 20260815T002130Z)
Full-board accumulation: chunks 1-3 (20 cells) all PASS, then chunk4:
- crash_consistency FAIL 0/32 NO_TERMINAL_RECORD @00:34:02Z — phases COMPLETED but at 90s budget edge (test17: datawrite 24s, md5write 33s; 50 O_SYNC dd ≈ 0.5s/op).
- dir_reuse_coherency FAIL 0/32 pace (43/44).
Chunk5 (soak, dirent_durability→publish→type, open_defects) NOT run on .506 yet.

## DISPROVEN (RULE 4 2a)
"Dir demote/handoff bast work queue-delayed behind sweep-release works on m_mxfs_inode_bast_wq": P296 shows ZERO events on ALL 32 nodes inside each node's cc fail window, and each node's 400-cap saturated only AFTER its window (so absence is real, not cap-censoring). The src=16 sweep torrent DOES backlog the wq (397/400 events src=16, excess up to ~900ms incl isdir=1) but only in INTER-TEST gaps and during drc — not during cc's collapse.

## PROVEN in-window
- P34-ACQ-SLOW ino=26226559 (the shared cc dir) isdir=1 req_mode=5 dur_ms=6366/12471/11619/12543 attempts=1 on test17 — 4 create-path stalls of 1-2 full 6000ms ACQUIRE_WAIT BAST-retry periods. The holder sat on the dir EX through BASTs with NO wq delay anywhere → either release aborts on holder, BAST swallowed BEFORE queueing (P296 blind spot: only measures QUEUED works), or drain pipeline seconds-slow.
- Discriminators reproduce: P50-RD 1850-4186/window (pass ~500), P12-AGBAST-RX ~78 (pass ~10), P70-BP ~870/90s.

## Evidence artifacts
- scratchpad/dir_timeline_raw.txt (3679 lines: P291-EXWIN/P34-ACQ-SLOW/P15-REL-ABORT/P36-MHT-REARM(exh>=100ms) for ino=26226559, all 32 nodes, dmesg -T).
- P291-EXWIN `realms=` field is EPOCH-MS wall clock — cross-node grant-chain ordering without boot-epoch math.
- test17 stall: request ~00:32:16Z, grant 00:32:29Z. Find the 00:32:16-29 EX holder in the timeline; its P15-REL-ABORT lines (orph=1 entry_gen==now_gen seen on test1/test15 at 00:32:25) are the suspect shape.

## Next
1) Grant-chain reconstruction around the stall → name the holder + why it held.
2) RULE-5 consult with evidence before fix design.
3) Chunk5 on .506; then D-488 leg7 fault-inject, leg8, ledger rewrite.
