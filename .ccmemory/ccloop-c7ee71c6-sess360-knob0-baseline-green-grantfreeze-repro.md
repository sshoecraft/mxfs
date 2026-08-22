---
name: ccloop-c7ee71c6-sess360-knob0-baseline-green-grantfreeze-repro
description: sess360: 0.14.1 clean-build deployed 32/caw; knob=0 board 27 PASS zero behavior change (GO met); dirty-kill replay refusal reproduced grant-freeze li…
metadata:
  type: project
---

# sess360 — knob=0 baseline GREEN + grant-freeze live repro

## Deploy
- `make clean && make modules` → 0.14.1 sv BDEB75D40B5BE7C21C82EF6 (same sv as sess359 incremental — tree consistent). NOTE: make clean wipes tools/ binaries; `make tools` needed before prep (prep FAILs on missing mkfs_mxfs otherwise).
- Forced prep 32/caw OK 74s; all 32 mounted 0.14.1.

## knob=0 board baseline — GPT GO condition MET
- Full 28-cell board on 0.14.1: 27 PASS + open_defects POLICY red. Identical shape to 0.13.4 baseline. foreign_replay_token_enforce=0 default confirmed on fleet.
- Zero P227-FR-ENFORCE-* markers fleet-wide.
- crash_consistency FAILed once (0/32 NO_TERMINAL_RECORD, 90s budget exhausted) then PASS 19s on rerun — SAME intermittent pattern occurred 4x on 0.13.4 earlier the same day (05:46/06:16/09:01/15:39 FAIL each followed by PASS). Pre-existing harness capture flake, NOT a 0.14.1 change. Pattern: first crash_consistency of a chunk after heavy chunk sometimes times out with no terminal records. Unledgered as of sess360.
- Code-level knob=0 identity confirmed: at knob=0 the deciding refusal predicate is the mxfs_tainted blanket scan (xfs_log_recover.c ~3308, unchanged); Q6 allowlist only feeds mxfs_txn_admissible which is consulted solely inside the mxfs_fr_enforcement_active branch.

## Replay-path exercise at knob=0 (test32 dirty-kill 19:47Z)
- test32 wrote 2000 files in /mnt/shared/.fr360, virsh destroyed mid-write.
- test1 took recovery (P238-RECOV-LEASE slot=12), replay REFUSED 2 txns (P227-FR-ATOMIC-SKIP sbreason=2 lsn=0x100003aed items=7, 0x100003af3 items=8) → P227-FR-TORN-UNPUBLISHED. Same blanket-refusal behavior as 0.13.4 sess356 race-5 — no behavior change.
- D-513 containment WORKED: P241-RECOV-TERMINAL slot=12 reason=1 domain=2 ag_mask=0x2000 refused=2 digest=1bd288bc seq=1; P240-QUAR-IMPORT cluster-wide fswide=0.

## Grant-freeze defect #3 live repro (D-REFUSAL-GRANT-FREEZE-OUT-OF-CLOSURE-356) on 0.14.1
- Quarantine scoped to AG13 only, but victim's root-ino EX grant (AG0) frozen with no release path.
- test2 `touch /mnt/shared/.probe360` stuck in D-state: caw_wait_for_grant ← mxfs_v5_dlm_inode_lock ← mxfs_dlm_ilock_begin ← xfs_ilock ← mxfs_dlm_dir_consumer_refresh ← xfs_lookup (root dir lookup). Waiter polls to DLM -110, no distinct terminal-quarantine error.
- Fix shape already ruled (sess357 ruling, ccmemory ccloop-c7ee71c6-sess357-GPT-ruling-cascade-dispositions-and-gate-order): (1) closure grants frozen + DLM rejects new waits/cancels existing with distinct terminal-quarantine error; (2) replayed resources → normal recovery revocation/regrant; (3) provably-out-of-closure grants FORCE-REVOKED via recovery ownership epoch advance/publish before peer regrant; ambiguous buf→inode maps into closure.

## Next
Implement the closure fix (defect #3), then #4 D-UMOUNT-QUARANTINE-TIMEOUT-DIRTY-WITHDRAW-356; both BLOCK the #1 knob=1 campaign.
