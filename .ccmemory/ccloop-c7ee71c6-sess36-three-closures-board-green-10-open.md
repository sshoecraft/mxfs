---
name: ccloop-c7ee71c6-sess36-three-closures-board-green-10-open
description: sess36: COLDREAD-STALE-SPLIT + SILENT-MKDIR-LOSS + CAW-YIELD-STARVATION all FIXED AND VERIFIED (GPT-ruled); board 306 = 20/21; 10 OPEN remain
metadata:
  type: project
---

# sess36 milestone: 12 → 10 OPEN, board 20/21 on 0.11.306

## Closed this session (all GPT-ruled FIXED AND VERIFIED, full rationale in OPEN_DEFECTS.json dispositions)
1. **D-CRASH-COLDREAD-STALE-SPLIT**: blind-close chain patched at 3 links (B3 merge staging protection 299, honest-ledger rollback C 299, terminal release gate 306). Verification: 6 aged-mount cc laps at load 26-34 + 3 boards, P241=0, terminal crossings=0 with gate firing ~300x/run.
2. **D-SILENT-MKDIR-LOSS**: cross-incarnation dir_epoch root (fixed 242) verified at ALL capture scales sess36: 2/caw x4 + 8/caw x5 + 32 board, aged; durable_loss=0, precursors P195=P32E=P194=0 everywhere (structural absence, not just symptom absence). sess25 mass-missing note split out to NEW entry D-DIRVIEW-NONCONVERGE-SESS25 (read-side one-node stale view, high severity, OPEN).
3. **D-CAW-YIELD-STARVATION-SHUTDOWN**: 269 composite fix; sess36 evidence includes mechanism ENGAGEMENT (P221-YIELD-BOUND fired, no exhaustion). Paired A/B waived (structurally non-isolating — ghost-clear is foundational in both arms).

## Board 306 (srcversion C281B7DF)
20/21 PASS; only FAIL = dir_reuse_coherency pace (4-7 rounds vs >=8; host load 12-34 confound; residual = per-release wire-unlock protocol IO cost, TRAP-1 ceiling).

## Key operational lessons
- dmesg persists across module reloads: ALWAYS dmesg -C at deploy or filter by realns; epsrc line numbers differ per build (14919=303, 14925=304, 14926=305, 14938=306 terminal store).
- run.sh post-test dmesg collection blows per-lap timeouts when rings grow (16MB x 262 files); clear rings between lap batches.
- A killed run.sh can leave nodes with FS shut down: probe `mountpoint -q` fails while mount table lists it → sweep with tests/census_p.sh 32 'mountpoint -q /mnt/shared || umount+mount'.
- tests/census_p.sh (NEW sess36): parallel per-node dmesg census without job-control spam.
- P219 family fully contained on 306: 64 class-X masked (all landed), 55 P235 EX-restages, 8 rf/dem passthroughs superseded in-pipeline, 0 unlanded, 0 P224 fatal.

## The 10 OPEN
FOREIGN-REPLAY-UNGATED (needs authority-token protocol or mount-time suppression), RELEASE-BARRIER-OPEN (umbrella; terminal instance closed, per-slot ISTALE/ifree authority model remains), MOUNT-DEGRADES-WITH-USE, MATRIX-UNMEASURED (2/8-node dirent rows measured sess36 as side effect; needs full per-column boards), UNMOUNT-BUSY-INODES, DIR-REUSE-32-FLAKY (pace), 32NODE-SHARED-DIR-CREATE-PACE, INODE-CLUSTER-PUBLISH-WITHOUT-AUTHORITY, READDIR-PEER-CACHED-DIR-PACE, DIRVIEW-NONCONVERGE-SESS25 (new).

## Rig state at note time
Cluster prepped 8/caw on 306. Tree 0.11.306 == deployed. CHANGELOG through 306. Criteria: NOT production ready (10 OPEN).
