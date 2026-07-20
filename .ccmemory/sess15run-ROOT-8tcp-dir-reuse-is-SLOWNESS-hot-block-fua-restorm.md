---
name: sess15run-ROOT-8tcp-dir-reuse-is-SLOWNESS-hot-block-fua-restorm
description: sess15(ccloop): 8/tcp dir_reuse is CORRECT (PASS 8/8 at 900s) but too SLOW (~630s). Root: hot dir block daddr=120 FUA-re-read EVERY access (gen-inval…
metadata:
  type: project
---

## sess15(ccloop) — 8/tcp blocker is SLOWNESS, not correctness (mostly)

### Verified this session (build 9D474579 == validated runtime + P15 probes)
- **1/2/4 tcp still PASS.**
- **8/tcp dir_reuse_coherency PASSES 8/8 on a CLEAN cluster at TEST_TIMEOUT=900** (ROUNDS=24 default). NO content failures, no shutdown. Confirmed: dirinos coherent across all 8 nodes.
- BUT it takes **~630s** (round1@607s → round24@1222s). Native XFS would be ~12s. **~50× over → RULE 0 FAIL.** The full-suite failures were the harness TEST_TIMEOUT (300s default) KILLING dir_reuse mid-run → recorded FAIL → and the kill/contamination cascades fence/fault/tcp_dlm.
- The earlier failrounds.txt content-mismatches (readdir=601/800 etc.) were from CONTAMINATED runs (orphaned remote test procs after a local pkill — local `pkill -f run.sh` does NOT kill the remote `bash dir_reuse_coherency.sh` on the nodes; must `pkill -9 -f dir_reuse_coherency` on each node OR virsh reset).

### Predecessor hypothesis REFUTED
The DABUF P14 probe: `loaded_gen==dir_gen` at EVERY hole (never <). The gen-coupling/decoupling hypothesis is DEAD. (DABUF-hole shutdown is a separate INTERMITTENT correctness face — fmt=2 leaf dir, blocks 1,2 holes, dir held EX — ABA stale-leaf-vs-shrunk-map; not the main blocker.)

### SLOWNESS ROOT (instrumented, RULE 4) — P15-DIRFUA probe
Build 0BB72C83 added `dir_perf_probe` (module param) → logs per dir-class FUA read.
- **Single node** cold 800-entry verify = 0.55s, **0 dir FUA reads** (no peers → no gen bump → dir blocks stay cached).
- **8 nodes**: ALL 200 (capped) P15-DIRFUA reads are the **SAME block daddr=120** (dir DATA block 0 — touched by every lookup/readdir), each `rc=0 fresh_after=1`. The block is FUA-re-read on EVERY access: `_XBF_FUA_FRESH` is set by the read but CLEARED before the next read by the gen-invalidation in xfs_da_read_buf (line ~3351 clears XBF_DONE|_XBF_FUA_FRESH when b_mxfs_dir_gen != i_dlm_dir_gen). So i_dlm_dir_gen is ADVANCING on essentially every dir op at 8 nodes (constant DLM re-acquire / BAST ping-pong), invalidating the hot block each time. 8 nodes × per-access real FUA SCSI read on the LIO target (cache-bypassing, serialized) = ~65s/round verify.

### NEXT (RULE 4)
Find WHY i_dlm_dir_gen advances ~every dir read at 8 nodes. Hypotheses to test:
1. Concurrent dir READERS don't share PR — each read takes/re-acquires EX (or atime forces EX) → BAST ping-pong → gen bump every op. CHECK the dir DLM lock MODE for lookup/readdir (xfs_mxfs_dlm acquire path). If EX-only for dirs → that's the design bug; readers must share PR with NO gen bump.
2. The gen bumps even under shared PR re-acquire. If so, don't bump gen / don't invalidate the hot block when the re-acquire is PR→PR with no peer EX in between.
FIX target: a stable shared-read tenure where the hot dir block stays _XBF_FUA_FRESH (cached) across many lookups → ~50× fewer FUA reads → fits budget. Must NOT regress 1/2/4 correctness (the gen-invalidation exists for cross-node coherency).

probe levers: `mxfs.dir_perf_probe=1` (P15-DIRFUA), `mxfs.instr=1` (P-H18-INVAL). Set via MXFS_EXTRA_MODARGS='dir_perf_probe=1'.
See [[sess14run-PROBE-READY-build-61E384CC-run-drc8-read-P14-DABUF-HOLE]].
