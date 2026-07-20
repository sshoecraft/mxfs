---
name: AAA-ccloopa864-sess7-diagrun-live-r7-clean-watch-outcome
description: sess7 HANDOFF: dir_reuse@32/caw run (v0.10.53 C98E4152) LIVE r7 clean. SOLE criteria gap. Audit: 101 caw cells PASS, only this MISSING. Watch monitor…
metadata:
  type: project
---

## sess7 (ccloop a864) — dir_reuse@32/caw run LIVE, r7 clean, progressing

### CRITERIA AUDIT (definitive, this session, criteria.json):
`jq` over all applicable caw cells at 1/2/4/8/16/32 = **101 PASS + exactly 1 MISSING**. The one missing cell is **`dir_reuse_coherency 32/caw`** — the cell the LIVE run fills. Every other caw cell across every node count is PASS. dir_reuse has min_nodes=2 so 1/caw is N/A (correct). When this run records `nodes_pass=32/32` → 102/102 caw PASS → **criteria met**.

### LIVE RUN — DO NOT KILL, DO NOT REBUILD, DO NOT START OTHER RUNS (shared LUN)
`MXFS_DEV=/dev/mapper/mpatha ./run.sh 32 caw dir_reuse_coherency` — nohup timeout 4600, started ~11:31Z (run_id 20260711T113122Z). Build **v0.10.53 / C98E41521CB5C45CFF49804** on all 32 nodes. At 11:47Z: **r7/24, PHASE=create-done, all nodes synced, NO wedge, NO P-IOWAIT-STUCK**. Pace ~2.3 min/round → projected finish ~12:26Z. Node-side per-node timeout tt=140*32=**4480s** (deadline ~12:45Z); nohup 4600s (~12:47Z). run.sh master is blocked in `wait`; on completion `record()` writes criteria.json `dir_reuse_coherency.runs["32/caw"]`.

### FIRST ACTION next session: check the run.
`pgrep -f 'run.sh 32 caw'`; snapshot round: for n in 1..32 `dmesg|grep mxfs-DRCph|tail -1` (all should share same r=/PHASE). Monitor **bo9jsbmm7** (this session) emits HB per round + STALL(>150s no advance) + WEDGE-MARK + RUN-EXITED. If monitor is gone (session ended), re-arm it (command in sess7 transcript) or just poll.

### DECISION on RUN-EXITED / completion:
1. `jq '.categories[].tests[]|select(.name=="dir_reuse_coherency").runs["32/caw"]' criteria.json`.
2. If **PASS (nodes_pass=32/32)** → re-audit all caw cells (the jq above: 0 non-PASS) → optional quick no-regression (do NOT need to; every lower cell already PASS and recorded) → **`echo YES > /src/mxfs/.ccloop/runs/a8642ea1-81eb-4fcd-beea-b99f4f52db31/criteria-met`**. That is the ONLY exit condition; criteria = "1/2/4/8/16/32 node caw dlm multipath test 100%".
3. If **FAIL/wedge** → the failure is the sess6-proven lost-b_iowait-wakeup (see memory AAA-ccloopa864-sess6-HANDOFF...). Capture P-IOWAIT-STUCK on the stuck node — it now prints `sync_wait ioend_seen relse_seen` (v0.10.53 diag). DECODE: sync_wait=0 ⇒ last submit was ASYNC (xfsaild stole buf in owner_scan/bmbt_scan b_hold-only walk window) → fix = force sync ownership on durable_signal re-bwrite OR block async submit while durable_signal holds b_hold OR safe-exit xfs_buf_iowait on DONE+no-inflight+hold-b_sema. ioend_seen=0 ⇒ bio lost on FUA-fallback (different bug). relse_seen>0 ⇒ wrongful async-relse confirmed. Then RULE 4 loop: fix → rev VERSION → make modules → run.sh reprep → re-run.

### Mechanics: SSH=`bash tools/mxfs_sshpass.sh testN /tmp/.mxfs_pass '<cmd>'`. DEV=/dev/mapper/mpatha (mpath, 2 paths). run.sh prep re-mkfs+power-cycles all 32 + asserts srcversion + converges before the test. `record()` writes `.runs["N/caw"]`. Fixes in tree (KEEP): v0.10.52 b_mxfs_sync_wait + v0.10.53 diag fields.
</body>
