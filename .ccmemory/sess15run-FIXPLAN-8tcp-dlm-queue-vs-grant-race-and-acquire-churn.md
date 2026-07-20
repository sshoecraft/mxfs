---
name: sess15run-FIXPLAN-8tcp-dlm-queue-vs-grant-race-and-acquire-churn
description: sess15(ccloop) FIX PLAN for 8/tcp slowness: TCP-DLM queue-vs-grant race (sess35/36) residual at 8-way. dir_reuse is CORRECT (PASS@900s); blocker is a…
metadata:
  type: project
---

## sess15(ccloop) — FIX PLAN: 8/tcp dir_reuse slowness (TCP-DLM acquire churn)

### Settled facts (don't re-derive)
- **dir_reuse 8/tcp is CORRECT**: PASS 8/8 at TEST_TIMEOUT=900. The -110 (ETIMEDOUT) acquire failures are TOLERATED (file-op retries) — they do NOT fail the test. So the blocker is PURELY **slowness** (RULE 0): ~630s vs ~12s native = ~50×.
- Full 8/tcp suite = 15-16/17; ONLY dir_reuse fails, by harness TEST_TIMEOUT (300s default) killing the slow-but-correct test + the kill/contam (and rare DABUF-hole shutdown) cascading fence/fault/tcp_dlm.
- Slowness = **TCP-DLM acquire stalls**: `P36-RETRY ino=131 mode=EX/PR` (the hot shared test dir) and reused file inodes (e.g. ino=100665222) — per-attempt `MXFS_LOCK_ACQUIRE_WAIT_MS=1000ms` (include/mxfs/mxfs_dlm.h:279), 60 retries = 60s budget. Most recover in 1-2 retries but 8 nodes × every-1s churn + occasional 60-retry exhaustion = the per-round 12-74s variance (a slow round = one node's verify-phase acquire stalled in P36-RETRY; the coord_barrier makes all 8 report ~62s).
- REFUTED: fua_disable=1 did NOT help (not FUA-read cost). Predecessor gen-coupling: REFUTED.

### THE ROOT (documented in mxfs_dlm.h:266-278 sess36 comment, CONFIRMED still live at 8-way)
**Master-side queue-vs-grant race**: a waiter queues in the instant the holder owns no grant → NO BAST captured; the holder then re-acquires (or upgrades) and nothing re-fires the BAST → the waiter is stranded until its OWN ~1s ACQUIRE_WAIT retry re-fires the BAST. sess35 added `collect_grantee_bast_if_waiters` (dlm/dlm.c:528) to the direct-grant/upgrade/REAFFIRM paths (called at 1119 local-upgrade, 1238) + `collect_post_promotion_basts` on the release path. sess36 lowered 6000→1000ms as a BANDAID (each stall ~1s not ~6s). At 8 nodes the residual stalls + churn accumulate.

### FIX DIRECTION (next session — implement carefully, validate ALL of 1/2/4/8 tcp)
The retry should never be NEEDED in steady state. Find the remaining grant path that grants a holder while a conflicting WAITING/BLOCKED waiter exists WITHOUT firing a BAST. Candidates to audit in dlm/dlm.c:
1. **FRESH local grant** (local node acquires a lock it didn't hold, mode compatible with current holders but a conflicting WAITER is queued) — does it call collect_grantee_bast_if_waiters? The local-UPGRADE path (1117-1133) does; verify the fresh-grant path and the **remote-request grant path** (process_remote_request) do too.
2. **promote_waiters FIFO barrier** (605-655) stops at first incompatible — correct, but after promoting PR waiters, ensure the granted PR holders get BASTs if an older/younger EX waiter is blocked (collect_post_promotion_basts at 674 — verify it fires for ALL blocked modes, not just the first).
3. The -110-exhausting reused inodes (ino=100665222): a lock that NEVER grants in 60s = a genuinely stuck/lost grant or a master-reassignment gap (high-AG reused inode). Trace one with DLM_TRACE.

### RISK / CONSTRAINT
`MXFS_LOCK_ACQUIRE_WAIT_MS` is SHARED with the v5_mount ABBA-yield path (mxfs_v5_dlm_inode_lock_retries, v5_mount.c:1081) that sess58 tuned so the inode-acquire returns every ~retries seconds to re-run the cooperative AG-yield (breaks the inode↔AG ABBA deadlock in tcp_dlm_scaling). DO NOT just raise the constant — it would slow that yield cadence and may regress tcp_dlm_scaling. Prefer FIXING the missed-BAST race (no timing change) OR thread a per-call wait_ms so only the full-budget dir path waits longer while the ABBA path keeps 1s. Validate tcp_dlm_scaling + 2/tcp still pass after any change.

### Repro / probes
`MXFS_EXTRA_MODARGS='...' MXFS_TEST_ENV='DRC_ROUNDS=8' TEST_TIMEOUT=400 ./run.sh 8 tcp dir_reuse_coherency`; `dmesg|grep P36-RETRY` (always-on). DLM_TRACE is gated to ino==128 (edit to the hot ino). Build 167ADFFF has dir_perf_probe (P15-DIRFUA) + P14/P15 extent probes — all gated OFF by default (runtime==validated for 1/2/4). Clean repro REQUIRES virsh reset of all 8 (local pkill leaves orphan remote test procs that contaminate). See [[sess15run-PRECISE-ROOT-8tcp-dlm-acquire-starvation-ino131-P36-retry-60s]] [[sess15run-ROOT-8tcp-dir-reuse-is-SLOWNESS-hot-block-fua-restorm]].
