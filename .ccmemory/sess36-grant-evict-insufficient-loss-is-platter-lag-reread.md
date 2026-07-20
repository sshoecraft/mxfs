---
name: sess36-grant-evict-insufficient-loss-is-platter-lag-reread
description: sess36 KEY: grant-evict (sess10/61 fix) is SAFE but INSUFFICIENT — refreshes RMW base yet loss persists. Loss=node2_f49 durable, on ALL nodes. Lead:…
metadata:
  type: project
---

## sess36 (ccloop 4cb2d0a2) — DECISIVE NEGATIVE on the grant-evict; new lead = FUA-platter-lag on the post-evict re-read.

### Build 64544CAD = keeper 4703FA18 + `dir_grant_evict=1` (modify-evict keep-guard force-evicts a clean dir block whose b_mxfs_grant_gen != i_dlm_cached_grant_gen) + `dir_conv_genbump=0` (refuted). The grant-evict IS the long-sought sess10/sess61 fix, finally wired into the modify-EVICT (not just the read path).

### PROVEN this session (RULE 4, dirwr=1 capture, full 8-node):
1. **grant-evict is SAFE**: full 8-node drc run, 0 shutdowns, P36-GRANTEVICT fires correctly on ino=131 daddr=120 + every dir block, bgrant != cached_grant (e.g. 30681 vs 30698). The iter1 SHUTDOWN seen earlier was the pre-existing ino=131 184s DLM acquire-timeout flakiness (rc=-110), NOT my fix.
2. **grant-evict is INSUFFICIENT**: loss STILL occurs — readdir=799/800 round7 ALL 8 nodes. The evicted blocks are `in_ail=0 undestaged=0 undurable=0` = ALREADY evicted by existing logic, so the RMW base IS refreshed. **REFUTES the stale-base-RMW-at-modify theory as the sole root** — a fresh base still loses an entry.
3. **The lost entry = `node2_f49`** (node2's OWN file), added by node2 to **daddr=14654480** off=1552 (P11-DATALOG t=36.251 rank2), then durably LOOKUP_ENOENT + REREAD_MISS on ALL ranks (1,4,5,6,7,8). A single-dirent durable loss in the middle of the block.

### THE NEW LEAD (FUA-platter-lag, the CLAUDE.md "LIO drops FUA / target write-cache" hazard):
node2 adds f49, releases EX (drain). A PEER acquires EX, its grant-evict clears XBF_DONE on daddr 14654480 and FUA-re-reads — but the FUA read hits the PLATTER which LAGS the LIO target write-cache where node2's drained f49 still sits. So the peer's "fresh" reread is MISSING f49 → RMWs its own files onto that base → release-drain writes the block WITHOUT f49 → f49 durably gone everywhere (incl node2 on its next reread). The grant-evict correctly evicts+rereads but the reread SOURCE (platter) is stale. This explains why EVERY base-refresh fix (evict/gen/epoch/grant) has failed: the problem is downstream of the cache — the durable medium the FUA read targets lags the writer's drain.

### TESTING NOW: `dir_modify_target_flush=1` (SYNCHRONIZE CACHE after the modify-evict, before the FUA reread → push the writer's drained dirent from target cache to platter). cap_tf.log. If PASS → root CONFIRMED = platter-lag; implement a cheaper targeted flush (likely at the WRITER's release-drain: FUA-write or SYNCHRONIZE CACHE so peers' FUA reads are valid — check dir_release_fua_write / dir_release_flush_all_done). If still loses → platter-lag refuted, look elsewhere (leaf/freescan revert).

### STATE: build 64544CAD on disk (grant_evict ON default, conv_genbump OFF). Both are NEW levers this session. grant_evict is safe+sound but unproven-beneficial; consider default-OFF if next session wants pure keeper baseline. Repro: scratchpad cap.sh "<MA>" 24 (single 8-node drc run + dmesg capture); stream logs at tests/tcp/drc_cap/stream_rank*.log. See [[sess36-FIX-grant-gen-modify-evict-keepguard]] [[sess33-HEAD-handoff]].
