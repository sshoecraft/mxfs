---
name: sess39-ROOTFIX-membership-splitbrain-formation-and-flap
description: sess39 ROOT-CAUSE FIX (KEEPER build 8CC09D97): 8/tcp dir_reuse CATASTROPHIC 0/8 = membership split-brain (formation ramp + TCP flap). Fixed in dlm: d…
metadata:
  type: project
---

## sess39 — KEEPER build `8CC09D972985FD5D279D207`. CRITERIA NOT MET (8/tcp dir_reuse still loses 1 dirent ~half of runs; 1/2/4 tcp OK). The MEMBERSHIP root that 37 sessions of dir-block heuristics missed is FIXED; the residual is the deep steady-state zombie.

### ★ MAJOR WIN — root-caused + fixed the 8/tcp CATASTROPHIC (0/8) failures = MEMBERSHIP SPLIT-BRAIN (PROVEN, RULE 4):
Inconsistent `active_nodes` → `master = nodes[hash%count]` diverges across nodes → two nodes grant EX for the same dir → mass corruption (readdir=0/163/796 → cascades to DABUF_MAP_HOLE / xfs_dir3_block_verify shutdown). TWO triggers, same mechanism:
1. **FORMATION ramp**: 8 nodes converge 1→8; during the ramp they hold DIVERGENT views. PROVEN: `P-STALEMASTER-GRANT ino=128 active_count=5` and `=6` at t=47s on a fresh-boot run (workload round-1 started before convergence).
2. **Mid-run TCP FLAP**: under storm a peer's TCP stalls ~7s (all 7 peers drop t=366.2, reconnect t=373). `v5_peer_disconnect_cb_tcp` (dlm/v5_mount.c) IMMEDIATELY purged the node's locks + unregistered lease + refreshed active_nodes (8→7) — forgetting its held EX + remastering. This v5 TCP path BYPASSES the cooldown/stabilization in dlm/mount.c. ("membership changed" logs at DEBUG → invisible in dmesg; don't trust its absence.)

### THE FIX (both in dlm/, DEFAULT-ON, kill-switchable) — KEEP:
1. **Deferred TCP-death** (dlm/v5_mount.c, `tcp_death_grace_ms=15000`): disconnect marks peer SUSPECT (not immediate purge); new grace-checker thread `v5_tcp_death_worker_fn` declares death (`v5_tcp_declare_dead` = old purge+unregister+refresh) only if no reconnect within grace; `v5_peer_connect_cb_tcp` cancels on reconnect. Genuine death still caught by `v5_lease_expire_cb`. `=0` legacy.
2. **EX-grant membership-settle gate** (dlm/dlm.c, `memb_settle_ms=6000`, var defined in v5_mount.c): `dlm_lock_impl` BLOCKS an EX acquire (bounded 60s) while `dlm_membership_settling()` (active set changed within window; new field `ctx->last_memb_change_ms` stamped in update_active_nodes). Every node defers EX work until membership globally stable → consistent masters → no split-brain EX. Single-node + steady-state never gate (zero perf impact).

### EVIDENCE FIX WORKS: P-STALEMASTER-GRANT dropped to **0** on fresh-boot 8/tcp; catastrophic readdir=0/163 GONE. **2/tcp dir_reuse = 3/3 PASS (no regression)**. Validated harness `tests/drc_loop8.sh <iters> [modargs]` (reboot-clean, 20s settle, clears failrounds+dmesg, captures churn counts).

### THE RESIDUAL (NOT fixed, criterion blocker): rare steady-state xfsaild ZOMBIE reflush. With membership fixed: `stale=0 disc=0` cluster-wide, `P-DATACLOBBER-SKIP kind=data daddr=120 buf_cnt=154 disk_cnt=155 in_ail=1 bdirty=0 in_txn=0 comm=xfsaild` → readdir=799 (then cascades to DABUF_MAP_HOLE shutdown). MECHANISM (traced): on a handoff EX acquire the fast-path (xfs_mxfs_dlm.c ~13760) DOES eager `mxfs_dir_drain_evict_data_blocks`, but it SKIPS blocks it can't evict (`left>0` — block 0 is LOCKED by this node's own xfsaild mid-reflush, or undestaged). The skipped stale block-0 buffer is then reflushed stale by xfsaild. It's a RACE: acquire-side evict vs xfsaild-flush of the same buffer. The buffer reads bufgen==dirgen (looks current) yet is content-stale (it was stamped current without a real refresh).

### REFUTED this session (ALL on top of the membership fix, so NOT split-brain-confounded — these are genuinely the wall):
- `dir_tenure_reflush_skip=1` → round-1 readdir=0 (skip catches fresh writes).
- `dir_release_retire_bli=1 + dir_release_retire_done=1` → readdir=796 (over-lost 4 / cemented stale; the lseq==wseq destaged check is unreliable; the prior round-1 SHUTDOWN was a split-brain artifact, now gone).
- `dir_force_evict=1 dir_tenure_evict=1` → readdir=268 lookup_fail=161 (force-evict creates zombie BLIs / corrupts).
- **`dir_refresh_inplace=1`** (NEW this session, xfs_buf.c + xfs_mxfs_dlm.c, now DEFAULT-0 inert): at the xfsaild flush, when we hold EX (so disk read is stable) and disk is a strict superset of a clean in-AIL buffer, memcpy disk→buffer + complete no-op. → CORRUPTS: `xfs_dir3_block_verify block 0x78` metadata corruption. The disk image is NOT a drop-in for the in-core buffer's verifier/CRC/log state. REFUTED.
- Longer settle window (12000) → no change (residual is steady-state, not formation).
- CONCLUSION: EVERY buffer-layer intervention (skip/drop/retire/force-evict/refresh) corrupts or over-loses. The residual needs an ARCHITECTURAL fix.

### NEXT (RULE 4) — architectural options for the residual zombie (pick one, fresh context):
1. **Make `mxfs_dir_drain_evict_data_blocks` not SKIP on the acquire side**: when block 0 is locked by our own xfsaild mid-flush, ABORT/wait that in-flight write (don't let the stale flush land), then invalidate. Needs a flush-abort or io-quiesce for the inode's dir buffers at handoff-acquire.
2. **Write-through dir DATA blocks in multi-node mode**: dir blocks written synchronously (FUA) at modify under EX, buffer dropped after — so xfsaild never has a dir buffer to background-reflush. Biggest change; cleanest invariant.
3. **GPT's full write-authority token** ([[sess38-GPT2-DLM-fix-design-split-brain-mastership-write-authority]] #4): xfsaild must hold a per-resource current-EX write-authority token (mode+seq+cookie+io_refs) before submitting a dir-metadata write; BAST clears authority first, drains io_refs, invalidates. The principled fix; substantial.

Build identities: keeper `8CC09D97`; membership-fix-validated `5CE302DF`; with-refresh(refuted) `93B0F6ED`. See [[sess38-HEAD-handoff]] [[sess38-DECISIVE-loss-is-stale-EX-grant-bufepoch-eq-masterep]] [[sess38-GPT2-DLM-fix-design-split-brain-mastership-write-authority]].
