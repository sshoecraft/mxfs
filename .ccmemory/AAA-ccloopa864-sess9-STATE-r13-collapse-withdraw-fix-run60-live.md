---
name: AAA-ccloopa864-sess9-STATE-r13-collapse-withdraw-fix-run60-live
description: sess9: r13 32/caw collapse root-chained (shutdown nodes keep contending DLM; rank8 won dir EX 6min post-shutdown). Fix=shutdown withdrawal (0.10.60 C…
metadata:
  type: project
---

# sess9 (ccloop a864) — state at run60 launch

## Builds
- 0.10.58 = D797C10D (sess8 wedge#2 force_sync latch) — TESTED: wedge#2 STILL fired at r4 (P-IOWAIT-STUCK sync_wait=0 ioend_seen=2 relse_seen=2, comm=rm, dir3_data). force_sync latch alone insufficient.
- 0.10.59 = A446F1B6 (event-ring diag): per-buffer 8-event lifecycle ring (`b_mxfs_evring[8]` xfs_buf.h; `mxfs_buf_ev()` pal/linux/xfs_buf.c; events SUBMIT/BIOEND/IOEND/WORKER/EHERR/RESUB/BIO/IOFAIL/IOWAIT/STALE). P-IOWAIT-STUCK now dumps the ring. Decoder: `scripts/decode_bufev.py` (pipe stuck lines in). ALSO: latent-hole fix in `xfs_buf_ioend_handle_error` resubmit: carries `b_mxfs_force_sync = b_mxfs_sync_wait` into the resubmit (proven NOT this run's trigger — 0 I/O-error alerts — but closes the snapshot-reset hole).
- 0.10.60 = CEB546B0 (SHUTDOWN WITHDRAWAL, see below). Run60 live since 16:08:33Z 2026-07-11 (`timeout 4800 ./run.sh 32 caw dir_reuse_coherency`, log $SC/test60.log, SC=/tmp/claude-1000/-src-mxfs/6d68e8ae-1395-4854-9cdf-d917f75ca5db/scratchpad).

## Run59 (build A446F1B6) — NEW failure at r13 (wedge#2 did NOT fire in 12 clean rounds)
r13 create: **CAW inode-lock starvation cascade → 27/32 nodes shutdown** (all "DLM inode lock unrecoverable ino=131 mode=5 rc=-110" at xfs_mxfs_dlm.c:20801). Survivors: ranks 1,9,15,27,29.
PROVEN chain (streams in tests/tcp/drc_cap/stream_rank*.log.prev60):
1. ~1646s: ino131 (shared dir) EX becomes unavailable to some waiters for 360s+ (rank10 4×120s attempts) while EX handoffs CONTINUE for others (rank9 created with EX mid-siege) → fairness/starvation, not frozen holder. Slot gen was only 512 at 2006s → slot 63023 was RECENTLY RECREATED (ABA counter restart = slot reclamation hit the hot dir slot ~r13; 13 rounds × 3200 files cycled the 65536-slot table). UNPROVEN sub-hypothesis: reclamation of actively-waited slot lost waiter state → starve.
2. 1992s: first ~8 nodes rc=-110 → shutdown. Then cascade.
3. Shutdown nodes' dd/bash loops KEPT CONTENDING (no fence): slot CAS gen 512→130k in ~350s. rank8 (node_slot 20) SHUT DOWN at 1993s yet ACQUIRED ino131 EX at 2359s (P34-ACQ-SLOW rc=0, P35-ACQBAST-BATCH; disk last_ex_slot=20) — zombie tenure. rank1 SESS50-STARVE for minutes; its dd D-state in mxfs_dlm_ilock_begin under lookup.
4. Dead nodes' waiter bits + heartbeats persisted (slot dump: waiters=waiters_ex=yield_to=0x0805a100 = slots {8,13,15,16,18,27} all dead) — peers never purged them because shutdown nodes KEEP HEARTBEATING.
Slot dump method: disklock_offset=67117056 (chk_mxfs -v), CAW lock region = +32768, slot N at byte region+N*512 → slot 63023 = LBA 194175 (dd bs=512 skip=194175). Struct: magic@0 gen@4 resource@8(ino@16) hex@40 hpw@48 hpr@56 waiters@80 gm@88 wm@89 streak@92 lastmod@96 yield_to@104 ysm@112 wex@120 dir_epoch@128 last_ex_slot@132.

## FIX in 0.10.60 — shutdown withdrawal ("a dead FS leaves the cluster")
- `xfs_do_force_shutdown` (xfs/xfs_fsops.c): on FIRST shutdown queues `mp->m_mxfs_withdraw_work` (new field xfs_mount.h; INIT at dlm init in pal/linux/xfs_super.c ~2679).
- Worker (`mxfs_dlm_withdraw_work_fn`, xfs_mxfs_dlm.c ~19099 area) → `mxfs_v5_dlm_shutdown_withdraw(ctx)` (dlm/v5_mount.c): sets ctx->withdrawn, stops disklock heartbeat → peers' fire_dead→expire_cb purge reclaims our slots (~2 hb intervals).
- Fences: `mxfs_dlm_ilock_begin` early-return + P-SHUTDOWN-FENCE probe when xfs_is_shutdown (ilock_end tolerates unpaired end, P71 guards). v5: inode_lock/ag_lock/ag_lock_nb return -ESHUTDOWN when withdrawn.
- put_super + 2 mount-error paths (xfs_super.c): NULL m_mxfs_dlm FIRST, cancel_work_sync(withdraw_work), THEN v5_shutdown(ptr) — closes worker use-after-free.

## run.sh status lifecycle FIXED (user request)
PENDING is now live-run-only: reset_pending writes {status:PENDING, reason:"running <run_id>"} markers (was: cell deletion → permanent phantom PENDING); EXIT trap `finalize_pending` converts this run's leftover markers to FAIL; `fail_stale_pending` at start heals kill-9 leftovers. trap 'exit 143' TERM INT installed. NOTE: TERM-kill of run.sh does NOT fire the trap if its foreground child ignores TERM — kill children too (or the next invocation heals). Board healed: dir_reuse 32/caw currently FAIL (wedged r4 note).

## Watch in run60
- P-WITHDRAW-QUEUE / P-WITHDRAW / P-SHUTDOWN-FENCE = fix working when any node shuts down.
- P-IOWAIT-STUCK with ev=[...] ring → decode with scripts/decode_bufev.py → THE wedge#2 answer.
- r13 area: does the starvation recur? If nodes shut down but cascade contained (few victims, no zombie EX), fix A works; starvation root (defect B: suspect slot reclamation) still needs its own fix — instrument slot-reclaim of waited slots next.
- Round pace ~125s (24 rounds ≈ 50min); internal per-node budget 4480s; outer 4800s.

## Env notes
- Test cmd: `env MXFS_DEV=/dev/mapper/mpatha MXFS_TEST_ENV='DRC_STREAM=1' timeout 4800 ./run.sh 32 caw dir_reuse_coherency`
- Cleanup: pkill drivers ('timeout 4480'), pkill -x sshpass (they hold the flock FD!), rm /tmp/mxfs_run.lock.
- All 16 other 32/caw cells PASS; dir_reuse_coherency 32/caw is the ONLY criteria gap.
