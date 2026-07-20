---
name: sess40-REFRAME-799-is-tcp-flap-not-buffer-barrier-noop
description: sess40 REFRAME: dir_reuse readdir=799 single-dirent loss CORRELATES with a transient TCP DLM flap (peer disconnect+reconnect ~500ms). Buffer barrier…
metadata:
  type: project
---

## sess40 (ccloop 4cb2d0a2) — REFRAME of the dir_reuse readdir=799 residual. Build `E12A35EE` (writeback barrier) REFUTED as a no-op; barrier default reverted to 0. Root is the TCP DLM transport, not the buffer layer.

### What was tried and REFUTED this session
1. **sess39 v2 `dir_refresh_inplace=1`** (EX-gated subset DROP at write chokepoint): CATASTROPHIC on 8/tcp (leaf_removename corruption + bnobt double-free, 0/8). Reverted to default 0.
2. **Writeback-completion-barrier** (build E12A35EE, GPT-5.5 design): at dir EX release, wait for `m_mxfs_dir_wr_inflight==0` (count of submitted-not-completed dir-metadata bios) before DLM unlock. Hypothesis: a prior-tenure dir bio lands AFTER the next holder RMWs. **REFUTED: P40-WRBARRIER NEVER fired — the counter is ALWAYS 0 at release** (publish-before-notify already writes dir blocks SYNCHRONOUSLY, so there are zero in-flight dir bios at handoff). Barrier infra kept (xfs_buf_submit_bio inc + __xfs_buf_ioend dec + m_mxfs_dir_wr_inflight + b_mxfs_dir_wr_counted) but `dir_wr_barrier` DEFAULT 0. Build `E12A35EE` = 3/6 pass on 8/tcp drc_loop8 (no improvement over keeper).

### PROVEN reframe (RULE 4, drc_cap8.sh + node dmesg snapshots)
The readdir=799 single-dirent durable loss CORRELATES with a transient TCP DLM flap:
- Failing iter: `node7_f1` lost (round 1, FRESH dir, NO rm-rf reuse → it's a concurrent-ADD lost-update during initial dir growth, NOT cross-tenure stale write). All 8 nodes agree, LOOKUP_ENOENT REREAD_MISS = durable.
- On test7 (the node whose entry was lost): `TCP peer 2978492619 disconnected — deferring death 15000 ms` at t=46.344, then `reconnected — cancelling pending death (transient flap absorbed)` at t=46.846. A ~500ms disconnect+reconnect. The sess39 deferred-death absorbed it (no split-brain) BUT the entry was still lost.
- DECISIVE NEGATIVES (all silent): P-DATACLOBBER-SKIP, P25-RELVERIFY-MISMATCH, P40-WRBARRIER. So NOT a stale dir-block write, NOT a release in-core/disk gap, NOT a late bio.

### UNIFIED ROOT (both 8/tcp failure modes = ONE cause = TCP flap under load)
- **Mass-fail mode (e.g. drc8_barrier iter3)**: flap LASTS >15s → peer declared dead → P-STALEMASTER-GRANT active_count=7 → split-brain → readdir=0 cascade.
- **799 single-loss mode**: flap <15s → death deferred/absorbed → no split-brain, but ONE in-flight DLM grant/release message is lost in the ~500ms socket gap → one dirent dropped (lost-update / grant-on-incompletely-drained-release).
- LIKELY flap mechanism: under the 8-node create storm a node blocked in a long synchronous DLM op (publish-before-notify drain = xfs_bwrite+blkdev_flush, or CAW poll, or recv-thread msg_cb blocking in DLM processing) stops servicing its TCP recv socket → peers' `mxfs_pal_tcp_send` 16MB buffer fills → 5s sndtimeo + 3 retries (peer.c:891-927) → `mxfs_pal_tcp_shutdown` → disconnect. recv side (peer.c:99-147) disconnects on any non-EAGAIN recv error. TCP keepalive (kern.c set_opts): keepidle=10 intvl=3 cnt=3 (~19s); sndtimeo=5s rcvtimeo=30s.

### NEXT (transport reliability — pick one, RULE 4)
1. **Prevent the flap**: stop the recv thread's `msg_cb` (dlm.c dispatch) from BLOCKING — if BAST/grant processing blocks the per-peer recv thread, the socket stalls and senders disconnect it. Verify bast is deferred to a workqueue (it is `bast_work_fn`) and that msg_cb just queues. If msg_cb blocks (lock/drain), decouple it.
2. **Make DLM flap-tolerant**: DLM lock requests/grants/releases over TCP appear fire-and-forget → a message lost in the 500ms gap is never retransmitted → lost-update. Add request/response ACK + retransmit-on-reconnect, OR on `v5_peer_connect_cb_tcp` (flap absorbed) force-invalidate/re-sync any dir inode that peer was being granted/holding EX on.
3. Confirm correlation: every 799 failure has a flap; every PASS has none (instrument).

### Harnesses
`tests/drc_loop8.sh <iters> [modargs]` (reboot-clean loop, fail-evidence greps declaring-dead/P-STALEMASTER/relverify/dataclobber/shutdown). `tests/drc_cap8.sh <iters> [modargs]` (NEW: breaks on first FAIL, pulls drc_fail_r*.dmesg RDMISS/CLASS/P40 before reboot). Probes: mxfs.dirwr=1 (P40), mxfs.dataclobber=1, mxfs.dir_relverify=1. See [[sess40-FIX-dir-writeback-completion-barrier-readdir799]] (superseded by this), [[sess39-ROOTFIX-membership-splitbrain-formation-and-flap]].
