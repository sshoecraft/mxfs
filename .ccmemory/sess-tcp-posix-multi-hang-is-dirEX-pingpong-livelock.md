---
name: sess-tcp-posix-multi-hang-is-dirEX-pingpong-livelock
description: CORRECTED: posix_multi(100/node) 2-node TCP hang is NOT durable lost-update nor pure deadlock — it's dir-EX ping-pong + per-handoff drain churn (live…
metadata:
  type: project
---

## Decisive findings (build B77AD901, fresh-format cluster, RULE 4)
Refutes [[sess-tcp-dir-lostupdate-is-multiblock]] "durable multi-block lost-update":
- Instrumented phase timing (tests/repro_pm_timed.sh): single-node 100 creates=0.015s;
  concurrent same-dir 100/node creates=0.07s; cross-node readdir count=0.01s SEEING ALL 200
  (CONVERGES, no lost-update); peer content read=0.008s correct. NO op is slow in isolation.
- posix_multi (FPN=100) FAILS 3 different ways across runs (FLAKY): (a) full HANG (no RESULT,
  both nodes ~60s silent then `DLM inode lock failed ino=<dir> mode=3/5 rc=-110` = ETIMEDOUT
  on the 60s MXFS_LOCK_WAIT_TIMEOUT_MS); (b) count=100 (premature read after a barrier
  desynced by a slow node); (c) "hardlink-name gone" rename/unlink-visibility miss.
- 30-file concurrent (zero_silent_loss FPN=10) PASSES — the hang needs the MULTI-BLOCK dir
  (>1 4K dir-data block, ~>60 short names). So multi-block is the TRIGGER, but the bug is
  slowness/livelock, not a durable on-disk divergence (dir always converges post-hoc).

## Root mechanism (frozen-state capture, tests/catch_hang.sh)
At hang freeze: NO test process (bash/sh/touch) is kernel-blocked — only idle workers. So
it is NOT a pure D-state deadlock. It is dir-EX lock PING-PONG + per-handoff drain churn:
- dir inode DLM EX is CACHED and ping-pongs between nodes (i_dlm_dir_gen advances 2->4->...).
- EACH handoff runs the FULL release fence (xfs_mxfs_dlm.c ~L3370-3456): xfs_log_force(SYNC)
  + xfs_ail_push_ag_sync + mxfs_dir_flush_data_blocks (bwrite every dir block, wait unpin),
  unbounded until data_durable. Several handoffs * slow drain = tens of seconds.
- Read path spams `DIR-STALE-SKIP ino=<dir> blk=N buf_gen=0 inode_gen=N pin=1 ... bli_flags=0x2`
  hundreds/sec (xfs_da_read_buf:3213). buf_gen=0 is a FALSE-POSITIVE stale marker: evict set
  b_mxfs_dir_gen=0 on a clean block, then a LOCAL modify re-validated+pinned it WITHOUT
  bumping b_mxfs_dir_gen back to i_dlm_dir_gen, so every later read flags it stale (content
  is actually this node's current). Harmless to correctness, but signals gen tracking is off.
- LOCK ORDER in xfs_create (xfs/xfs_inode.c ~L1334-1355): xfs_dialloc (AG-DLM) FIRST, THEN
  re-acquire dir ILOCK (cluster dir-EX, cached). A node holding cached dir-EX that diallocs
  into an AG a peer holds, while the peer holds that AG and wants dir-EX = AB-BA risk (not
  observed as D-state at freeze, but architecturally present).

## Fix hypothesis under test (NO rebuild — runtime param)
Minimum Hold Time `inode_mht_ms` default=50ms is too short -> per-op ping-pong. Raising it
(echo 3000 > /sys/module/mxfs/parameters/inode_mht_ms on every node) should batch each
node's 100 creates into ~1 tenure -> ~2 handoffs total -> ~2 drains -> fast + no -110.
If that makes posix_multi pass reliably+fast, the fix = raise the mht default (xfs_mxfs_dlm.c
mxfs_inode_mht_ms) and/or make the release fence cheaper. TESTING NOW.

## Repro tooling added (tests/)
repro_pm_loop.sh (N iters, no reformat), repro_pm_timed.sh (phase timing), catch_hang.sh
(freeze-dump stacks+dmesg on a hang), stall_catch.sh. run via tests/setup/reset2_tcp.sh to
reformat between contaminated states (a hang can leave a node's umount D-state in
xfs_buftarg_drain -> needs virsh destroy+start, see [[reference-node-power-control]]).
</body>
