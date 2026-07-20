---
name: sess-tcp-double-grant-instrumentation-impossible
description: KEY: the tcp_dlm_scaling double-grant race is so narrow that ANY in-band recording (printk P-LKT AND lock-free no-printk ring) hides it (6/6 pass). N…
metadata:
  type: project
---

## DECISIVE FINDING (build 30D3C28E): the double-grant is un-instrumentable in-band.
Two independent in-kernel trace mechanisms BOTH make tcp_dlm_scaling go 6/6 PASS (Heisenbug):
1. printk per-lock-op (mxfs.lockwr=1 → mxfs_pal_log P-LKT): 6/6 pass.
2. LOCK-FREE, NO-PRINKT event ring (built this session: a few memory writes under the
   already-held table_rwlock, dump-only-post-mortem via the lktdump param): ALSO 6/6 pass.
=> The race window is sub-microsecond; even a handful of struct-field writes per grant/release
shifts the timing enough to close it. ANY in-band recording at the DLM lock sites hides it.
Therefore: do NOT try to instrument the lock path in-band. RULE 4's "instrumented proof before
patch" is PHYSICALLY IMPOSSIBLE in-band here — substitute EMPIRICAL OUTCOME validation: apply a
reasoned fix, then measure the standalone fail rate (~50% → must reach ~0 over ≥20 runs) + full
suite for regressions.

## OBSERVATION ALTERNATIVES if proof is still wanted (lower overhead than printk/ring):
- ftrace function tracer (set_ftrace_filter on the grant/remove/release fns in
  /sys/kernel/debug/tracing/) — ~100ns/event vs ~1µs+ printk; MIGHT be low enough not to hide it.
  Capture trace_pipe at the failure. Untested.
- A COUNTER-only anomaly detector: at the EX-grant point, the master could compare its just-made
  grant against a CHEAP cross-node signal — but the divergence is master-table (1 holder) vs the
  OTHER node's cached i_dlm_mode=EX, which is not locally visible, so a single-node detector can't
  see it. Would need a shared on-disk/heartbeat EX-holder bitmap (TCP has none; CAW has
  mxfs_v5_dlm_inode_ex_count via disk slots — not available on TCP).

## TOOLING LEFT IN TREE (build 30D3C28E, all gated OFF by default = behaviorally == 73B0809D):
- dlm/dlm.c: lock-free P-LKT ring (mxfs_lkt_record / mxfs_dlm_lkt_dump), recording gated on
  mxfs.lockwr, dumped by writing a dir-ino to /sys/module/mxfs/parameters/lktdump. Harmless dormant
  (won't catch THIS race; useful for coarser future DLM debugging). P_LKT() placed at: grant
  insert (local+remote), reaffirm-remote, stale-removal-remote, unlock, remote-release.
- xfs/xfs_mxfs_dlm.c: params instr/dirwr/lockwr + lktdump (module_param_cb). P-RDDIAG in
  xfs_dir2_readdir.c (instr-gated). B4 inode guard (KEEP). prep_node.sh MODARGS = clean
  force_transport=1. Repro: tests/tcp/repro_double_grant.sh.

## FIX PATH for next session (reason + empirical-validate, NO in-band tracing):
Root = master grants EX to peer P while holder H still holds EX cached, H's master-table entry
removed WITHOUT H releasing (P106: H had no EXREL). H never released → NOT a stale LOCK_RELEASE,
so a RELEASE-only fencing token would NOT fix it. The removal is in the REQUEST path: H (or P)
RE-REQUESTS while a waiter exists → Bug-51 still_safe check (dlm.c ~2044-2078) FALSE due to the
waiter → stale-removal (dlm.c ~2081-2134 remote / ~890-911 local) removes the holder's entry +
promote_waiters grants the peer, but the holder got NO BAST (it initiated) → both hold EX.
=> FIX = monotonic per-grant GENERATION token on the grant + REQUEST + release messages (model on
struct mxfs_lock.request_epoch/granted_at). The stale-removal must only fire when the re-request
carries a gen OLDER than the current GRANTED entry's gen (genuinely stale, holder already moved on);
a re-request carrying the CURRENT gen = the holder still holds → re-affirm / do NOT remove+promote.
GUARD the request-path removal, not just release. CAUTION: don't break the Bug-51 fix that made
posix_multi pass — validate posix_multi + cache_coherency + tcp_dlm_scaling + full suite.
See [[sess-tcp-double-grant-mechanism-refinement]] [[sess-tcp-tcp-dlm-scaling-DOUBLE-GRANT-proven]].
