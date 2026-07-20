---
name: sess-tcp-HANDOFF-phantom-ex-fixed-residual-incarn-aba
description: HANDOFF build 6E20D7F9: phantom-EX FIXED (TCP held-check was broken). dir_reuse 2/tcp still flaky-fails on residual = prior-incarnation block-0 buffe…
metadata:
  type: project
---

## HANDOFF (build 6E20D7F9) — dir_reuse_coherency 2/tcp: phantom-EX FIXED, residual remains

### CRITERION still NOT met. Only dir_reuse_coherency fails (16/17). Marker NOT written.

### LANDED FIXES (all KEEP — real bugs):
1. **TCP held-check** (dlm/dlm.c `mxfs_dlm_held_mode`, dlm/v5_mount.c `mxfs_v5_dlm_inode_held` +
   `mxfs_v5_dlm_is_tcp`): `mxfs_v5_dlm_inode_held` returned 1 ALWAYS on TCP → ALL phantom-EX
   detection inert on TCP for ~90 sessions. Now a real local-mirror lookup.
2. **Unpublished-EX backstop broadened** (xfs_mxfs_dlm.c ~8309): divert EVERY unpublished dir
   EX-modify (pin==0) to slow-path real acquire (was gated `reused||!self_created`).
3. **Un-throttled TCP dir-EX held-verify + re-acquire** (xfs_mxfs_dlm.c ~8246, "P-TCPEX-REACQ"):
   published dir, held<EX → demote in-core, slow-path re-acquire.
**RESULT: P106-STALE-EX → 0, P-TCPEX-REACQ → 0. Phantom-EX (mutual-exclusion violation) ELIMINATED.**

### DIAGNOSTICS (gated mxfs.dirwr=1 now, off by default): P-DWR/P-DRD in xfs_dir2_data.c
(node1_f dirent count per dir block write/read + comm). P-DE/P106/P-TCPEX logs are cheap-capped.

### RESIDUAL ROOT (PROVEN, flaky ~50%): DIVERGENT block-0 cache via PRIOR-INCARNATION buffer.
- Loss ALWAYS node1's first data files (node1_f1..f18, block 0) or last md5 (leaf); node2 wins.
- P-DWR: block-0 daddr (112/120, REUSED across rm-rf+recreate) on-disk content OSCILLATES
  83↔100 (83=node2 view missing node1's, 100=complete), ALL writes by **xfsaild** (release-fence
  xfs_bwrite never fires — block already clean). P-DRD: failing runs read disk=83 (DURABLE stale).
- P35F-STALE-RETRY-EXHAUSTED=0, P-SF-DURABLE-FAIL=0 → release drain/stale COMPLETES; not a
  release-miss. P34-TRYLOCK-STALE blk=0 daddr=112 42x → read-hook serves stale (buffer LOCKED).
- MECHANISM: node2's round-N buffer at daddr=112 (incarnation N) LINGERS into round N+1 (daddr
  reused). drain_evict at acquire finds nothing (new dir empty → extent map has no data block yet,
  block 0 re-allocated at daddr=112 only DURING modify). Read-hook incarn_aba check
  (xfs_da_btree.c ~3212 `b_mxfs_dir_incarn != i_generation`) is the right catch BUT (a) TRYLOCK
  fails (node2's own xfsaild destaging the stale buffer = locked) and/or (b) the invalidate is
  SKIPPED when the buffer is dirty/pinned/delwri (3220/3228/3229) — yet a prior-incarnation
  buffer's dirty content is DEAD and MUST be discarded (destaging it clobbers the new incarnation).

### NEXT-FIX CANDIDATES (RULE 4 — try, test 4x flaky):
1. **Discard incarn_aba dirty buffers**: at xfs_da_btree.c ~3216, for owner_aba||incarn_aba,
   xfs_buf_stale() the buffer EVEN IF dirty/delwri (cancel the dead incarnation's writeback) —
   skip only PINNED (sess64). The dead-incarnation content has no value; destaging it IS the
   clobber. Watch ghost-buf/AIL corruption (sess99 stale was safe post-drain; here it's pre-drain
   of dead data — may need xfs_trans_binval semantics).
2. **Cross-node freed-daddr invalidation**: node1 frees block 0 (rm-rf) and binvals locally; node2
   never invalidates its cached daddr=112 buffer. Make peer block-free/realloc invalidate peers'
   buffers at that daddr (the true root; harder).
3. **Stop xfsaild destaging prior-incarnation dir buffers** (the lock+clobber source).
Reproduce: `MXFS_EXTRA_MODARGS='inode_mht_ms=300' bash tests/drc_cap2.sh` (dmesg -C first; with
mxfs.dirwr=1 for P-DWR/P-DRD). mht=300 still NOT code default — make default before criterion run.
See [[sess-tcp-drc-residual-is-divergent-block0-cache-writeside]]
[[sess-tcp-PHANTOM-EX-root-fix-held-check-was-tcp-noop]].
