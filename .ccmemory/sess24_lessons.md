---
name: Sess24 lessons (cached-AG divergence + ruled out LIO bug)
description: Sess24 P33 diagnostic captured BOTH nodes simultaneously alloc'ing OVERLAPPING ranges from same AG (smoking gun). P35 confirmed both nodes had pag_dlm_cached=true on AG=0 simultaneously. caw_verify.c built — LIO target CAW cross-init coherence WORKS (sess23 hypothesis #1 falsified). UDP-BAST-on-claim-empty fix made things worse. Disable-cached experiment broke inode-DLM. Bug remains open: cached-AG state diverges silently between nodes.
type: project
originSessionId: 586111e5-07cc-45d0-b00f-761e04d0712c
---
## Headline finding

The bnobt LEFT/RIGHT-FAIL family is caused by **cached-AG state divergence between nodes**.  Both T1 and T2 simultaneously have `pag_dlm_cached=true` on the same AG, neither doing CAW round-trips, neither receiving BAST notifications.  Both alloc concurrently → overlapping ranges → bnobt corruption.

P33-INSTR diagnostic (in tree at `xfs/libxfs/xfs_alloc.c`) captures this directly:
- Run-1 iter 4: T1 alloc'd [24568..48008) + T2 alloc'd [16392..91288) at AG=0.
- Run-3 iter 9: T1 alloc'd [8200..139256) + T2 alloc'd ranges overlapping.

P35 traced AG-DLM acquire path: from 21:03:36 onward in run 3, NEITHER node did fresh-acquire on AG=0; both used `fast-cached` path — confirming the local cache state divergence.

## Hypotheses ruled OUT

1. **LIO target loses CAW writes silently** (sess23 hypothesis #1) — FALSE.
   `tools/caw_verify.c` (added sess24, built standalone with gcc) tested:
   - T1 CAW write 0xAA, T2 FUA-read → 0xAA ✓ 
   - T2 CAW write 0x55, T1 FUA-read → 0x55 ✓
   Cross-initiator CAW + FUA reads work correctly on this LIO target.

2. **xfs_buf_stale on BLI** (sess22 hypothesis) — sess23 P32-INSTR ruled out.
   The stale events fire AFTER corruption (downstream effects of shutdown).

## Failed sess24 fix attempts (all reverted)

- **P34-INSTR**: post-CAS FUA-read verify in `caw_slot`.  Mount-time false
  positives (pre-mkfs garbage content); during stress, only one benign
  release-vs-promote race captured per node.  Not the actual bug signal.

- **UDP BAST on claim-empty**: send `caw_send_bast_mcast` after successful
  `claim-empty` for AG/INODE resources.  Goal: notify peer that resource
  was taken (find=rc-2 → claim-empty doesn't go through register-waiter
  path that normally sends UDP BAST).  Result: stress run-4 failed iter 3
  vs run-3 iter 9 baseline — strictly worse.  Reverted.

- **Disable cached fast-path entirely**: bypass `if (pag->pag_dlm_cached)`
  in `mxfs_ag_dlm_lock` (both before+after `pag_dlm_acquire_lock`).
  Force every acquire through slow-path CAW READ.  Result: inode-DLM
  wedged in DEMOTING state on T1; T2 root-dir lock timeout at iter 1.
  Inconclusive about the AG bug.  Reverted (T1 needed reboot).

- **bast_poll self-correction**: when a held slot shows `our_mode=NL`,
  fire `bast_cb` to clear local cached state.  Result: failed iter 1
  with **Mode A** (`xfs_trans_cancel` + `xfs_dir_removename rc=-ENOENT`)
  — the dir-coherence bug from sess20.  CRITICAL FINDING: Mode A and
  bnobt LEFT/RIGHT-FAIL share a root cause (silent cached divergence),
  and any cache-invalidation fix triggers Mode A immediately because
  the upper-layer drain/release path has correctness issues.

## Open hypotheses

1. **bast_poll_fn doesn't detect "we lost the grant"**: when slot in our
   held list shows our_mode=NL on disk (peer took over), bast_poll just
   `continue;` — no signal to clear local cached state.  The check at
   `dlm_caw.c:1898` could fire bast_cb instead of skipping.

2. **bast_work_fn flush race**: between the Phase-1 flush and Phase-2
   caw_unlock, a fast-path acquire might slip through the gap (re-bumping
   holders → cached=false, then unlock → cached=true).  bast_work_fn's
   re-check at line 1812 would see holders=0+cached=true and proceed.

3. **AIL push doesn't actually drive bnobt updates to disk**:
   `xfs_ail_push_all_sync` returns when AIL items are submitted but not
   necessarily I/O-completed.  T1's read after T2's release might predate
   T2's bnobt write completion despite the flush sequence.

## Suggested next investigation

The shared-root-cause discovery (Mode A + bnobt LEFT/RIGHT-FAIL = silent
cache divergence) means the fix has to handle BOTH or neither:

1. **Audit upper-layer drain correctness**: when `mxfs_dlm_ag_bast_work_fn`
   sets `cached=false` (line 1823 of `xfs_mxfs_dlm.c`), in-flight
   transactions/dir-ops/inode-ops with stale cache references may corrupt.
   Trans-aware drain might be needed before invalidating cache.

2. **Lease-based cached-AG**: per-resource expiring lease in cached state.
   Avoids "premature invalidation triggers Mode A" because cache expiry
   happens at quiescent points (no in-flight ops).

3. **Fix Mode A FIRST, then bnobt**: sess20-22 spent extensive effort on
   Mode A but it's still surfacing.  Sess24's self-correct attempt
   confirms cache-invalidation drives Mode A.  A correct invalidation
   path that doesn't break Mode A would also enable the bnobt fix.

## Files

- In tree: `xfs/libxfs/xfs_alloc.c` — P33-INSTR alloc-bnobt-snap +
  fail-bnobt-snap dumps.  Keep until bug closed.
- New tool: `tools/caw_verify.c` — built standalone (`gcc -o caw_verify
  caw_verify.c`).  Not added to tools/Makefile per CLAUDE.md rule.
- srcversion at sess24 end: `9A023439F613AE4B6120C26` (v0.3.83 + P33).
- Comprehensive analysis: `/tmp/sess24-analysis.md`.
- Stress logs: `/tmp/sess24_run{1..5}.log` and `/tmp/sess24_t{1,2}_run{2,3,4}.log`.
