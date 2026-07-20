---
name: sess117_lessons
description: sess117 — bnobt double-free FS-shutdown FIXED (Gemini root: in-AIL AG-meta outlives its disk write; AIL removal is checkpoint-driven). Lost-update co…
metadata:
  type: project
---

# sess117 (ccloop run 4eef1f39)

## WINS (verified)
1. **bnobt double-free FS-shutdown FIXED** (`ltbno+ltlen>bno` xfs_alloc.c:2244 →
   xfs_free_ag_extent → FS shutdown). Build `3CBB2553` (deployed all 4 nodes): both
   runs since show `ltbno=0 shutdownFS=0 Corruption=0`. The catastrophic corruption
   that cascaded all 4 subtests to FAIL is gone; runs are now FAST (no 244s barrier
   timeouts).
2. **Gemini RULE-5 ROOT (the contradiction resolved):** an in-AIL AG-meta buffer is
   NOT always this-node-ahead. **AIL item removal is LOG-TAIL/checkpoint-driven, NOT
   buffer-writeback-driven.** So after a node drains+bwrites its bnobt at AG yield
   (content durable), the buffer stays `in_ail=1` until the next checkpoint. A peer
   then commits a newer alloc to disk; the read-hook sees in_ail=1 and PROTECTED the
   now-stale buffer; xfsaild re-flushes it over the peer's split → P93-REVERT-CLOBBER
   → double-free. PROVEN: every clobbering write is `in_ail=1 dirty=0 pin=0 delwri=0`,
   `buf_gen=0 < pag_gen=5`, `disk_nr > buf_nr`, comm=xfsaild.

## Fixes landed in 3CBB2553 (KEEP — builds clean, no corruption)
- P117-AGMETA-STALE-CLEAN: release-side stale of CLEAN bnobt/cntbt in
  mxfs_dlm_ag_drain_meta_buffers skip_no_li branch (closes sess110 clean-alias gap).
- P117-COLDREAD-DISCARD: gen-independent acquire-side discard of clean bnobt/cntbt on
  the FAST reclaim paths (pag_dlm_cached / release_pending) — `mxfs_ag_meta_coldread_discard`
  (xfs_mxfs_dlm.c). The slow fresh-CAW path already calls mxfs_dlm_invalidate_ag_meta.
- P117-INAIL-STALE-ARTIFACT: read-hook (mxfs_ag_meta_invalidate_stale) now DISCARDS a
  PREVIOUS-epoch (buf_gen<pag_gen) in-AIL-but-clean bnobt/cntbt log-tail artifact
  instead of protecting it. Gen-gated + scoped to free-space trees → preserves the
  sess103 AGI protection (that was a CURRENT-epoch buf_gen==pag_gen buffer).
  NOTE: fired 0× — xfsaild WRITES before any allocator READS, so the read-hook is the
  wrong place; the real fix must be at YIELD (evict) not READ. This is why it's flaky.

## STILL BROKEN: lost-update content-revert (FLAKY)
Run1 = 4/4 PASS (variance!), Run2 = 2/4 (unlink_visibility 31 misses + cross_write_read
1-2 misses, FAST, no corruption). P93 still fires 2-6×/run (latent stale-bnobt writes
that didn't manifest as corruption). The 4/4 was NOT real — do not trust a single PASS;
require 3 consecutive clean runs.

## USER DIRECTION (sess117) — APPROVED: HARD CACHE-BARRIER RE-ARCHITECTURE
Stop point-patching the lossy gen-counter caching scheme. Make every DLM yield/acquire a
HARD cache barrier for metadata buffers:
  YIELD(resource): xfs_log_force(SYNC) + drain(bwrite dirty) → then EVICT (xfs_buf_stale +
    clear DONE) ALL the resource's buffers — eviction ATOMIC with yield, AFTER write so
    nothing is lost. Then release DLM.
  ACQUIRE(resource): buffers gone → first access cold-reads the shared LUN.
=> no metadata buffer survives a tenure boundary; gen counters + read-hooks become
   unnecessary for correctness. Correctness-first; accept perf hit, optimize later.
KEY SAFETY INSIGHT: evict AFTER write at yield is safe even for AGI (sess103 trap was
evicting a this-node-ahead NOT-yet-written buffer at READ time — different point/time).

## NEXT SESSION — implement the re-arch, AG-meta first (incremental, test each step)
1. **YIELD evict-all:** in mxfs_dlm_ag_drain_meta_buffers, generalize BOTH stale sites
   (the drained-buffer stale ~L6960 `if bnobt||cntbt: xfs_buf_stale` AND the P117 clean
   stale ~L6812) from bnobt/cntbt-ONLY to ALL AG-meta types (agf/agfl/agi/bnobt/cntbt/
   inobt/finobt). After drain everything is durable → stale all → cold-read on acquire.
   This is the core change. Build, deploy (reset4 + virsh reboot if corrupt), run
   cache_coherency ×3 — require 3/3 clean + P93=0 + ltbno=0.
2. If AG-meta hard barrier holds, do the INODE-CLUSTER + DIR-BLOCK half (the remaining
   content-revert: sess61/85 cluster false-sharing, sess106 same-name-mkdir parent-dir).
   Same pattern at the inode-DLM yield/reload path.
3. deadlock watch: forced checkpoints/ail_push can deadlock cross-AG (sess18) — the
   existing drain is targeted per-AG for that reason; keep evict per-AG/per-resource.

## TIMING (user re-corrected — see [[timing-timeouts-must-match-test]])
Healthy cache_coherency = ~20-60s. DO NOT use a 700s ceiling (masks slowness=FAIL).
Run with ~120s cap; also tighten MXFS_BARRIER_TIMEOUT (tests/lib/cluster.sh L11, currently
120) so a stalled barrier FAILS fast instead of burning 120-244s.

## Infra
4 nodes test1-4 under virsh -c qemu:///system on this host (clyde). Clean reboot =
destroy+start. reset4.sh 4 = teardown+mkfs+mount. /src NFS auto-mounted by criteria lib.
cache_coherency unmounts nodes at end (DOWN after a run is normal, not a crash — check
ltbno/Corruption/"Shutting down filesystem", NOT loose "shutting down" which matches
normal "DLM shutting down"). See [[sess114_lessons]] [[sess110_lessons]].
