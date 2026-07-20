---
name: sess-tcp-DLM-double-grant-FIXED-gen-token
description: FIX (build 404BC55C): TCP DLM double-grant FIXED via grant-generation token (re-affirm not remove+promote; gen-checked release; client rejects unsoli…
metadata:
  type: project
---

## FIX (build `404BC55CA1AF4A73317C3DA`, KEEP) — the proven TCP DLM double-grant
([[sess-tcp-tcp-dlm-scaling-DOUBLE-GRANT-proven]]). Implemented the grant-generation protocol.

### Wire/struct changes:
- `mxfs_dlm_lock_resp` += `uint32_t grant_gen`; `mxfs_dlm_lock_release` += `uint32_t grant_gen`
  (+pad). (include/mxfs/mxfs_dlm.h). 8192B peer buffer; CAW unaffected (doesn't use these structs).
- `struct mxfs_lock` += `uint32_t grant_gen`; `mxfs_dlm_ctx` += `uint32_t grant_gen_next`
  (init 1). `dlm_next_gen(ctx)` monotonic, never 0, under table_rwlock. (dlm/dlm.h, dlm.c)
- process_remote_grant/release signatures += grant_gen; both dispatchers (v5_mount.c, mount.c)
  extract resp->grant_gen / rel->grant_gen.

### Protocol (dlm/dlm.c):
1. Every GRANTED transition stamps entry->grant_gen=dlm_next_gen (promote_waiters, immediate
   grant, re-affirm, conversion). GRANT echoes it.
2. **process_remote_request, sender already GRANTED, mode>=req: ALWAYS RE-AFFIRM** — keep entry,
   bump gen, re-send grant, NEVER remove+promote a waiter. (Deleted the Bug-51 still_safe block
   AND the stale-removal+promote branch = the proven double-grant site.)
3. **process_remote_release**: ignore a STALE release (grant_gen != entry->grant_gen, both nonzero)
   — the holder re-acquired since; keeps Bug-51 fixed without remove+promote. gen==0 → old
   unconditional remove (liveness fallback).
4. **process_remote_grant (client)**: pending_signal_resource now returns matched; UPDATE existing
   mirror in place (no dup); if !mirror && !matched → UNSOLICITED grant (re-affirm arrived after we
   released) → REJECT: send gen-stamped RELEASE so master drops the phantom + promotes the real
   waiter (prevents phantom-EX hang).
5. mxfs_dlm_unlock echoes the mirror's grant_gen in its RELEASE.

### VALIDATION:
- Full `./run.sh 2 tcp`: **tcp_dlm_scaling PASS 2/2** (was ~50% flaky double-grant). 15/16 overall.
- NO regression: only other fail was dlm_fairness 1/2 — which passes **4/4 STANDALONE** on this
  build (flaky cumulative, not caused by the fix). crash_consistency + cache_coherency + posix_multi
  + all DLM tests PASS.

### REMAINING for 16/16: intermittent DIR-COHERENCY flakiness in the cumulative full suite —
cache_coherency (cross_visibility: node sees peer file missing) and dlm_fairness (`shared dir
drained exp=0 got=1`). Both pass standalone, flake in-suite. Same family: peer's dir-entry
mods not promptly visible WITHOUT drop_caches → consumer_refresh relies on i_dlm_dir_gen advancing
via the DIR_MODIFY eviction-ring notification (suspect unreliable on TCP). Investigate next.
Fallbacks: 404BC55C (this), 1ED7A5FD (cc-fix only), 30D3C28E (pre-both).
