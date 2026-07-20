---
name: sess16run-RESOLVED-f1-written-then-clobbered-on-hot-block0
description: sess16(ccloop) RESOLVED the determinism: node1_f1 is WRITTEN durably 286x by owner (+other nodes) then CLOBBERED — not never-written, not a conversio…
metadata:
  type: project
---

## sess16 (ccloop) — determinism RESOLVED: hot-block0 cross-tenure clobber

dirwr=2 trace, grep durable writes (P-RELFLUSH/P11-FLUSH/P-DIRWR) whose block names include "node1_f1":
- test1 (owner/rank1): 286 writes WITH node1_f1. test3:129, test4:81, test8:43, test7:26, test6:9. test2/test5 (the verifying peers that report it MISSING): 0 (they don't write it — they're readers).
→ node1_f1 is durably WRITTEN MANY TIMES across nodes, then CLOBBERED. NOT never-written; NOT a structural format-transition drop (the sess16run-...-DETERMINISTIC conversion hypothesis is REFUTED — supersedes it).

### Why ALWAYS node1_f1 (+node5_f40) — determinism explained
node1_f1 is rank1's FIRST-created file → it lives in the dir's FIRST data block (block0, daddr=120). block0 is the HOTTEST block: every node's early creates RMW it, and it's the block with the proven count=126→77 cross-tenure lost-update regression ([[sess16run-BREAKTHROUGH-dir-EX-handoff-midtransaction-lostupdate]]). So the earliest entries are deterministically the victims of the block0 clobber. Not a special-case bug — just the most-contended block. (node5_f40 similar — an early-ish entry in a hot low block.)

### Unified root (high confidence, multiple independent confirmations)
Cross-node cross-tenure RMW lost-update on the hot shared dir block0: a node RMWs block0 from a stale base (missing peers' entries incl f1) and durably writes it back, dropping them. Frequency-dependent on mht (mht=300 PASS, mht=50 FAIL) because fewer handoffs = the hot block stays coherent within a tenure.

### REFUTED fixes (do NOT retry — all FAIL at mht=50)
force_coherent=1; dir_postread_reread=1; b_mxfs_dir_epoch read-trigger (build 42178C17); dir_release_fua_write=1. → loss is NEITHER read-cache-staleness NOR write-durability. The stale base is a node's OWN cached block0 buffer preserved across a handoff by the anti-resurrection keep-guard; re-reading at use doesn't fire / doesn't help.

### THE FIX (next session — committed direction)
GPT-5.5 design parts 1+2 [[sess16run-GPT-design-tenure-scoped-dirbuf-coherency-FIX]]: invalidate the dir's cached data/leaf buffers at the RELEASE/handoff point (after Invariant-1 drain, under a REVOKING writer-fence that blocks new local dir ops until active txns finish + drain + invalidate + drop-grant), so the next acquirer is FORCED to re-read the peer's durable image. The REVOKING fence is the piece sess96's naive force-evict-on-release lacked (closes the redirty-after-drain window). Read-side enforcement is the BACKSTOP, not primary. Validate: P-DIRWR daddr=120 count must be monotonic (no 126→77), dir_reuse 8/tcp PASS at mht=50, tcp_dlm ≤60s, then 17/17, then 1/2/4. Canaries unlink/rename_visibility/crash_consistency must stay PASS (resurrection guard).</body>
