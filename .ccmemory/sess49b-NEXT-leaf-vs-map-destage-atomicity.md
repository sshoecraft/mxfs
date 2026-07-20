---
name: sess49b-NEXT-leaf-vs-map-destage-atomicity
description: sess49b NEXT: 8/tcp torn-disk = STALE LEAF flushed UNDER EX (ex_write_guard already ON, only skips non-EX). Fix = force-invalidate all dir leaf/data…
metadata:
  type: project
---

## sess49b — DECISIVE narrowing of the 8/tcp DISK-TORN fix (read FIRST next session)

### Mechanism (fully narrowed this session)
On-disk dir (ino 131) is torn: the LEAF block references data blocks the dinode extent map lacks (FUA-proven, DISK_MAPS_WANT=0). The stale LEAF home-write comes from a node that **holds EX** but whose **cached leaf is STALE** (from before a peer's middle-block-free removal) and was NOT re-read on acquire, then flushed it over the peer's durable leaf.

### Why the existing guards do NOT catch it (ruled out this session)
- `mxfs_dir_ex_write_guard` is **already DEFAULT 1 (ON)** (xfs_mxfs_dlm.c:20001). It skips a dir DATA/LEAF buffer destage ONLY when `dir_not_held_ex` (`!in_core || mode != EX`). The torn flush happens while the node **DOES hold EX** (mode==EX), so the guard passes it through. Enabling more of these per-buffer guards is NOT the fix.
- The read-time leaf invalidation (xfs_da_btree.c xfs_da_read_buf: re-fetch a cached dir block when `b_mxfs_dir_gen < i_dlm_dir_gen`) is the mechanism that SHOULD refresh the stale leaf on acquire — but it's gated on `i_dlm_dir_gen`, which on TCP is bumped only by the LOSSY async heartbeat evict-ring + slow-path reacquire. A fast-pathed EX re-acquire (cached grant) misses the bump → leaf stays stale → flushed under EX. This is the same lossy-gen coupling that's bitten dir coherency for ~130 sessions.

### THE FIX TO IMPLEMENT (GPT consult #3, [[sess47-GPT-consult-leaf-coherence-invariant-and-design]])
On EX ACQUIRE of a multi-node dir that has seen peer activity (post_release / handoff / dir_gen>0), **force-invalidate ALL cached dir LEAF/NODE/data buffers** (not gated on the lossy gen) so they are cold-re-read from the durable platter before the tenure modifies/flushes them. The mechanism already exists: `mxfs_dir_evict_owned_dir_blocks(ip)` (P68 owner-evict, map-independent, by header owner) — currently called only on a SHRINK/incarnation-change reload (P68-PREEVICT). Extend its trigger to EVERY genuine cross-node EX acquire of a dir (the reliable `genuine_handoff` / grant-handoff signal, NOT the lossy dir_gen). Cost: re-read dir blocks once per real handoff (acceptable; RULE-0 only if it fires on solo/unchanged dirs — gate on grant-handoff so it doesn't).
- PAIR with the KEPT torn-disk reload gate (build A9180EB2) which already stops adopting an already-torn disk. Together: gate stops propagation INTO in-core; acquire-evict stops a stale leaf from being flushed OUT.
- After implementing, run `tests/tcp/drc_reliab_iter.sh 8` ≥5× clean-reboot; need ALL pass for the criterion. Then re-confirm 2/tcp + 4/tcp didn't regress (full `run.sh {2,4} tcp`).

### Status: build A9180EB2 (torn-disk reload gate, partial, ~1/3 pass, oops+cascade eliminated). 2/4 PASS, 8 FAIL. Marker NOT written.
See [[sess49b-BREAKTHROUGH-torn-disk-reload-gate-partial-8tcp]] [[sess49-8tcp-root-is-durable-dir-delalloc-extent-tear]].
</body>
