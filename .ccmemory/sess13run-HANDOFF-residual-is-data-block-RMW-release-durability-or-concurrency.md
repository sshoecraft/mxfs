---
name: sess13run-HANDOFF-residual-is-data-block-RMW-release-durability-or-concurrency
description: sess13(ccloop) HANDOFF: dir_reuse 4/tcp residual 1/400 is a DATA-block double-alloc (ENOENT, not leaf-hole). dir_force_evict=1 already evicts clean b…
metadata:
  type: project
---

## sess13 (ccloop 4cb2d0a2) HANDOFF — dir_reuse 4/tcp at 399/400, residual fully localized

### STATE: criterion NOT met. Best result = 399/400 (was 0/400).
WINNING CONFIG (PROVEN this session): `MXFS_EXTRA_MODARGS="fua_disable=0 fua_always=1 dir_epoch_adopt=1 dir_epoch_convert_gate=1"` on `./run.sh 4 tcp dir_reuse_coherency` → 399/400 all nodes, ZERO shutdowns (DABUF_MAP_HOLE eliminated). Both levers required (fua alone=306, epoch alone=sess10-refuted). See [[sess13run-WINNING-CONFIG-fua-plus-epoch-adopt-399of400]] [[sess13run-BREAKTHROUGH-FUA-removes-corruption-readdir-divergence-remains]].

### RESIDUAL precisely characterized
- 1 durable lost dirent / 400 / run, ALWAYS the 2nd-wave (.md5 sidecar / later file). `LOOKUP_ENOENT REREAD_MISS` on ALL 4 nodes = DURABLE DATA-block loss (bytes overwritten), NOT a leaf-hash hole (so dir_leaf_rebuild won't recover it). = sess11run PROVEN dir-DATA-block FREE-SLOT DOUBLE-ALLOCATION: two nodes place different dirents at same (daddr,off); LATER writer's in-core reverts to disk → its entry lost.
- REFUTED this session: MHT=0 (worse, 318/400 — MHT batching HELPS); LIO-read-cache-as-sole-root (FUA fixes corruption not the residual); dir_force_evict already=1 (evicts clean blocks unconditionally, only skips dirty/pinned/undestaged = own in-flight).
- So with coherent reads (FUA) + reliable handoff adopt (epoch) + unconditional clean-block evict, the residual MUST be: (a) a RELEASE-side durability hole — node A released EX with its specific dir-DATA-block add still dirty/not-yet-destaged, so the evict on B skipped it as "undurable" and disk was NOT a superset (Invariant #1 gap for ONE block under the 2nd-wave burst); OR (b) a residual same-block concurrent RMW. Directionality (later writer reverts to disk) fits (a): A's add not durable when B reads/places.

### GPT-5.5 DESIGN (full in this session's transcript; key points)
1. NEVER in-place adopt on the same-tenure/FASTEX path if any dir buffer is dirty/pinned/joined (caused prior dabuf-HOLE/bnobt shutdowns). Post-release adopt stays.
2. CORE FIX (#D): make xfs_dir2 addname's free-slot search coherency-safe — before placing a dirent, revalidate the EXACT target data block (and leaf/free-index) against the LUN: if clean-stale → invalidate + scoped-FUA reread + recompute bestfree; if DIRTY-stale → protocol violation (shutdown, don't blind-merge). Stamp buffers with di_gen incarnation (dir 131 reused every round).
3. SCOPED FUA (replace fua_always, RULE-0 perf): add XBF_MXFS_COHERENT_READ flag in the dir metadata read wrappers (xfs_dir3_data_read/leaf_read/free_read, xfs_da_read_buf); decision driven by DLM dir epoch (grant_epoch > buffer/base epoch). Block/SCSI layer just honors the flag → REQ_FUA. Must ALSO invalidate stale clean in-core xfs_bufs (FUA only pierces LIO cache, not the local buffer cache).
4. BAST = hard local admission fence: on incoming BAST, stop admitting new FASTEX ops immediately, drain, release.

### NEXT SESSION CONCRETE PLAN
A. First re-confirm winning config 399/400 (reset virsh, run with the MXFS_EXTRA_MODARGS above; tool timeout ≥480000ms). 
B. Implement GPT #3 scoped-FUA so fua_always can be dropped (perf), verify still 399.
C. Implement GPT #D placement-time target-data-block revalidation OR audit the release-drain for the 2nd-wave block durability hole (instrument: at bast_process release drain ~xfs_mxfs_dlm.c:6164, log per-dir-DATA-block dirty/pin/destaged state for the storm dir; find the ONE block released not-yet-durable). 
D. Once dir_reuse=400/400 ×3 clean, set source DEFAULTS (dir_epoch_adopt=1, dir_epoch_convert_gate=1, scoped-FUA on) — prep_node.sh does NOT pass params, so defaults must change for the criterion harness. Then FULL `./run.sh 2 tcp` ×3 (no regression, watch dlm_fairness starvation/perf RULE-0), then 1/4/8.
E. 8/tcp has NEVER been run (criteria.json 0/0) — must validate after 4/tcp.

### Other 4/tcp fails (from last full run, likely contamination after dir_reuse/fence shutdown): fence_during_write & fault_netpartition ("node still writable" — possibly real fencing bug at 4-node, verify standalone), tcp_dlm_scaling (got=0 = cascade), soak (setup mkdir = cascade). Re-verify each STANDALONE once dir_reuse is fixed.
Cluster: test1-8 virsh -c qemu:///system. Build 40AC2A0C. See [[sess13run-MHT0-refuted-residual-is-cached-clean-stale-buffer-evictskip]].</body>
</invoke>
