---
name: sess69-REFUTATIONS-and-gpt-design-dirreuse-4tcp
description: sess69 REFUTATIONS (direct stream evidence) + GPT-5.5 design for 4/tcp dir_reuse single-dirent loss. All coherency mechanisms report SUCCESS yet a di…
metadata:
  type: project
---

## sess69 — what's REFUTED (direct kernel-log-stream evidence) for the 4/tcp single-dirent durable loss

Repro: `MXFS_TEST_ENV='DRC_ROUNDS=20 DRC_STREAM=1' ./run.sh 4 tcp dir_reuse_coherency` (build A81DB821). Fails ~round 16-19, readdir=399/400, ONE dirent durably gone (LOOKUP_ENOENT+REREAD_MISS on ALL nodes incl creator). Lost entries seen: node3_f23 (kept its .md5), node3_f2.md5 — always a node3 entry (2 samples; may be coincidence). dir ino reused each round (131/132).

The streamed run (full kernel log to /root/drc_stream_rankN.log, beats ring rotation) REFUTES, with counts for the FAILING dir ino:
- **Phantom-EX (local mirror): REFUTED** — `P106-STALE-EX = 0` all nodes (every dir-EX fast-path serve DID hold the grant in its local mirror). CAVEAT: P106 checks only OUR `mxfs_v5_dlm_inode_held(dlm,ino)!=0`, NOT global exclusivity — so a true cross-node DOUBLE-GRANT (both nodes hold EX in their own mirrors) would NOT trip P106. Double-grant is NOT fully refuted; needs cross-node same-wall-clock EX correlation.
- **Reacquire reload SKIPPED (P116-RELOAD-SELFCLOBBER-SKIP): REFUTED** for the dir — `P116 ino=131 = 0`. The dir reload is not skipped.
- **Reacquire evict misses/keeps a stale block: REFUTED** — `P-DE-BLK disp=SKIP ino=131 = 0` all nodes; every block the reacquire `mxfs_dir_drain_evict_data_blocks` visits is EVICTED (DONE cleared). `P-DE-ENTER nd` reaches 4 (data + leaf all covered). So on reacquire the base IS fully invalidated → next read cold-fetches.
- **Release not durable: REFUTED** — `P-SF-DURABLE-FAIL = 0`, `P97-RELFENCE-WEDGE = 0`. The sess97 release fence always xfs_bwrite's dir blocks durable before handoff.
- **Extent-map divergence at modify: REFUTED earlier** (sess68 MAPDIVERGE=0).
- Handoff-refresh UNDER-fires (BAST 155-218/node vs slow P63-HANDOFF ~50 + fast P63-FASTEX-HANDOFF 0-1) — but per above the reacquire path that DOES run is complete, so under-fire of the fast handoff signal may be moot if every real handoff goes slow-path (which fully evicts).

### The paradox
Every coherency mechanism reports SUCCESS (reacquire fully invalidates; release fully durable; reload runs; local-mirror EX held) yet a single dirent is durably lost from a DATA block (readdir miss, not leaf-hash hole). Remaining live hypotheses:
1. **daddr aliasing during concurrent GROW**: node3 writes the entry to daddr D; a peer's reloaded extent map maps the same logical offset to a DIFFERENT daddr D' → peer RMWs D', orphaning D (and the entry). Needs a probe logging (logical-offset→daddr) for the dir at BOTH the creating commit and the clobbering RMW.
2. **true cross-node double-grant** via optimistic handoff (dg_grant_ex/handoff token) — the master's request path queues on incompatible (dlm.c:1252) so a FRESH EX request can't double-grant, but verify the CONVERT/handoff path doesn't. Needs cross-node EX-hold time correlation.
3. **write-side**: peer reads block WITH the entry (cold) but the XFS dir RMW picks an insertion offset from a stale free-index and overwrites the entry's slot. (evict covers the free block, so less likely.)

### NEXT decisive instrument (next session)
Add an always-on probe (gated to the test dir, low volume) at the dir DATA-block WRITE/destage (xfs_dir2_data.c or the buf write) logging daddr + entry-count + presence of a canary name, AND at the create that adds the entry: log (ino, logical-offset, daddr, name). Correlate across node streams to catch the exact moment the entry's block is overwritten and by which node, and whether the daddr matches. This pins hypothesis 1 vs 3.

### GPT-5.5 design (consulted RULE 5; full answer worth re-reading)
Tie dir-cache validity to LOSS OF WRITER-EXCLUSION (EX *or* PR → NL), a LOCAL reliable signal — not the lossy DIR_MODIFY eviction-ring and not raw grant_gen (over-fires on same-node PR→EX upgrades). On dropping below writer-exclusion: flush+log-force+drain THEN invalidate local dir buffers; on reacquire from NL: reload before RMW; never fast-path RMW while ACQUIRING/REVOKING/RELEASING or reload_needed. Treat dirty/pinned/in-AIL dir buffers found AFTER release+reacquire as a BUG/waitable protocol violation, NOT a skip reason (add a hard assert to catch it). For precise no-over-fire cross-node detection use a DLM LVB `dir_change_seq` carried in the grant response (master-authoritative), not async messages. This is the GFS2/OCFS2 model. NOTE: my stream evidence shows the reacquire path ALREADY fully invalidates (P-DE-BLK SKIP=0), so the GFS2 fix may already be effectively in place on the SLOW path — implying the loss is NOT a stale-reacquire-base but hypothesis 1/2 above.

Tooling added (KEEP): tests/suite/dir_reuse_coherency.sh has persistent /root/drc_failrounds.txt + DRC_STREAM=1 kernel-log streaming. See [[sess69-PROVEN-4tcp-dirreuse-two-failures-handoff-underfires]].</body>
