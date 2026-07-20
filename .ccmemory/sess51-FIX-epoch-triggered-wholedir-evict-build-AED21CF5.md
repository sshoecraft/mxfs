---
name: sess51-FIX-epoch-triggered-wholedir-evict-build-AED21CF5
description: sess51(ccloop) BOTH fixes REVERTED (tree back to baseline C69E3475). grant_gen=0 refuted; GPT epoch-triggered whole-dir evict REGRESSED to mass loss…
metadata:
  type: project
---

## sess51 (ccloop) — both fix attempts REVERTED; tree back to baseline C69E3475

### Attempt 1 (grant_gen=0, dlm.c:1346): REFUTED — single-dirent loss persisted identically. Reverted.

### Attempt 2 (GPT-5.5 design: epoch-triggered whole-dir clean-block evict in mxfs_dlm_dir_modify_refresh): REGRESSED HARD, reverted.
Wired `epoch_advanced = (mxfs_v5_dlm_inode_dir_epoch != i_dlm_dir_evict_mep)` into the gate so mxfs_dir_evict_data_blocks fires once per cross-node handoff. RESULT (build AED21CF5, 8/tcp): round7 readdir=722/800 (lost 78), round8/9 readdir=700/800 (lost 100) — MASS loss vs the single-dirent baseline.

### WHY it regressed (key new insight):
Under the storm the dir-EX handoffs happen on nearly every op, so the level-trigger fires constantly. Each fire evicts ALL clean cached dir blocks; the subsequent cold re-read fetches the on-disk image, which LACKS peers' committed-but-not-yet-durable entries (each node syncs only at END of its 50-file wave). The re-reading node then RMWs+writes back that SHORT image → durably clobbers many peers' entries. So "force the reader to re-read more" is the WRONG direction — it amplifies the loss.

### What this REVEALS (next lead): the loss is fundamentally a RELEASE-SIDE durability/ordering gap, not a reader-side staleness gap.
For a post-handoff cold read to LOSE a peer's entry, that entry must NOT be durable on the shared LUN at handoff time — i.e. the prior holder released EX (allowing the handoff) WITHOUT its dir-DATA block additions being durable (Invariant #1: drain-before-release MUST flush dir data to the LUN before the on-disk DLM unlock). The single-dirent baseline loss = the rare timing where one block's drain races a handoff; forcing eviction made the race constant → mass loss. 
⇒ NEXT SESSION: instrument/verify the RELEASE-side drain pipeline for dir DATA blocks (mxfs_dlm_bast_process drain phase: drain_meta_buffers/drain_alloc_buflist/drain_inode_buffers + blkdev_flush BEFORE mxfs_v5_dlm_ag_unlock — Architectural Invariant #1). Confirm whether a dir-EX release on the storm dir reliably flushes ALL just-added dir DATA blocks to the LUN (FUA/platter) BEFORE the master is told to release. If a release lets the master grant a peer while a just-added dirent block is still in-AIL/in-core (not durable), that is the root. Probe: at dir-EX release, log per-data-block durable-vs-incore count for ino 131; at the peer's first post-handoff read, log the cold-read count. A gap = the Inv-1 hole.

### Alternative still-open: GPT mechanism (d) local quiesce race — a local create admitted to the fast path BEFORE a BAST keeps running AFTER mode=NL/release. GPT's full design (quiesce: state=REVOKING, wait active_users==0, then drain+release) would close it. See [[sess51-PROVEN-loss-is-count-preserving-divergent-RMW-phantom-cached-ex]] for the proven mechanism and the full GPT design.

### STATE: tree = baseline C69E3475 (both edits reverted, module byte-identical). Cluster nodes may be wedged from the killed repro7 (build AED21CF5) — next session must reboot+reprep (which reloads C69E3475 via NFS). Marker NOT written. dirwr content-fingerprint method (MXFS_EXTRA_MODARGS=dirwr=1 + DRC_STREAM=1, analyze /src/mxfs/tests/tcp/drc_cap/stream_rank*.log) is the decisive tool — reuse it.
