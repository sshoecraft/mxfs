---
name: sess69-TRUE-ROOT-crossnode-stale-readcache-hit-poisons-rmw-base
description: sess69 TRUE ROOT (proven): 4/tcp dir_reuse loss = cross-node STALE READ-CACHE HIT. A peer advances a dir block; this node's non-FUA read hits its sta…
metadata:
  type: project
---

## sess69 TRUE ROOT (proven by RD/WR content-lineage trace, dirwr=2)

Reconstructed the full read/write content timeline of dir block 0 (daddr=120) by merging always-on `P-DIRRD` (read crc+fua) and `P-DIRWR` (write crc+count) across all 4 nodes by realns, mapping read crcs to known write entry-counts.

**18 STALE READS detected on daddr=120, and ALL 18 are: `fua=0` (non-FUA) AND cross-node (the reader is NOT the node that wrote the latest version).** A read returned content with FEWER entries (e.g. 70) than a strictly-earlier write by a PEER (e.g. 81).

### The fully-connected mechanism (every link evidenced this session)
1. A PEER acquires dir EX and durably advances dir block 0 (daddr=120) to N entries on the shared target.
2. THIS node has daddr=120 cached locally as a STALE XBF_DONE buffer (N-k entries). The local-cache invalidation that should drop it on a peer modify is driven by the **LOSSY async DIR_MODIFY eviction-ring** (mxfs_dlm_note_evicted → i_dlm_dir_gen/MXFS_IF_DIR_RELOAD), which DROPS messages on TCP → the buffer is never invalidated.
3. This node does a non-FUA READ (comm=bash: md5sum/ls, or a create's read) → **CACHE HIT on the stale buffer** (returns N-k). FUA is irrelevant: a cache hit never issues a disk read, so fua_disable / FUA-passthrough cannot fix it — the buffer must be INVALIDATED to force a miss.
4. The stale read re-validates the buffer XBF_DONE, **poisoning the base**. A subsequent fast-path (cached-EX, no reacquire-evict) create RMW reads this poisoned buffer, adds its entry, and durably writes back — DROPPING the peer's entries. = the readdir=399/400 single/multi-dirent durable loss seen on ALL nodes.

This unifies every prior sess69 finding: the clobbering WRITE looks legit (real_mode=EX, stale_base=0, clean buffer — indistinguishable from rm) BECAUSE the staleness was injected on the READ side earlier and the write is just flushing the poisoned base. P-TDS-RMW stale_base=0 because the lossy dir_gen signal never fired. The reacquire-evict (P-DE-BLK SKIP=0) IS complete — but these poisoning reads happen on paths that DON'T reacquire-evict (consumer_refresh fast-path / fast-path create), relying on the lossy ring.

### THE FIX (next session — concrete, high-confidence)
Make cross-node dir-buffer invalidation RELIABLE instead of depending on the lossy eviction-ring. Options (prefer 1):
1. **GPT-5.5 loss-of-writer-exclusion (local, reliable)**: when THIS node drops the dir below writer-exclusion (EX/PR → NL, i.e. a peer is taking it), INVALIDATE all cached dir DATA/leaf buffers for that inode immediately (clear XBF_DONE) — locally driven, cannot be lost on TCP. Then any later read (fast-path or consumer) MISSES cache and re-fetches the peer's durable image. Per Invariant 1 our work was drained at release, so no resurrection. This is the GFS2 "invalidate on demote" pattern. Wire it at the dir EX/PR→NL release/BAST path (xfs_mxfs_dlm.c release sites + bast_process), not the lossy mxfs_dlm_note_evicted ring.
2. Reliable LVB-carried dir_change_seq in the DLM grant (master-authoritative) consulted on the read/fast-path to force re-read.

VALIDATE: dirwr=2 RD/WR trace should show ZERO stale cross-node reads on daddr=120 after the fix; then 4/tcp dir_reuse PASS; then full 2/tcp 17/17 ×3 (no resurrection regress in unlink_visibility/rename_visibility) + 1/4/8.

### Tooling
Decisive repro+trace: `MXFS_EXTRA_MODARGS='dirwr=2' MXFS_TEST_ENV='DRC_ROUNDS=20 DRC_STREAM=1' ./run.sh 4 tcp dir_reuse_coherency`, then merge P-DIRRD/P-DIRWR for the failing dir's block daddr by realns and map read-crc→write-count (python in scratchpad/rdwr analysis). dirwr=2 enables both probes (dirwr=1 only enables P-DIRWR; P-DIRRD needs >=2).

### Caution
test2 AND test3 each wedged a D-state kworker (mxfs-ino-bast / flush-8:0) mid-session and needed `virsh -c qemu:///system destroy/start`. A node holding the LUN (mxfs loaded) breaks NODE1's mkfs ('zero_region verify FAIL') — ensure ALL nodes rmmod before prep.

Build DE3A7E21 (baseline + dirwr-gated probes; inert at production). Marker NOT written — criterion NOT met. This SUPERSEDES the write-side-dead-end conclusion: the write is downstream; the root is the read-side stale cross-node cache hit. See [[sess69-CONCLUSIVE-no-writeside-fix-buffer-content-reverted]], [[sess61-THE-FIX-implement-sess10-grant-gen-faststale-check]].</body>
