---
name: sess10run-DISCRIMINATOR-clobber-stale_base0-invisible-to-gen
description: sess10(ccloop) discriminator: 4/tcp dir_reuse clobber fires stale_base=1 ZERO times — staleness invisible to in-core dir_gen/loaded_gen; write-side g…
metadata:
  type: project
---

## sess10 (ccloop 4cb2d0a2) — DECISIVE discriminator (build DE3A7E21, fresh dirwr=2 trace)

Reproduced 4/tcp dir_reuse FAIL 0/4. Losses are EARLY (rounds 2,8,9 — NOT accumulation): lost node2_f16.md5, node4_f10.md5, node1_f9 (sidecars + a data file). All durable (survive drop_caches).

### KEY FINDING
Grepped ALL 4 nodes' dirwr=2 streams for `stale_base=1`: **ZERO occurrences.** Every dir-EX RMW reports stale_base=0 (i.e. i_dlm_dir_gen <= i_dlm_dir_loaded_gen — the node believes its base is current). Yet a durable entry is lost.

### Implication (rules out a whole class of fixes)
The clobbering write is INVISIBLE to the in-core gen detector. The block's in-core gen was stamped FRESH (loaded_gen advanced to dir_gen) while the content was actually STALE (missing a peer's committed entry). So:
- NO write-side gate keyed on dir_gen/loaded_gen/epoch-vs-valid_epoch can catch it (they all read "fresh") — this is why dir_epoch_adopt, the P63 handoff fast-path check, dir_modify_extent_adopt, etc. all FAIL: they fire on gen/epoch advance, but at the clobber the gen says fresh.
- The bug is UPSTREAM: a refresh/re-read STAMPED a stale image as fresh (loaded_gen=dir_gen) — most likely the node re-read the block (consumer_refresh / slow-path reload / xfs_da_read_buf) at a moment the peer's durable write was NOT yet visible to that read, then marked it current. Confirms sess69's read-side-poisoning root on the current build.

### Where the fix must act (next session)
NOT a gen/epoch gate at the write. Instead, ensure the re-read that stamps loaded_gen reads the AUTHORITATIVE current content:
1. Find every site that sets `i_dlm_dir_loaded_gen = i_dlm_dir_gen` (or evicted_gen) and audit whether the preceding re-read was guaranteed-coherent (FUA / post-peer-durable). grep `i_dlm_dir_loaded_gen =` and `b_mxfs_dir_gen =` in xfs_mxfs_dlm.c + xfs_da_btree.c. If a re-read can return a pre-peer-durable image yet still stamp fresh, that's the bug.
2. Tie loaded_gen advancement to a coherent read: only stamp loaded_gen=dir_gen AFTER a FUA/uncached re-read under EX/PR (peer's release+drain, Invariant 1, guarantees durability once we hold the grant the peer gave up).
3. Verify the RE-READ content: after reload/refresh of a contended dir, the read should reflect the epoch the grant carries. If a read returns content older than the grant epoch implies, it's a durability/visibility race (peer's write in-flight to SCST) — needs a read barrier or retry.

### Repro/trace
`MXFS_EXTRA_MODARGS='dirwr=2' MXFS_TEST_ENV='DRC_ROUNDS=20 DRC_STREAM=1' ./run.sh 4 tcp dir_reuse_coherency` (~5min, reproducible). Streams: /root/drc_stream_rank<R>.log on each node; lost name in `mxfs-drc-RDMISS round=N`; per-round create snapshot /root/drc_create_r<N>_rank<R>.dmesg. Probes: P-DIRWR/P-DIRRD (content crc), P16-DIRBLK-SUBMIT (daddr,dgen,lgen,bgen), P-DIRFASTEX/P-SFDIR-STALE-RMW/P-TDS-RMW (stale_base). To find the clobber: pick a round from RDMISS, find the daddr holding the lost name, merge P-DIRWR by realns across nodes, find the write that wrote that daddr with a count missing the lost name.

See [[sess10run-NEXT-real-fix-direction-concurrent-rmw-stale-base]] [[sess69-DECISIVE-loss-invisible-to-detectors-double-grant-remaster]] [[sess69-TRUE-ROOT-crossnode-stale-readcache-hit-poisons-rmw-base]].</body>
