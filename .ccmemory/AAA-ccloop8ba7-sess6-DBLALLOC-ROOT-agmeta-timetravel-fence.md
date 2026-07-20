---
name: AAA-ccloop8ba7-sess6-DBLALLOC-ROOT-agmeta-timetravel-fence
description: sess6 pt2: DOUBLE-ALLOC ROOT FOUND (iter_10 red-handed: test28 re-alloc agno7/295 over live uv block, same tenure, no handoff) = AG-meta cold-read ti…
metadata:
  type: project
tags: [ccloop-8ba7ae5c, sess6, double-alloc, time-travel, P143]
---

# Double-alloc ROOT CAUSE + fence (sess6 pt2)

## Red-handed evidence (iter_10, logs in tests/logs/dblalloc_repro/iter_10/full_test*.log)
- 22:20:28 test28 allocates AG7/agbno295 as uv-dir (37748889) block bno=3. uv keeps it through final 5-extent map (shrink 11→5 freed OTHER blocks; 295 never freed; cc ends 22:21).
- 22:22:44 SAME node test28 allocates AG7/295 AGAIN for posix_multi — P-DBLALLOC fired with disk_owner=37748889 (live XDD3 uv block on disk). tenure=1 both times (no AG re-acquire). Also test29 AG22/297 + test31 AG10/295 same window, each over live uv blocks (disk_owner=37748889).
- No membership flap (peer-join flush only at mount 22:18:55). No AG handoffs. ALL handoff probes silent (P130/P131/P75/P125/PROBE-A/P88/P121) — by construction: no handoff involved.
- Live uv dir: `ls` returns EFSCORRUPTED (its block holds pm content). Static xref OVERLAP fsb 1835303 + foreign content fsb 5767465.

## Mechanism (GPT consult gpt-5.6-sol: 90%+; matches sess6-46efd8b6 PROVEN dir-leaf family)
Node allocates → bnobt/AGF updated, logged → AIL pushes buffer → write completes into LIO TARGET WRITE CACHE (not media; LIO drops FUA) → buffer clean → memory pressure evicts it → later allocation COLD-READS the daddr via FUA passthrough (bypasses target cache) → PRE-write media image → free-space state regresses → re-allocates owned blocks. Per-buffer b_mxfs_wr_flush_epoch guard dies with eviction — AG meta had no guard. CRC/verifiers can't catch (old image is internally valid).

## Fence (0.10.116 srcversion 28B78CA1) — flush-before-hazardous-cold-read (GPT's ranked-best bounded fix)
- xfs_ag.h: pag_mxfs_meta_wr_epoch (atomic64) — stamped with m_mxfs_flush_epoch at AG-meta WRITE COMPLETION (__xfs_buf_ioend, beside the per-buffer stamp), multi-node gated.
- pal/linux/xfs_buf.c mxfs_agmeta_ops(): AGF/AGI/AGFL/bnobt/cntbt/inobt/finobt (AGF included per GPT — stale root redirects traversal).
- xfs_buf_read_map cold-read (!DONE) branch: if pag wr_epoch >= m_mxfs_flush_epoch → P143-AGMETA-FLUSHREAD print (cap 60) + mxfs_release_coalesced_flush(mp) (now non-static; coalesced + epoch-advancing) BEFORE the read.
- xfs_buf_readahead_map: SKIP RA of hazardous AG-meta (RA would populate DONE with stale image, bypassing the fence).
- Correct-by-epoch-ordering: completion-stamp only (buffer locked during write flight → no concurrent cold read); coalesced flush advances epoch after blkdev_issue_flush → all stamps ≤ then become non-hazard.

## Session fix stack (all in 0.10.116): P133 raw-FUA cluster init (0.10.111), site-11 igrab guard (112), P142 ident guard + drop-unless-last (113-115), iget_cache_miss out_destroy cancel_sync of BAST works (115) — placeholder-free panic root fix, AG-meta fence (116).

## Validation state
iters 8,9 fully clean (pre-fence build); iter_10 = the reproduction (pre-fence). NEXT: run iters 11+ on 28B78CA1: expect P143 fires occasionally + NO new double-alloc (P-DBLALLOC with disk_owner=<live ino> gone; static xref CLEAN). Then full 32/caw ladder (RULE0_CALIBRATE=1 — that's how ALL criteria rows were recorded; posix_multi needs ~65-80s vs flat 30s budget, calibration tolerates), 16/8/4/2/1 regression, criteria marker.
Known open: Family-A panics (post-rmmod callbacks after heartbeat-abandon teardowns — mystery reboots between iterations; serial logs via sudo -n tail /var/log/libvirt/qemu/testN-serial.log). cc @32 has occasional 31/32 2-check fails (iter_7c — was probe-bail perturbation; watch on new build). Leftover run.sh/ssh chains after wrapper kills hold /tmp/mxfs_run.lock — kill full chains (fuser -v /tmp/mxfs_run.lock).
