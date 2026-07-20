---
name: sess110_lessons
description: sess110 — clean run: bnobt double-free (NOT sf_lookup) is the cache_coherency shutdown; sf_lookup NULL was a contaminated-cluster artifact. P99-AGMET…
metadata:
  type: project
---

# sess110 (2026-06-06, ccloop run 4eef1f39)

Continues sess109 (wedge fix C7393A5A, KEEP — AG-AIL-STALL=0 confirmed live this session).
Marker NOT written.

## Reframe (decisive, clean hard-reboot run)
On a CLEAN cluster (virsh destroy+start all 4 → reset4), the cache_coherency shutdown is the
**bnobt double-free** (`ltbno + ltlen > bno` xfs_alloc.c:2244 → xfs_free_ag_extent, in `rm`
inactivation/itruncate), NOT the sf_lookup NULL. The sess109 sf_lookup Oops (`xfs_dir2_sf_lookup`,
if_data=NULL while fmt=LOCAL) did **NOT recur** (P110-SFNULL=0) — it was a secondary artifact of
last session's contaminated cluster state. So the bnobt double-free is THE blocker, as in sess79-92.

Run result (build 89C04201, C7393A5A + sf_lookup -EIO guard): test completed (no 900s hang) →
`passed=0 failed=4 of=4`. cross_visibility FAIL: "cannot see node2.txt" + **"node3 reads node4's
content"** (= two files share a disk block = data-block DOUBLE-ALLOC, same root as bnobt double-free).
test1 shut down at t=233s via bnobt → unmounted → bailed the other 3 subtests.

## Builds this session
- `89C04201` = C7393A5A + P110-SFNULL diagnostic (xfs/libxfs/xfs_dir2_sf.c xfs_dir2_sf_lookup:
  if !sfp → log P110-SFNULL + return -EIO instead of NULL-deref). KEEP (defensive; converts a
  potential Oops to clean EIO). Never fired on clean run.
- `87726318` = +P110-BIO-OVER-LOGGED guard on the PLAIN-BIO read path (pal/linux/xfs_buf.c
  xfs_buf_submit, after the FUA block ~L2305): if XBF_READ && AG-meta && mxfs_buf_has_uncheckpointed_mods
  → keep in-core authoritative, skip read (mirror of P91 FUA backstop). DEPLOYED; run in progress at
  relay boundary — NEXT SESSION must read result: did P110-BIO fire on bnobt + shutdown gone?

## bnobt root recap (from sess92, re-confirmed applicable)
In-core revert of bnobt buffer split→pristine before drain (inode durable + AIL drained + storage
persists, all refuted as causes). FUA read is **sync+locked** (verified: mxfs_pal_scsi_read_fua_bdev
uses scsi_execute_cmd, blocking; xfs_buf_submit holds buf lock) → GPT "mechanism F" (mid-read TOCTOU)
IMPOSSIBLE via mxfs_buf_read_fua. P91 FUA backstop already guards pinned/logged FUA reads. Remaining
revert vectors: (a) PLAIN-BIO read clobber (no guard → P110-BIO probe added to test), (b) ALIASING
via xfs_buf_stale (clears _XBF_DELWRI_Q → cancels writeback of in-AIL split).

## KEY GAP FOUND (likely the fix site) — mxfs_dlm_ag_drain_meta_buffers (xfs_mxfs_dlm.c:6401)
sess99 ALREADY added publish-and-discard `xfs_buf_stale(bp)` for bnobt/cntbt at AG release
(L6618-6627, P99-AGMETA-STALE) per GPT "same fence applies to AGF/AGI/bnobt". BUT it only stales
buffers that go through the DRAIN (in-AIL / li_list / pinned). A bnobt buffer that is **CLEAN at
drain time** (already written by xfsaild, not in-AIL) is SKIPPED at L6476-6480 (`if (!ispinned){...
continue;}`) → NEVER staled → stays cached as a stale alias for the next tenure → fast-path re-grant
RMWs it → clobber. The acquire-side hook mxfs_ag_meta_invalidate_stale (L4800) only invalidates
gen-LAGGING bufs (buf_gen < pag_gen); a clean buf stamped buf_gen==pag_gen on a prior FUA read is
treated as current and NOT invalidated (the P70/P95 "buf_gen==pag_gen yet stale" hole).

## NEXT SESSION
1. Read the 87726318 run result (cc_run2.log + dmesg P110-BIO/ltbno on all 4). If P110-BIO fired on
   bnobt and shutdown gone → bio-path was the vector, KEEP guard, re-run full. If silent + shutdown
   persists → it's the CLEAN-cached-alias gap above (or aliasing), not the bio read.
2. Candidate fix (sess98/GPT/NEWARCH cold-read model): at AG release, xfs_buf_stale ALL cached
   bnobt/cntbt bufs in the AG (not just drained ones); OR cold-read (stale incore) on EVERY AG EX
   acquire. Pair release-discard + acquire-coldread (GPT: one without the other fails).
3. This IS NEWARCH-aligned: the bnobt revert is a landmine in the lossy caching machinery NEWARCH
   Phase 2/3 retires. After shutdown gone, run NEWARCH Phase 0 force_coherent gate (sess108 item 3).

## User context (IMPORTANT)
User asked "WTF happened, I thought NEWARCH was going to work." Status given: NEWARCH Phase 1 (kill
P106 stale-EX) is essentially DONE (chokepoint landed sess108, P106-STALE-EX=0 every run; wedge fixed
sess109). cache_coherency still red because (a) Phase 2 TCP invalidation mesh NOT built (the read-side
staleness it fixes), (b) bnobt landmine shuts FS down. NEWARCH is sound, ~mid-Phase-1→2. Do NOT
band-aid endlessly — advance NEWARCH (Phase 0 gate next, after bnobt shutdown neutralized).

## Infra
Nodes NFS-mount /src from 192.168.1.4 (criteria lib ENSURE_NFS auto-mounts; /mnt/mxfs-src is WRONG
path — it's /src). reset4.sh deploys via that. cache_coherency buffers stdout until done + makes
cluster very slow (ssh hangs under FUA load). virsh -c qemu:///system destroy+start for clean reboot.
</body>
