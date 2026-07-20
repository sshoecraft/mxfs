---
name: sess70-overcount-fix-and-purge-cascade-fix
description: sess70: FIXED bmbt over-count corruption (P70-DINO-RECONCILE) + purge_node cascade (batched). Build 55379AA2. New blocker = SCSI PR reservation confl…
metadata:
  type: project
---

## sess70 (ccloop 14d31183) — two verified fixes, zsl root advanced; build 55379AA23901AE1BF0B8330

Marker NOT written. zsl still FAILs but the failure MODE moved twice (corruption→fixed, cascade→fixed, now SCSI-PR).

### Confirmed FE603677 (sess69 heartbeat fix) does NOT leak module ref
Controlled single-node test3 mount→umount→rmmod: refcnt 0→1→0, RMMOD_OK. The refcnt leak prior sessions saw is a SYMPTOM of FS-shutdown-wedged nodes, not the heartbeat fix. Cure = virsh destroy+start (cluster_reset_n.sh 16) before each zsl.

### FIX 1 (KEEP) — bmbt OVER-count corruption, P70-DINO-RECONCILE (xfs/libxfs/xfs_bmap.c ~line 1247)
PROVEN: fast (instr=0) zsl iter1 shutdown = `corrupt dinode 131 (btree extents)` at `xfs_iread_bmbt_block+0x500` = line 1247 `ir->loaded + num_recs > if_nextents`. Hex dump showed a STRUCTURALLY VALID bmbt leaf (BMA3, correct uuid/owner=0x83, level0 numrecs=19) — CRC/over-count, not garbage. This is the INVERSE of sess68's under-count: the sess68 consume FUA-refresh makes the LEAF fresh-high while the in-core dinode `if_nextents` stays stale-LOW (i_dlm_dir_gen-notify race lets a fastex re-acquire self-skip the reload). dirwr run PROVED on-disk pair IS coherent (P34B cached_recs=23 disk_recs=31→P68 refresh new_recs=31 if_nextents=31 MATCH; every P62-IFLUSH-FORCE leafsum==if_nextents). So the on-disk dinode is the authority. FIX = symmetric completion of sess68: at the over-count point, FUA-re-read THIS inode's dinode, and if `xfs_dfork_data_extents(d_dip) >= loaded+num_recs`, adopt `ifp->if_nextents = disk_nx` instead of shutting down. Scoped to multi-node BTREE dir data fork; held ILOCK_EXCL. Logs `P70-DINO-RECONCILE` (dirwr-gated). VERIFIED: no more "corrupt dinode" anywhere after this fix.

### FIX 2 (KEEP) — purge_node cascade amplifier (dlm/dlm_caw.c mxfs_dlm_caw_purge_node ~2810)
PROVEN by stack: `disklock_hb_fn → v5_lease_expire_cb → mxfs_dlm_caw_purge_node → read_slot → blk_execute_rq` D-state tens of s. purge_node ran ON the heartbeat thread doing 65536 individual FUA read_slot (~5-60s on contended LUN) → node couldn't beat → peers evicted IT → cascade; also starved the verify `find` on dir ilock (sess69 hang). FIX = delegate to the EXISTING batched `mxfs_dlm_caw_purge_dead_nodes(ctx, 1ULL<<dead_slot)` (32-slot/16KiB chunked reads, <1s, IDENTICAL per-slot clear+CAS). VERIFIED: zsl iter1 now completes in 47s (no hang).

### REMAINING BLOCKER (next session) — SCSI PR reservation conflict → FS shutdown under 16-node storm
After both fixes, zsl iter1 = silent=1600 (whole-storm blast radius from ONE shutdown), iters 2/3 INFRA FAIL (nodes wedged). dmesg chain (test1 t93, test5 t79, test9 t91): `reservation conflict` (FIRST, mid-storm) → `XFS log I/O error -52` → `Filesystem shut down (log error 0x2)`; downstream `xfs_agi_verify block 0x2` / `xfs_agf_verify block 0x1` corruption from torn writes. A LIVE node loses its SCSI PR registration mid-storm → writes rejected. Mechanism: heartbeat eviction (`no longer responding after 31 checks`) → fence. Fence path = `v5_lease_expire_cb` (dlm/v5_mount.c:505) — CHECK if it calls `mxfs_scsipr_preempt` (dlm/scsipr.c:138) to PR-preempt the "dead" node's key. Under storm a live-but-busy node's heartbeat WRITE starves (FE603677 confirm-READ can't help a missing WRITE) → false eviction → PR preempt of a LIVE node → that node's writes conflict → shutdown. P-EVICT-AUTOMON (disklock.c:379) is NOT eviction — it just inits slot→node monitoring on first sight (idempotent), ignore it. NEXT: (a) trace v5_lease_expire_cb fence/preempt; either don't PR-preempt on heartbeat-only eviction, or harden liveness (the heartbeat WRITE must not starve — already REQ_PRIO|SYNC|FUA at pal/linux/kern.c:849, but the hb thread does self-fence SB read at disklock.c:269 BEFORE the write each cycle — consider writing hb FIRST). (b) Likely SHARED root with fence_during_write (lost=400). Reference: zsl PASSED 355s on build 9C2D4FA6 (sess17) — diff what made eviction this fragile.

### Infra notes
cluster_reset_n.sh 16 verify step races (sshd throttling) — shows random NOT_LOADED; nodes ARE booted clean (virsh destroy+start), zsl re-insmods all itself, so run zsl directly after reset regardless of the verify gate. Sequential spaced ssh (sleep 0.6) gives true load state.

Links: [[sess69-heartbeat-stale-read-false-eviction-fix]] [[sess69-zsl-heartbeat-eviction-cascade-blocks-verify]] [[sess68-host-loopback-deadlock-and-sharpened-p67-probe]] [[sess60-zsl-writer-releases-inconsistent-dinode-bmbt]] [[sess65-zsl-dlm-handoff-metadata-coherency-root]]
