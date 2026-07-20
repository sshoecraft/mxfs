---
name: compiled-heartbeat-eviction-purge-cascade
description: sess69-70: heartbeat false-eviction (stale PLAIN read) + purge_node 65536-FUA cascade starves zsl(16) verify; both fixed, now SCSI-PR root.
metadata:
  type: project
tags: [compiled, heartbeat, eviction, purge-node, zero-silent-loss, caw, coherency]
---

## Heartbeat false-eviction + purge_node cascade that starves the zsl(16) verify

Central topic: under a 16-node storm on the single shared LUN, the CAW dead-detector
falsely evicts LIVE peers, and the eviction handler's `purge_node` is so slow it both
(a) prevents the evicting node from beating (self-cascade) and (b) holds dir ilocks so
long the `zero_silent_loss.sh` (zsl) verify `find` hangs. Not a silent-loss bug — a
structural verify-hang masquerading as one. Chronology below is sess69 → sess70.

### Infra baseline / reproduction
All 16 nodes' I/O funnels through clyde's single SCST `disk1` vdisk = one `/dev/sdd`
(loopback iSCSI to disk1b). Prep: `cluster_reset_n.sh 16` (virsh destroy+start — force-kills
D-state wedged nodes) then run `tests/criteria/zero_silent_loss.sh` directly; the reset
verify step races (sshd throttling) and shows a random node NOT_LOADED, but zsl re-insmods
all nodes itself so ignore the gate. Sequential spaced ssh (sleep 0.6) gives true load
state. zsl PASSED at 355s on build **9C2D4FA6** (sess17) — the regression baseline to diff
against; something after that made eviction this fragile.

### sess69 — the cascade, proven [[sess69-zsl-heartbeat-eviction-cascade-blocks-verify]]
First real zsl(16) run after host unwedge (all 16 on build **2D460CA3**), defaults 3 iters
dpn=100 mode=1. Result FAIL (structural): verify hang, killed at outer 520s (internal 480s).
Host did NOT re-wedge (D-state 0, portal up) — failure is in the cluster, not SCST.
Proven chain (sysrq-w + dmesg on test1):
- `slot 7 (test8) no longer responding (heartbeat expired after 31 checks)` →
  `P-H22-PURGE-NODE dead_slot=7` → `XFS (sda): Starting recovery`; repeats for slot 9.
  A cascade of heartbeat evictions under storm.
- `mxfs-worker` pid1200 D-state in `mxfs_dlm_caw_purge_node → mxfs_pal_bdev_read_prio →
  mxfs_pal_scsi_read_fua_bdev → io_schedule_timeout`.
- `mxfs_dlm_caw_purge_node` (dlm/dlm_caw.c:2810) scans ALL 65536 slots, one `read_slot`
  FUA read each (dlm_caw.md:103) = tens of s to minutes on the contended LUN; cascade
  multiplies it.
- During purge+recovery node0 holds dir ilocks: `find` blocked in
  `xfs_readdir → xfs_ilock_data_map_shared → down_write`; getattr finds blocked behind the
  queued writer. All permanently D.
Eviction window: `samples = timeout_ms / MXFS_DISKLOCK_HB_INTERVAL_MS` ⇒ ~31 checks ⇒ ~16s
(disklock.c:1060, :474; lease_timeout_ms=16000 set sess18). Two candidate roots were named
here (slow O(65536) purge; too-aggressive heartbeat) with the standing rule: do NOT just
widen lease_timeout_ms (RULE 0 masks slowness + breaks crash_consistency's 16s detect).

### sess69 — false-eviction root + confirm-before-evict fix, build FE603677 [[sess69-heartbeat-stale-read-false-eviction-fix]]
Code-confirmed root of the SPURIOUS evictions: the heartbeat thread WRITES its own beat with
`write_sector_fua` (FUA), but the dead-detector monitor READS each peer's slot with plain
`mxfs_pal_bdev_read` (disklock.c:343) — cacheable. Under storm the guest block layer / SCST
per-initiator cache returns a STALE heartbeat sector, so a live-but-busy peer's
`timestamp_ms` looks frozen → `equal_samples` hits `dead_threshold` (~31) → false eviction.
This is the codebase's signature FUA-read-coherency gap, now found in the dead-detector
(every other coherency-critical read uses `mxfs_pal_bdev_read_prio` → `mxfs_scsi_read16_fua`,
cache-bypassing).
Fix (dlm/disklock.c): at the eviction decision point (`equal_samples>=dead_threshold &&
live`), BEFORE firing dead, FUA re-read via `mxfs_pal_bdev_read_prio`; if the beat actually
advanced (`rhb->timestamp_ms != nt->last_timestamp`), log `P-HBFALSE slot=.. last_ts=..
fua_ts=.. eq=..` and DO NOT evict (reset equal_samples, adopt fresh ts). Epoch-change reboots
still reach `fire_dead:` via goto and correctly SKIP the confirm (definite restart). Added
`int crr;` at top of the monitor for-loop to avoid goto-skips-init. Build
**FE603677** (FE6036776397D935E906E96), UNVERIFIED at sess69 close. Follow-up idea if
P-HBFALSE fires a lot: convert the PRIMARY monitor read (disklock.c:343) to
`mxfs_pal_bdev_read_prio` so the detector never accumulates stale samples.

### sess70 — two verified fixes, root advances; build 55379AA2 [[sess70-overcount-fix-and-purge-cascade-fix]]
FE603677 confirmed NOT to leak a module ref: controlled test3 mount→umount→rmmod gives
refcnt 0→1→0 RMMOD_OK. The refcnt leak prior sessions saw is a SYMPTOM of FS-shutdown-wedged
nodes, not the heartbeat fix; cure = virsh destroy+start before each zsl.

FIX 1 (KEEP) — bmbt OVER-count corruption, `P70-DINO-RECONCILE` (xfs/libxfs/xfs_bmap.c
~line 1247). Fast (instr=0) zsl iter1 shutdown = `corrupt dinode 131 (btree extents)` at
`xfs_iread_bmbt_block+0x500` (line 1247, `ir->loaded + num_recs > if_nextents`). Hex dump
showed a STRUCTURALLY VALID bmbt leaf (BMA3, owner=0x83, level0 numrecs=19) — an over-count,
not garbage. INVERSE of sess68's under-count: the sess68 consume FUA-refresh makes the leaf
fresh-high while the in-core dinode `if_nextents` stays stale-LOW (i_dlm_dir_gen-notify race
lets a fastex self-skip the reload). On-disk pair proven coherent (P34B/P68/P62-IFLUSH-FORCE
all match), so the on-disk dinode is authority. Fix = symmetric completion of sess68: at the
over-count point FUA-re-read this inode's dinode and if `xfs_dfork_data_extents(d_dip) >=
loaded+num_recs`, adopt `ifp->if_nextents = disk_nx` instead of shutting down. Scoped to
multi-node BTREE dir data fork, held ILOCK_EXCL, logs `P70-DINO-RECONCILE` (dirwr-gated).
VERIFIED: no more "corrupt dinode" anywhere.

FIX 2 (KEEP) — the purge_node cascade amplifier itself (dlm/dlm_caw.c
`mxfs_dlm_caw_purge_node` ~2810). Proven by stack: `disklock_hb_fn → v5_lease_expire_cb →
mxfs_dlm_caw_purge_node → read_slot → blk_execute_rq` D-state tens of s. purge_node ran ON
the heartbeat thread doing 65536 individual FUA `read_slot` (~5-60s on contended LUN) → node
couldn't beat → peers evicted IT → cascade; also starved the verify `find` on dir ilock (the
sess69 hang). Fix = delegate to the EXISTING batched
`mxfs_dlm_caw_purge_dead_nodes(ctx, 1ULL<<dead_slot)` — 32-slot / 16KiB chunked reads, <1s,
identical per-slot clear+CAS. VERIFIED: zsl iter1 now completes in 47s (no hang). Build
**55379AA2** (55379AA23901AE1BF0B8330).

### Remaining blocker after 55379AA2 — SCSI PR reservation conflict → FS shutdown
zsl still FAILs, but the mode moved (corruption→fixed, cascade→fixed, now SCSI-PR). iter1 =
silent=1600 (whole-storm blast radius from ONE shutdown), iters 2/3 INFRA FAIL (nodes wedged).
dmesg chain (test1 t93, test5 t79, test9 t91): `reservation conflict` (FIRST, mid-storm) →
`XFS log I/O error -52` → `Filesystem shut down (log error 0x2)`; downstream
`xfs_agi_verify block 0x2` / `xfs_agf_verify block 0x1` from torn writes. A LIVE node loses
its SCSI PR registration mid-storm → writes rejected. Mechanism: a heartbeat-only eviction
(`no longer responding after 31 checks`) drives the fence path `v5_lease_expire_cb`
(dlm/v5_mount.c:505) which likely calls `mxfs_scsipr_preempt` (dlm/scsipr.c:138) to preempt
the "dead" node's PR key. The residual false eviction is now a starved heartbeat WRITE, which
FE603677's confirm-READ cannot rescue (a missing write can't be re-read fresh). NEXT: (a) trace
`v5_lease_expire_cb` fence/preempt — either don't PR-preempt on heartbeat-only eviction, or
harden liveness so the hb WRITE never starves. The hb write is already REQ_PRIO|SYNC|FUA
(pal/linux/kern.c:849), but the hb thread does a self-fence SB READ at disklock.c:269 BEFORE
the write each cycle — consider writing the beat FIRST. (b) Likely SHARED root with
fence_during_write (lost=400, write-side durable lost-update). Note: `P-EVICT-AUTOMON`
(disklock.c:379) is NOT an eviction — it just inits slot→node monitoring on first sight
(idempotent); ignore it.

### Carry-forward
- Other separate roots still open: fence_during_write (lost=400), rsync_paired (148% perf).
- If zsl passes, also re-run posix_semantics_multi16 (likely same heartbeat root) and full
  verify_ship.sh.
- Parallel 16-node `reset4.sh` mount is unreliable (single-LUN contention, 1 random node
  fails / NOMNT drift) but no evictions at idle — the heartbeat fix is stable at rest.
