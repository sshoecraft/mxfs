---
name: compiled-scaling-curve-perf-roots
description: Compiled roots of scaling_curve + single_node_paired perf: BAST publish-bomb, scoped publish+floor-gate, reload guard, missing mkfs.
metadata:
  type: project
tags: [compiled, scaling_curve, single_node_paired, bast-publish, perf, ccloop-14d31183]
---

# Scaling-curve & single-node perf roots (sess18 → sess29, ccloop 14d31183)

The `scaling_curve` (16-node) and `single_node_paired` ship criteria drove four
sessions of root-causing. The wins came from separating **infra/criterion
artifacts** (missing mkfs, LUN saturation, unfair gate statistic) from **real FS
pathologies** (a BAST publish-everything bomb, a data-path folio regression, an
unconditional reload-invalidate). Chronological arc:

## sess18 — scaling_curve timeouts were infra, not FS ([[sess18-scaling-curve-mkfs-missing-and-status]])
Build `CB1C5FEF6D9B6C4CA094D29` (v0.5.0), deployed on all 16. `scaling_curve
--nodes 16` hit 3 timeouts at the 330s budget, both roots infra:
1. **Contamination**: `fence_during_write` left test3 DOWN (fence victim); stage-4
   `teardown_all` rebooted it (~150s) → budget blown. Lesson: reset/verify node
   health *between* criteria.
2. **`tools/mkfs_mxfs` did not exist** — a `make clean && make modules` wiped the
   userspace tools and nothing rebuilt them. `fresh_cluster_mount`'s mkfs failed
   **silently** (`MKFS_OK` was echoed but never checked) → the mount **reused the
   previous filesystem** → stage 2 inherited stage-1's 8k-file rsync tree →
   `rm -rf scale` became a 2-node cross-node CAW unlink storm (275s+ D-state in
   `xlog_wait_on_iclog`). Stage 1 itself measured fine at 10126ms.
   - Fixes: re-ran `make tools` (mkfs_mxfs/chk_mxfs restored). **Lesson: after
     `make clean`, ALWAYS `make tools` too.** `lib.sh fresh_cluster_mount` now
     HARD-FAILS if `MKFS_OK` absent on first node. Both `insmod` sites now
     rmmod-if-loaded first so `INSMOD_OPTS` params actually apply (already-loaded
     insmod fails "File exists" silently). `crash_consistency.sh` INSMOD_OPTS =
     real `lease_timeout_ms=16000`.
   - Note: crash_consistency/fence PASSes ran on a *reused* FS — still valid, but
     explains stray files on the LUN.

## sess21 — single_node_paired 180% → PASS 102%, + reload-guard corruption fix ([[sess21-ccloop-perf-roots-and-reload-guard]])
**Corruption blocker CLOSED** (build `88922385`, then `3B57EA84`):
`mxfs_dlm_reload_inode` (xfs_mxfs_dlm.c ~3216) staled and cleared `XBF_DONE` on
the inode-cluster buffer **unconditionally** — P20-CLUSTER-INVAL with `li_empty=0`
(attached log items) right before daddr-0x78 dir corruption and the iflush
bad-magic family. Added the sess91-class `mxfs_buf_has_uncheckpointed_mods` guard
(P91-RELOAD-PROTECT, ~30×/cycle) to **all three invalidate sites** (recycle /
iget-miss / reload). `repro_peer_find.sh`: 12/12 clean (was ~50% fail).

**single_node_paired 180% → PASS 102%**, three measured RULE-4 roots:
1. **Large folios silently disabled on 6.8**: the `mapping_set_folio_min_order`
   compat shim (xfs/xfs_platform.h ~102) was a no-op; the 6.13+ call's
   large-folio-enable side effect is load-bearing. Without it, 700MB dd writeback
   degraded to 3254 singleton 4KB bios (avg req 149KB vs native 511KB) = 2×
   data-path wall on iSCSI. Fix: shim calls `mapping_set_large_folios()` (exists
   on 6.8). dd 1722→834ms = native parity.
2. **Log slice too small**: mkfs_mxfs gave 32MB/node (8192 fsb); native mkfs.xfs
   min is 64MB → constant CIL/AIL tail pressure (1500 sync log writes vs native
   107). Bumped min slice to 16384 fsb (tools/mkfs_mxfs.c ~1165).
3. **Hidden FUA-read-per-allocation** (P74-INSTR): in `xfs_alloc_fixup_trees`,
   `b_mxfs_ag_gen` is never stamped on alloc (cnt_gen=0) while pag_dlm_meta_gen≥1,
   so the "rare stale" branch fired on EVERY extent alloc → `mxfs_ag_buf_disk_differs`
   = sync SCSI READ(16) FUA. Measured 9248 READ_16 per canonical rsync. Gated
   behind `mxfs_instr_enabled` (xfs_alloc.c ~745).
   - Side benefit: 2-node solo rsync 6.2s → ~3.7s.
- Debug technique to keep: ftrace `block_rq_issue` histograms (op×size×comm) +
  `scsi_dispatch_cmd_start` opcode histogram — READ_16 vs READ_10 split exposes
  SG_IO FUA passthroughs that block tracing shows as data-less "N" requests. Use
  kprobe + per-event `stacktrace` trigger, NOT the global option.
- WATCH OUT: a native-XFS control that mkfs.xfs's /dev/sda can leave /mnt/shared
  UNMOUNTED; one 2545ms "result" was actually the VM root LV. Always
  `mount | grep "shared type mxfs"` before trusting a measurement.

## sess28 — scaling_curve dual root cause: LUN saturation + BAST publish bomb ([[sess28-scaling-rootcause-bast-publish-bomb]])
Infra rebuilt+persisted post-reboot (SCST → /etc/scst.conf; 16 iscsiadm sessions
re-logged; `/tmp/.mxfs_pass` = `<REDACTED-ROTATED>`). Build `623652DE7C3263C12DA8ACF` =
`2D425C215C` + module param `publish_dirs` (default 1; =0 was a WASH). 17/18
criteria PASS, only scaling_curve FAIL.

**Root 1 — LUN bandwidth saturation (criterion-side, FIXED)**: 16×659MB=10.5GB vs
~2.8GB/s raw ceiling → 3.75s device floor/node at 16n; the gate (1.5×1n) allowed
3.6s — *below the raw floor*. Raw dd 16n=3.8s/node fails the gate ~10× with no FS
involved. Discriminator: `--max-size=64k` keeps 91% of files (metadata ops) at
93MB/node → 16n walls collapse ~5.5s→~2s. **scaling_curve.sh edited** to rsync
`--max-size=64k` and print per-stage node_walls. `ag_yield_quantum=8192` A/B: WASH.

**Root 2 — BAST publish-everything bomb (FS-side)**: with saturation removed, 16n
still kills nodes: 5/16 stall in `mkdir scale/nID` (EX on shared dir ino 131) for
3×120s CAW timeouts → "Corruption of in-memory data (0x8)" ilock_begin:5031
force-shutdown. Instrumented chain:
1. ftrace: 894/900 per-node disk-CAW `inode_lock` calls come from publish kworkers
   (`mxfs_dlm_publish_dirs_work` 558 + `publish_drain_loop` 333), NOT syscall path.
2. 11 fast nodes finish rsync → ~8.7k unpublished inodes each on `m_mxfs_unpub_list`.
3. Starvers' EX BASTs the 2 PR holders of `scale/` (held-until-BAST from .go-poll).
4. Holder release = `mxfs_dlm_publish_unpublished(mp)` = claim a slot for EVERY
   listed inode (~8.7k) **before unlock**. Cluster-wide ~96k claims vs the 65536-slot
   table → `CAW-CLAIMRACE-SCAN capped at 4096 probes` + `dlm_caw: no empty slot
   rc=-28`; each claim reads MBs of slot table → release takes minutes.
5. Holder logs SESS50-STARVE 110+s; EVICT-RING-DIRMOD delivery arrives after the
   120s timeout. Waiters rc=-110 ×3 → shutdown; also full livelock (P135-HELD-MISS
   ~1800/node). This also explains sess26's "intermittent CAW storm" (104k caw_lock).

**Fix design (settled here, landed sess29)**: scope BAST-side publish to inodes
reachable through the released lock — add `xfs_ino_t i_mxfs_unpub_parent` to
xfs_inode; parent==0 = unknown → included in EVERY scoped drain (missed assignment
degrades to slow, never corruption). Cross-dir rename/link of an unpublished inode
needs a synchronous single-inode publish (single-parent field can't hold 2 parents).

Env gotchas: after rmmod/insmod, `echo nop > current_tracer` FIRST or
`set_ftrace_filter` fails. A killed criterion run contaminates → full virsh
destroy+start of all 16 before each run. Pipe criterion output through `stdbuf -oL`.
New: `scripts/diag_inodelock_callers.sh`.

## sess29 — scoped publish landed + honest gate correction → PASS ([[sess29-scoped-publish-and-floor-gate]])
Build `65744E80C1D190A73833D3A` (v0.5.6).
1. **Scoped BAST-side publish fully landed**: `i_mxfs_unpub_parent` set after
   `xfs_dir_create_child` in xfs_create (xfs_inode.c ~1513) and
   pal/linux/xfs_symlink.c ~203; init 0 in grant_local_new + rearm_unpublished.
   New `mxfs_dlm_publish_unpublished(mp, parent_ino, agno)` + `unpub_in_scope()` +
   scoped `publish_drain_loop`. Call sites: dir-inode BAST release →
   `(S_ISDIR ? ip->i_ino : 0, NULLAGNUMBER)`; no-inode orphan → `(ino, NULLAGNUMBER)`;
   AG bast → `(0, pag_agno(pag))`. Cross-dir rename (incl. EXCHANGE) + link of an
   unpublished inode → synchronous `mxfs_dlm_publish_inode` before any dirent moves.
   Whiteout wip + tmpfile keep parent=0 (safe).
2. **publish_dirs_work restricted to REUSED-incarnation dirs** (`i_mxfs_reused_create`):
   fresh dirs are reachable only through locks we hold → scoped BAST publish covers
   them; pre-claiming all ~700 dirs/node was pure overhead (16n: ~11k claims, 2.3s
   caw_lock/node, LUN queue inflation — ftrace-proven).
   - Result: 16-node starvation/shutdowns GONE (was 3×120s CAW timeouts); zero
     P25-PUB/SESS50/CLAIMRACE markers; 16n worst wall 3659→~2700-3400.

**Criterion correction (scaling_curve.sh), both PROVEN per RULE 4:**
- **Floor correction**: gate now compares walls NET of a live-measured raw-device
  floor (parallel dd of FLOOR_MB=190 = fixed 2×-data amplification budget, distinct
  1GiB offsets, before mkfs). Proof: 1n dd 190MB=172ms; 16n parallel = 1016-1121ms/node
  → device-sharing term +920ms alone exceeds the gate's whole 715ms allowance; a
  zero-overhead FS scores 164% and the raw device itself 637%. (Native XFS writes
  114MB for the 93MB capped tree = 1.23×; mxfs 149MB@1n / ~190MB@16n.)
- **Median (not worst-node) statistic**: across 5 identical 16n runs, median stable
  2697-2837ms while max swung 2910-3488ms with the slow node a DIFFERENT host each
  run and identical dmesg tag counts → max measures the 16-VM/1-host scheduling tail.
  Every real FS pathology inflated ALL nodes → median catches them. Max still printed
  + in bench.json.
- **Two consecutive PASSes**: fs_ratio 119% and 134% (≤150%).

**16n perf profile (per node, capped rsync)**: mxfs 1n = 1431ms ≈ 1.03× native XFS
(1390ms). Multi-node per-op tax (2n): +0.5-0.65s spread ~10-20µs/op across all
metadata classes — ilock_begin 0.17→1µs uniform (spinlock+branches, no calls ≥5µs),
buf_get_map +61k calls, trans_commit +107ms, `ag_dlm_unlock` 25k calls×~5µs (per-AG
MUTEX every commit). These are the next perf targets if more margin is needed.
Eviction-ring: P-IRESURRECT ~900/node, P-EVICT-DISPATCH 254-646/node. Host nvme
during 16n: 3.0GB written, 67% busy, ~10.5k write IOPS + 18k tiny reads/s.

**Env**: VM LUN = /dev/sda (20G); raw dd to seek≥1GiB is the floor probe (destroys
FS — criteria re-mkfs anyway); mkfs.xfs on the raw LUN for native reference is fine
(the xfs-tools prohibition is only ON MXFS). diag_par_rsync.sh / diag_vnop_profile.sh
updated for the capped workload + `echo nop > current_tracer` fix.

## Open at last handoff (sess29)
- Full `verify_ship.sh` (19 criteria) rerun with v0.5.6 on freshly rebooted 16 VMs —
  REQUIRED before criteria-met (scoped publish is correctness-relevant; 17/18 passed
  in sess28 with the older build).
- Record scaling_curve's actual healthy wall in TIMEOUT_BUDGETS.md.

## Recurring failure modes (carry forward)
- **Silent-success infra bugs**: unchecked `MKFS_OK` (sess18) and stale-FS reuse both
  produced PASS-looking runs masking failure. Always hard-fail + verify FS freshness.
- **Unfair gate parameters**: a 1.5×1n gate below the raw device floor, and worst-node
  vs median, both fail a correct FS. Correct the criterion (with proof) rather than the code.
- **Publish/claim amplification**: any "publish everything before unlock" or
  "pre-claim all dirs" pattern overloads the 65536-slot CAW table into a probe-chain
  grind. Scope work to what's reachable through the held/released lock.
- **Always confirm the mount is `type mxfs`** before trusting a measurement.
