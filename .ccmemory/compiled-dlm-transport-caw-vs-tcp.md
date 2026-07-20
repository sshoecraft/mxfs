---
name: compiled-dlm-transport-caw-vs-tcp
description: CAW is the load-bearing primary DLM transport; TCP DLM is a <16-node fallback with straggler + phantom-lock defects. Compiled.
metadata:
  type: project
tags: [compiled, dlm, caw, tcp-dlm, transport, scaling, scsi-caw]
---

# DLM transport: CAW (primary) vs TCP (fallback)

MXFS coordinates cluster locks over two DLM transports. **CAW (SCSI
Compare-And-Write, disk-based) is the deliberate load-bearing primary;
TCP DLM is a fallback**, not a replacement. The recurring temptation to
"switch the lock critical path to kernel TCP DLM as an architectural
fix" is wrong and refuted by prior-art evidence — see
[[CAW DLM is load-bearing for scale, not a design mistake]].

## Why CAW is primary (not a design mistake)
Prior art in `~/src/mxfs.1/` (continued in mxfs.2/3) settled this:
- TCP DLM is **correct** at 32 nodes (zero crashes, zero corruption) but
  **performance-limited above ~16 nodes**: single-lock-master-per-resource
  serial bottleneck. 32-node test = only 27% metadata completion; 16-node
  = 100% pass (`~/src/mxfs.1/README.md`, `docs/architecture.md`).
- TCP DLM per-node write imbalance 6.5x–7.7x at 4+ nodes; CAW = 1.01x on
  identical hardware (`~/src/mxfs.1/bench.json`).
- At 16+ nodes the DLM opens 120 TCP peer connections; heavy DLM traffic
  fills send buffers, blocks lease renewals → false node-death cascades.
  Heartbeats were moved off TCP onto **UDP multicast** for this reason
  (`~/src/mxfs.1/libmxfs/lease.md`).
- `mount.c::check_tcp_scale_warning` already emits a one-shot dmesg
  warning recommending CAW above 16 TCP DLM nodes.
- CAW is not free either: BAST poll I/O at 8 nodes can saturate the iSCSI
  target — addressed via poll-frequency reduction + `MXFS_BAST_YIELD_QUANTUM`
  (`~/src/mxfs.1/scale_tests_session10.txt`).
- User characterization: "TCP saturates and loses packets, ~24 nodes it
  completely falls off." Mechanism is more precise: correct-but-unusable
  due to (a) serial lock-master bottleneck + (b) TCP send-buffer congestion
  causing cascading false-death disconnects.

**Rule for debugging:** when a CAW bug appears, fix CAW. Do not propose
TCP/kernel-DLM as a cure-all. TCP DLM (`dlm/v5_mount.c`,
`mxfs.force_transport=1`) is a legitimate fallback for hardware lacking
CAW support and for clusters <16 nodes, and must keep working. When
comparing to GFS2/OCFS2, separate the transport axis (their kernel TCP
DLM is not a model for MXFS) from the cache-coherency-on-release contract
(GFS2/OCFS2 *are* a good reference there — see
`project_gfs2_coherency_pattern.md`).

## TCP DLM straggler pattern (transport-specific)
Per [[TCP DLM straggler issue]] (Session 69, 2026-03-20): under concurrent
sequential writes, TCP DLM has severe per-node throughput imbalance. On
tcm_loop (Samsung 870 1.8TB via LIO iblock, QEMU scsi-block passthrough):
- **CAW** 4-node new-file: 130/129/129/129 MB/s, spread **1.01x**, agg 517 MB/s.
- CAW 3-node new-file: 168/173/168 MB/s, spread 1.03x, agg 509 MB/s.
- CAW 2-node overwrite: 346/351 MB/s, spread 1.01x, agg 697 MB/s.
- **TCP** 4-node: **7.7x** spread fastest-to-slowest.

CAW eliminating the straggler proves it is transport-specific (not
allocation, caching, or FS-level). Suspected causes: TCP lock-grant
serialization, head-of-line blocking, keepalive/timeout interactions
under concurrent lock traffic. Always benchmark **both** transports;
never assume parity.

## TCP DLM port (sess27, v0.3.111)
See [[sess27 lessons]]. Full TCP DLM transport added in `dlm/v5_mount.c`,
bypassing kernel SCSI CAW (which sess26 found reports CAS-success without
persisting under stress). `mxfs.force_transport=1` selects TCP at insmod;
default 0 = unchanged CAW path.
- Wired all DLM-engine + peer + lease callbacks. `v5_dlm_send_cb_tcp`
  forwards control msgs via `mxfs_peer_send`; `v5_peer_msg_cb_tcp` parses
  wire frames → `mxfs_dlm_process_remote_*` (inbound `MXFS_MSG_LOCK_BAST`
  invokes v5 inode/AG notify_fn directly). `v5_bast_cb_tcp` forwards
  master BAST to holder (3 retries, 50ms backoff) or local-dispatches.
- `v5_refresh_active_nodes` pulls the active set from lease (self already
  registered at index 0 — initial double-add bug fixed).
- **Nothing** in `xfs/xfs_mxfs_dlm.c`, wire-protocol structs, or
  `peer.c/dlm.c/discovery.c/lease.c` needed changing — the v5 abstraction
  absorbed the port.

### Phantom AG locks on single→multi transition (TCP path bug, FIXED sess27)
Symptom: 15×512 stress freezes iter 1, both nodes spin on
`DLM AG lock failed: ag=N rc=-110` (60s ETIMEDOUTs). Cause: T1 mounts
alone (single-node), acquires AG EX as local master with
`pag_dlm_cached=true`. T2 mounts → peer discovery →
`v5_refresh_active_nodes` → `mxfs_dlm_update_active_nodes({T1,T2})` purges
local lock-table entries (re-mastering), **but XFS perag keeps
`pag_dlm_cached=true`**. Result: phantom holds on each other's preferred
AG; BAST ping-pong can't release because the master-side tracking entry
was purged → ETIMEDOUT loop. Fix: `mxfs_dlm_peer_joined_flush` already
handles exactly this (flush dirty + drop `pag_dlm_cached` for holderless
AGs); the CAW path fired it via `dlm_caw->single_node`, but the TCP path
never checked. Fix: in `v5_discovery_peer_cb`, when `ctx->peer` is set,
call `mxfs_dlm_is_single_node(ctx->dlm)` and fire `peer_joined_notify_fn`
**before** the `v5_refresh_active_nodes` purge.

### Mode A is transport-invariant (sess27 finding)
TCP DLM did **not** fix Mode A (dir-entry lost-update where `rm` finds
ENOENT); it confirmed it as pre-existing/architectural. Rates ~= CAW
baseline (~50–70% pass at 5×256; best lucky run 35/35). Instrumentation
progression:
- **P55** (`605DAD5B…`): post-`blkdev_issue_flush` on-disk dir snapshot
  inside `mxfs_dlm_bast_process` — showed dir released with `disk_size=6`
  (empty) despite a just-committed entry → the
  `xfs_log_force(SYNC)+xfs_ail_push_all_sync+blkdev_issue_flush` chain does
  **not** reliably persist recent dir mods before release.
- **P56**: `vfs_size` vs `ip->i_disk_size` — VFS sees 36 (2 entries),
  `i_disk_size`=21 (1 entry); `if_bytes==disk_size` (P58 never fired), so
  divergence is between VFS `i_size` and XFS `i_disk_size`+`if_bytes`.
  Divergence is necessary-but-not-sufficient for Mode A.
- **P59**: at every bast_process release `in_ail=0`, `pinned=0` — AIL
  genuinely empty, **ruling out** "incomplete flush at release." xfsaild
  already iflushed. Leaves block-layer/target write-cache (LIO/qemu FUA
  handling) as the suspect — same class as sess26 root cause #2, on the
  write side.
- **Refuted (sess27):** adding a *second*
  `log_force+ail_push+blkdev_issue_flush` cycle (`CAD6E386…`) → 2/5 vs 3/5
  baseline, WORSE. The first ail_push already drains the AIL.

### AIL-push deadlock at ≥512MB (architectural, not TCP-specific)
15×512 hangs iter 2 in `mxfs_dlm_ag_bast_work_fn` →
`xfs_ail_push_all_sync`: both nodes drain the full AIL, which holds items
needing locks the other node holds → mutual stall (122s hung-task). Same
issue likely affects CAW at scale. **Bounding the push is unsafe:**
`xfs_ail_push_all_sync_timed` (5s cap, `-ETIME`) → 5×256 FAILED iter 3
with corruption/shutdown (peer read stale disk before iflush). Conclusion:
AIL push must be **unbounded for correctness**; the bottleneck needs a
different fix (per-AG AIL filtering, or drop the sync push and rely on
per-AG buflist drain + `blkdev_issue_flush`). The
`xfs_ail_push_all_sync_timed` helper was left in `xfs_trans_ail.c` unused;
bast work fn reverted to unbounded. This is the sess33 "user ILOCK held
across AG-DLM CAW poll" family's neighbor.

## CAW persistence work — Path A (sess30, v0.3.128)
See [[sess30_lessons]]. **Path A (manual-bio CAW submission) is the
v0.3.128 default.** `pal/linux/kern.c::caw_manual_bio()` mirrors
`drivers/scsi/sg.c`'s `sg_start_req`: fresh `alloc_page()` per submission,
copy compare/write in, `bio_alloc(…REQ_OP_DRV_OUT…)`, `bio_add_page(…1024…)`,
`blk_rq_append_bio`, manual scmd (`scmd->allowed=0`, no `RQF_QUIET`),
`blk_execute_rq(req,true)` — avoids the `bio_map_kern`→`virt_to_page`
aliasing that `scsi_execute_cmd` does. `bio->bi_bdev` set to part0 to match
sg.c.

Results (mount-verified, 5×256, 5 samples × 5 iters):
- `caw_path=1` default: **20/25 = 80%** (up from sess26 ~50% baseline).
- `+caw_flush=1` (post-CAS `blkdev_issue_flush`): 21/25 = 84% (marginal).
- `+caw_gen_verify=1`: 22/25 = 88% (marginal, P72=0, no detection).
- `+caw_verify=1` (poll-persist FUA-readback): **0/25 = 0%** — DO NOT USE.

At **15× scale** (15×256, 15×512) the underlying SCSI non-persist bug
still fires — bnobt LEFT/RIGHT-FAIL at iter 1–9. Marginal improvements are
within sample variance because the **device write-cache returns
most-recent-written data on FUA-read**, so at-PAL/at-caller verify reads
see the still-cached write, not media; the bug manifests only when peer's
later FUA-read hits the device after the cache entry is *evicted* rather
than committed — invisible to the originating node.

Final srcversions: `A492B1861C46A46C2EFBE7D` (path1 default, all verify
flags 0), earlier `EE4C29D1F2511EB80FB51A1` = VERSION 0.3.128.

### DO NOT REPEAT (sess30)
- **`caw_verify=1` at PAL layer** compounds with caller retries →
  ETIMEDOUT. Verify-mismatch retries CAS; retry hits MISCOMPARE (peer
  raced or our prior CAS finally persisted) → `-EAGAIN`; caller's
  `MXFS_CAW_MAX_RETRIES=100` loop compounds → 100×5×(CAS+verify+msleep)
  blows the 60s DLM grant. Observed: `caw_unlock: unlock exhausted 100
  retries`, `DLM inode lock failed … rc=-110`, `Corruption of in-memory
  data (0x8)` shutdown; P71-INSTR fired thousands of times on same lba.
  Detection is *correct* (sess26 P49 root cause #2 is real) but
  compounding makes it worse than no-verify. If retrying, do it at the
  **caller** (`caw_lock`/`caw_unlock` in `dlm_caw.c`) using the slot
  `generation` field to distinguish "our CAS persisted, peer overwrote
  with later gen" (success) from "gen unchanged" (retry).
- **`caw_path=1` from insmod onto non-fresh disk state** → iter 1
  ETIMEDOUT regardless of path (stale CAW slots; mkfs pwrite-O_SYNC zero
  isn't durable on LIO). Always fresh-mkfs reset before stress.

### Storage-side root cause (sess30)
`/dev/sda` on test1/test2 = virtio-scsi passthrough of host `/dev/sdc`
(tcm_loop → LIO `block` backstore → host `/dev/sda`, Samsung 870 EVO 2TB).
**Samsung 870 EVO does not support SCSI FUA** (`queue/fua=0`, `DpoFua=0`,
`FUAB=0`). **LIO `tcm_iblock` silently drops the initiator FUA bit** —
`target_core_iblock.c:772` only sets `REQ_FUA` on its outgoing bio if
`bdev_fua(ib_dev->ibd_bd)` is true (false on the 870), so CAW writes with
CDB FUA hit the SSD write-back cache and ACK before NAND commit;
`emulate_write_cache=0` means initiators don't auto-flush. Adding
`blkdev_issue_flush` per CAS-success only bought 80→84%, so FUA-on-write is
not the whole story. Candidate next steps: set `emulate_write_cache=1`,
use an FUA-capable enterprise SSD, or build Path C (`mxfs_clayer`
cluster-coherency above DLM using slot-generation semantics to
detect/recover non-persist).

### Test-harness gotcha (sess30)
`mxfs_cluster_reset.sh` can silently fail test1's mkfs/mount (e.g.
`zero_region verify FAIL … storage silently dropped writes`) and keep
going; test2 then mounts the prior filesystem single-node and stress runs
test2-only, while "T1+T2 dd+rm OK" markers all PASS because test1's dd
lands on local ext4. **Always verify both nodes mounted post-reset**
(`mount | grep -c mnt/shared == 1` on each) before trusting results.

## Cross-cutting thread
sess26 P49 kernel `scsi_execute_cmd` non-persistence is a **real kernel
SCSI passthrough bug** worth root-causing — it is *not* evidence CAW is
the wrong primitive. Both the sess27 Mode A write-side staleness and the
sess30 CAW non-persist bottom out in the same LIO/tcm_iblock/write-cache
FUA-drop family, which the `_XBF_FUA_FRESH` read-side hooks and Path C
coherency layer are meant to contain.
