---
name: sess21-ccloop-perf-roots-and-reload-guard
description: sess21 run14d: reload-invalidate guard fixed corruption (12/12 clean); single_node_paired 180%→102% via 3 roots: large-folio shim, 64MB log slice, P7…
metadata:
  type: project
---

# sess21 (ccloop run 14d31183) — 2026-06-11

## Fix 1 — corruption blocker CLOSED (build 88922385, then 3B57EA84)
`mxfs_dlm_reload_inode` (xfs_mxfs_dlm.c ~3216) staled + cleared XBF_DONE on the
inode cluster buffer UNCONDITIONALLY. P20-CLUSTER-INVAL site=reload showed
li_empty=0 hits (attached log items) right before the daddr-0x78 dir corruption
and the iflush bad-magic family. Added the sess91-class
`mxfs_buf_has_uncheckpointed_mods` guard (P91-RELOAD-PROTECT, fires ~30×/cycle).
**repro_peer_find.sh: 12/12 cycles clean** (prior ~50% fail). Same guard now in
all three invalidate sites (recycle / iget-miss / reload).

## Fix 2-4 — single_node_paired 180% → **PASS 102%** (RULE 4 chain, each measured)
Diag scripts (in tree): `scripts/diag_single_paired_phases.sh`,
`scripts/diag_data_io_shape.sh`, `scripts/diag_rsync_io_shape.sh`.

1. **Large folios were silently disabled on 6.8**: compat shim for
   `mapping_set_folio_min_order` (xfs/xfs_platform.h ~102) was a no-op; the
   6.13+ call's large-folio-enable side effect is load-bearing. Without it,
   700MB dd writeback degraded to 3254 singleton 4KB bios (avg req 149KB vs
   native 511KB) = 2× data-path wall on iSCSI. Fix: shim calls
   `mapping_set_large_folios()` (exists in 6.8). dd 1722→834ms = native parity.
2. **Log slice too small**: mkfs_mxfs gave 32MB/node (8192 fsb); native
   mkfs.xfs min is 64MB → constant CIL/AIL tail pressure (1500 sync log writes
   vs native 107). Bumped min slice to 16384 fsb (tools/mkfs_mxfs.c ~1165).
3. **P74-INSTR probe = hidden FUA-read-per-allocation**: in
   xfs_alloc_fixup_trees, `b_mxfs_ag_gen` is NEVER stamped on alloc (cnt_gen=0)
   while pag_dlm_meta_gen>=1, so the "rare stale" branch fired on EVERY extent
   alloc → `mxfs_ag_buf_disk_differs` = sync SCSI READ(16) FUA. Measured 9248
   READ_16 per canonical rsync (= all 9248 zero-data "N" reqs in blktrace).
   Gated behind mxfs_instr_enabled (xfs_alloc.c ~745).

Side benefit: 2-node solo rsync 6.2s → ~3.7s; repro stays 4/4 clean on 3B57EA84.

## Debug technique that cracked it (keep)
ftrace `block_rq_issue` histograms (op×size×comm) + `scsi_dispatch_cmd_start`
opcode histogram on the node — READ_16 vs READ_10 split exposes SG_IO FUA
passthroughs that block-layer tracing shows as data-less "N" requests.
kprobe + per-event `stacktrace` trigger (NOT the global option — too slow).

## Also
- posix_semantics results key split: `posix_semantics_single` /
  `posix_semantics_multi16` (posix_semantics.sh, SUCCESS_CRITERIA.md,
  showstat.sh all updated 1:1).
- WATCH OUT: a native-XFS control test that mkfs.xfs's /dev/sda leaves
  /mnt/shared UNMOUNTED; one rsync "result" (2545ms, 1 flush) was the VM root
  LV. Always `mount | grep "shared type mxfs"` before trusting a measurement.

## Remaining for gate
scaling_curve(16), posix_semantics_single, posix_semantics_multi16, then full
verify_ship.sh end-to-end.
