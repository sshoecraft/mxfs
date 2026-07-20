---
name: sess75-readahead-count-leak-unmount-wedge-fix
description: sess75: zsl 1600→3 silent loss (FIX1+FIX2 deployed). New blocker found+fixed: bt_readahead_count leak wedges umount in xfs_buftarg_wait, breaking mul…
metadata:
  type: project
---

## sess75 (run 14d31183) — zero_silent_loss progress

### Big win: FIX1+FIX2 (build 67597818, from sess74) deployed + verified
Deployed to 16-node v5 cluster. `zero_silent_loss --iters 1 --dpn 100 --mode 1`:
**total_fs_silent dropped 1600 → 3** (no shutdown cascade, all 16 mounted, no verify hang).
- FIX1 (readdir ILOCK self-deadlock) + FIX2 (torn-dinode iflush barrier) are KEEP/working.
- Residual silent loss ~3-9/iter: a dir-block lost-update. Forensics: e.g. `MISSING node6_dir94 creator=test6 CREATOR_MISSING creator_errs=[none]` — creator's own dirent durably lost, no mkdir error. This is the remaining real coherency bug (NOT yet fixed).

### NEW BLOCKER FOUND + FIXED (RULE 4, decisively proven): bt_readahead_count leak → umount wedge
`zsl --iters 3` only completes 1/3: iters 2-3 INFRA-fail because the inter-iter `mount_cluster` umount **wedges a node** (different each run) in D-state:
`xfs_buftarg_wait+0x.. -> xfs_log_quiesce -> xfs_log_unmount -> umount`. Device `/dev/sda` (SCST_FIO via virtio-scsi) is HEALTHY (dd works). The flapping QNAP iSCSI `conn error 1020` (192.168.1.4) is UNRELATED noise (QNAP also serves NFS /src; /dev/sda is the host SCST LUN).

**Root (instrumented, proven):** `xfs_buftarg_wait` hangs in `while(percpu_counter_sum(&bt_readahead_count)) delay(100)` — `bt_readahead_count` leaks exactly +1. Mechanism: under the dir storm, a dir extent-map reload (`xfs_iread_extents -> xfs_btree_visit_blocks -> xfs_btree_read_buf_block`) issues a **bmbt readahead** (inc count at `xfs_buf_readahead_map`, pal/linux/xfs_buf.c:879), then the SAME lookup path synchronously reads the same bmbt block via `_xfs_buf_read`, which CLEARS `XBF_READ_AHEAD` while the buffer is still counted. The eventual `__xfs_buf_ioend` sees `XBF_READ_AHEAD` clear and SKIPS the `percpu_counter_dec` (it's gated on the flag) → leak → unmount spins forever. Proof probes: `P-RA-CLEAR-AT-BUFREAD daddr=<bmbt> ops=xfs_bmbt comm=touch` + stack through `mxfs_dir_bmbt_invalidate_stale`/`xfs_iread_extents`, and `P-RA-DECSKIP-IOEND` (kworker). (Diagnostic note: a global RAT tracking array showed false outstanding=0 due to bp-pointer reuse hiding the leak — percpu counter is the source of truth.)

**FIX (build CE6B0445, `_xfs_buf_read` in pal/linux/xfs_buf.c ~668):** when `_xfs_buf_read` finds `XBF_READ_AHEAD` set (a counted readahead being converted to a sync read), `percpu_counter_dec(&bp->b_target->bt_readahead_count)` to settle the accounting. Pairs exactly with the inc; the re-submitted read completes with ra clear and won't double-dec. Marker log `P-RAFIX-BUFREAD` (rate-limited). All heavy diagnostics stripped; tree is fix-only and builds clean.

### NEXT SESSION
1. Deploy CE6B0445: `bash scripts/cluster_reset_n.sh 16` (confirm srcversion CE6B0445 on all).
2. `INSMOD_OPTS="dirwr=1" ./tests/criteria/zero_silent_loss.sh --iters 3 --dpn 100 --mode 1` — confirm NO umount wedge (all 3 iters complete = 3/3) and grep dmesg for `P-RAFIX-BUFREAD` (should fire, no wedge).
3. If 3/3 complete, the remaining failure is the dir-block lost-update (silent ~3-9/iter, `CREATOR_MISSING creator_errs=[none]`). That's the next root to chase (RULE 4) — see [[sess65-zsl-dlm-handoff-metadata-coherency-root]], [[sess60-zsl-writer-releases-inconsistent-dinode-bmbt]].
4. Other failing criteria still open: fence_during_write (lost=400), posix_semantics_multi16 (>600s), rsync_paired (148%).

### Cluster reset note
Multi-iter runs leave PR-reservation/wedge residue; always `scripts/cluster_reset_n.sh 16` (full virsh destroy/start) before trusting results. Single-iter zsl leaves the FS mounted (no inter-iter umount) so it doesn't expose the wedge.
