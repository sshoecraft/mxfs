---
name: sess-tcp-2node-three-root-fixes
description: 2-node dlm=tcp: 3 PROVEN root fixes (DLM deny-status, FUA-read fallback, verify-fail coord) — basic cross-node create+read now 100% on first try. Bui…
metadata:
  type: project
---

## Goal
Criteria: **2-node `dlm=tcp` test 100% successful** = every test in `./showstat.sh 2 tcp`
PASS (see [[test-status-showstat]]). Storage = LIO/tcm_loop write-through, TCP DLM
(force_transport=1). Cluster = test1 (forms) + test2 (joins).

## Starting state (this run)
Deployed build `305641B7` crashed the kernel on the FIRST 2-node create:
`P-DIALLOC dp=128 err=1 ino=0` → `P-CREATE-ERR1` → `P-CR62 ... disk_di_mode=0177777
verdict=disk-read-err/badmagic` → `BUG: NULL deref do_open+0x60` (RAX=-EISDIR).

## THREE PROVEN ROOT FIXES (build A70942DB, KEEP)

### FIX 1 — DLM NOQUEUE deny returns positive MXFS_ERR_DEADLOCK (the crash). `dlm/dlm.c`
`xfs_dialloc` first pass uses XFS_ALLOC_FLAG_TRYLOCK → `mxfs_ag_dlm_trylock` →
`mxfs_v5_dlm_ag_lock_nb` → TCP `mxfs_dlm_lock(...,NOQUEUE)`. When a REMOTE master
denies (peer holds the AG), `process_remote_request` sends status `MXFS_ERR_DEADLOCK`
(enum = **1**, `include/mxfs/mxfs_common.h`). `dlm_lock_impl` returned that +1 verbatim;
`ag_lock_nb` only mapped `-EWOULDBLOCK`→`-EAGAIN`, so +1 propagated into `xfs_dialloc`
as `err=1`. Since `1 != -EAGAIN`, the allocator treated a busy peer-held AG as FATAL
instead of skipping to the next AG → create fails → do_open NULL-deref.
**Fix:** in `dlm_lock_impl` remote-status path, translate `MXFS_ERR_DEADLOCK`→`-EAGAIN`,
any other positive→`-EIO`. Never leak a positive protocol code to the kernel.

### FIX 2 — SCSI FUA read rejected by LIO/tcm_loop. `pal/linux/kern.c` + `pal/linux/xfs_super.c`
`tools/fua_verify` proved the target rejects READ(16)/WRITE(16)+FUA:
`sense key 5 (ILLEGAL REQUEST) ASC 0x24 (invalid CDB)`. mxfs cross-node coherency
re-reads metadata via `mxfs_pal_scsi_read_fua_bdev`; the rejection returned -EIO →
dmesg `fua_disk_mode=0xffffffff` → misread as inode corruption → EFSCORRUPTED.
Backstore is write-through (emulate_write_cache=0) so a plain bio read is already
coherent. **Fix:** `mxfs_pal_scsi_read_fua_bdev` latches a static `mxfs_fua_read_unsupported`
flag on ILLEGAL_REQUEST (or non-SCSI dev) and falls back to `mxfs_pal_bdev_read_plain_bdev`.
Plus a one-shot mount-time FUA probe in `xfs_fs_fill_super` (right after envelope setup)
so the flag latches BEFORE any real I/O (otherwise the first real read fails before the
latch). On a real FUA-capable target (SCST) the passthrough succeeds → fallback never engages.

### FIX 3 — reader verify-fail bypassed sess127 coordination. `xfs/xfs_icache.c`
New child inode's cluster isn't durable when peer first reads it (deferred-publish:
creator's child EX is LOCAL, nothing BASTs it). On SCST the stale read = valid free
dinode (mode==0 → -ENOENT → sess127 PR-reload fires). On TCP/LIO the stale on-disk
cluster fails `xfs_dinode_verify` → `-EFSCORRUPTED` at `xfs_inode_from_disk`, which
`goto out_release_dlm` BEFORE reaching sess127's `error==-ENOENT` recovery → first read
returns EFSCORRUPTED (self-heals ~18s later on a later access). **Fix:** in
`xfs_iget_cache_miss`, after the from_disk verify-fail (ip is still pristine — from_disk
bails at the verifier before mutating forks), run the SAME coordinated
`mxfs_dlm_ilock_begin(PR)+mxfs_dlm_reload_inode(...,false)+ilock_end`; if `i_mode!=0`
after, clear error. Guard: `error && !tp && !dlm_acquired && !XFS_IGET_CREATE && multi-node`.
Probe: `P-TCP-VERIFY-COORD`.

## ALSO (cleanup, KEEP)
- Reverted the sess73 diagnostic busy-spin ILOCK acquire in `xfs/xfs_inode.c` (was
  `while(!down_write_trylock(&ip->i_lock)) cond_resched()`, "revert after capture") back
  to standard `down_write_nested` — it distorted lock timing. Added a `P-DIALLOC` probe.

## Verified
`tests/setup/reset2_tcp.sh` (NEW, in-tree): clean 2-node TCP reset + cross-node create/read
smoke. Both directions PASS on FIRST read, no crash, clean dmesg. Build A70942DB on both nodes.
Reset budget ~40s wall (NOT 320 — RULE 0).

## NEXT
Run the full `./showstat.sh 2 tcp` matrix (16 tests). cache_coherency was the recorded FAIL;
re-run it + the other coordinated P2/P3 tests. A crash leaves a node wedged (mount busy,
rmmod fails, self-fence on next mkfs) — recover with `virsh -c qemu:///system destroy/start`
both nodes (see [[reference-node-power-control]]) before re-deploying.
</body>
