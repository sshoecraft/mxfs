---
name: sess67-zsl-root-stale-cached-bmbt-leaf-not-write-clobber
description: sess67: zsl ROOT REFRAMED+PROVEN via P34B FUA-readback — disk leaf is CORRECT, reader uses STALE cached bmbt leaf that survives reload eviction; sess…
metadata:
  type: project
---

# sess67 (ccloop 14d31183) — zero_silent_loss ROOT REFRAMED & PROVEN; sess66 fix theory REFUTED; HOST WEDGED at end

zsl STILL FAILS (total_fs_silent=1600, FS shuts down). But this session DECISIVELY reframed the root with a direct FUA-readback probe, refuting the sess66 write-clobber theory and a FUA-read fix theory.

## DECISIVE EVIDENCE (P34B-BMBT probe, dirwr=1)
Enabled `dirwr=1` (via prep insmod) so the sess34 P34B probe fires: it does a direct SCSI **FUA read** of each bmbt block during `xfs_iread_bmbt_block` and compares to the cached buffer.
Result on the storm dir (ino=131, leaf daddr=22960848, level=0):
```
P34B-BMBT-STALEREAD ino=131 daddr=22960848 level=0 cached_recs=14 disk_recs=18 bflags=0x20   (test16)
P34B-BMBT-STALEREAD ... cached_recs=18 disk_recs=19 ...                                       (test9)
P34B-BMBT-STALEREAD ... cached_recs=19 disk_recs=20 ...                                       (test1)
```
- `STALEREAD` = the cached buffer is CLEAN (no uncheckpointed mods; bflags=0x20 = XBF_DONE only, NOT pinned/dirty/delwri/in_ail) and its content (cached_recs) is BEHIND the platter (disk_recs via FUA).
- **The on-disk bmbt leaf is CORRECT and matches di_nextents** (disk_recs=18 == if_nextents=18). The DISK IS NOT TORN.
- The reader (`xfs_iread_extents`) walks the **STALE CACHED leaf** (14) → `ir.loaded=14 != if_nextents=18` (di, freshly reloaded) → P59-IREAD-MISMATCH → EFSCORRUPTED → FS shutdown → the whole 1600-dirent cascade.

## What this REFUTES
1. **sess66 write-clobber theory (xfsaild writes stale leaf over peer's durable leaf) — REFUTED.** The disk leaf is the LATEST/correct image, not clobbered. The tenure WRITE-gate (`mxfs_dir_bmbt_track` + extended `mxfs_buf_xfsaild_skip_bmbt_write`) attacks the wrong side; build 88688A48 still fails identically. P66-LEAFWRITE shows different nodes writing different numrecs to the shared daddr, but the LAST/durable one is correct — the harm is the stale READ, not the write.
2. **FUA-read fix — REFUTED.** Set `fua_disable=0` (default is `mxfs_fua_disable=1`): zsl STILL fails, P59 unchanged. Reason: a CLEAN **XBF_DONE cached buffer is returned with NO I/O** — the FUA gate only applies when an actual read is issued. So FUA is irrelevant while the stale DONE buffer survives in cache. `bmbt` IS already in `mxfs_buf_needs_fua_read` (sess63).

## THE ACTUAL ROOT (proven by elimination)
The cached bmbt leaf buffer is STALE (behind disk) and **survives the reload-time eviction** `mxfs_dir_evict_bmbt_blocks` (called unconditionally for dirs at `mxfs_dlm_reload_inode` xfs_mxfs_dlm.c:5501, and in `mxfs_dir_drain_evict_data_blocks` gated need_iread). P59 REQUIRES a reload that purged iext (idestroy_fork) → so eviction WAS invoked, yet the clean-DONE stale leaf is still used by the next `xfs_iread_extents`. WHY it survives is the open question:
  - (a) the rhashtable walk (filtered bb_owner==ino) MISSES it (concurrent-walk skip), or
  - (b) at evict time it was transiently pinned/dirty/in_ail (eviction `if` at xfs_mxfs_dlm.c:753 requires !pinned !dirty !delwri (!in_ail||!undestaged)); the 50-iter/2ms bounded unpin wait isn't enough; it later settles clean-DONE and the reader uses it, or
  - (c) after eviction clears DONE, a plain-bio re-read (fua_disable=1) re-populates it stale from SCST per-initiator cache, marking _XBF_FUA_FRESH so the FUA gate then skips. (But fua_disable=0 also failed → leans (a)/(b).)

## INSTRUMENTATION BUILT (build 3AC3BF09, NOT YET OBSERVED under storm)
Added to `mxfs_dir_evict_bmbt_blocks` (xfs_mxfs_dlm.c), gated dirwr/instr:
- `P67-BMBT-EVICT-ENTER ino nheld need_iread` (after held[] built) — does the walk FIND the leaf?
- `P67-BMBT-EVICT-SKIP ino daddr DONE pin dirty in_ail delwri undestaged flags` (else-branch when NOT evicted) — WHY skipped?
Plus existing `P59-BMBT-EVICT` (success). NEXT SESSION: run storm with dirwr=1, grep P67-* for ino=131 leaf daddr to settle (a) vs (b). If walk-miss → make eviction robust (re-walk / lookup by daddr from broot ptrs). If transient-pin → the leaf is THIS node's obsolete prior-tenure pinned image; can't clear DONE on pinned (sess64) → need to discard/replace it another way (e.g. overwrite cached content from broot-pointed FUA disk read at consume point in xfs_iread_bmbt_block).

## HOW TO GET P34B/P67 PROBES
`dirwr=1` module param (writable 0644). prep insmods first so storm's `insmod dirwr=1` is a no-op — set dirwr via prep insmod OR sysfs `/sys/module/mxfs/parameters/dirwr` after mount. (This session temporarily edited prep then REVERTED it to clean `insmod "$MODULE"`.) P34B does a FUA read per dir-bmbt-block read (perf cost; diagnostic only).

## ⚠️ HOST WEDGED AT SESSION END (RULE 2 — user action required)
The test cluster's shared LUN wedged at clyde's kernel level: 20→90 `iscsi_conn_cleanup` threads in **D-state** (uninterruptible); every serialized SCSI cmd (CAW, PR REGISTER) blocks forever in EXEC_CHECK_BLOCKING. `sg_persist --register-ignore` returns rc=1; mkfs/mount get `reservation conflict` / "Invalid exchange"; mount hangs D-state; test1 qemu briefly unkillable. A stale SCSI PR (WE-RO, holder key 0x5551fe5c, 16 keys) cannot be cleared because register itself fails. `systemctl restart scst` HUNG (rc=124) → scst now "deactivating". This is EXACTLY the documented wedge in `scripts/clyde_boot_recover.sh` ("only a host reboot clears kernel-thread state"). **Per CLAUDE.md RULE 2, recovery of the HOST is the user's call only — a manual reboot of clyde is required.** After reboot, the @reboot `clyde_boot_recover.sh` re-establishes iSCSI; then `scripts/cluster_reset_n.sh 16` for a clean cluster.

Links: [[sess66-zsl-bmbt-leaf-xfsaild-clobber-tenure-gate]] [[sess62-zsl-bmbt-leaf-write-never-submitted-confirmed]] [[sess60-zsl-writer-releases-inconsistent-dinode-bmbt]] [[sess50-infra-iscsi-recovery-and-mkfs-busy]]
