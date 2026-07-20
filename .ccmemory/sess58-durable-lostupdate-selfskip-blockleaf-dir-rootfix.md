---
name: sess58-durable-lostupdate-selfskip-blockleaf-dir-rootfix
description: sess58 PROVEN ROOT+FIX (build 6657565C): zero_silent_loss durable dirent loss = P36-RELOAD-SELFSKIP kept stale BLOCK/LEAF dir base on post-release re…
metadata:
  type: project
---

# sess58 — durable dirent lost-update PROVEN ROOT + FIX (block/leaf dir reload self-skip)

## The criterion
`zero_silent_loss` (16-node × 100dpn mkdir storm into a shared dir). Real failure =
durable dirent lost-update (NOT the dir2 di_size corruption, which was a stale-dmesg
artifact — see [[sess58-dir2-corruption-was-stale-dmesg-artifact]]). A node's mkdir'd
subdirs vanish from the shared parent, invisible even to their creator.

## PROVEN root (RULE 4, two always-on probes, build 8E707B59)
1. `P58-STALE-BASE-ADD` (xfs_dir2.c, xfs_dir_createname_args, fires when
   `i_dlm_dir_gen > i_dlm_dir_loaded_gen` at add time): captured
   `pino=131 add=[node9_dir95] fmt=2 dir_gen=109 loaded_gen=12 self_created=0 reload_flag=0`
   — the shared dir's in-core blocks were loaded at gen 12 while peers had advanced it to
   gen 109. The RMW + release-drain writes that 97-generation-stale base back, durably
   ERASING every peer dirent committed in between.
2. `P58-SELFSKIP-STALE-DIR` (in the P36-RELOAD-SELFSKIP branch of mxfs_dlm_reload_inode):
   `ino=131 fmt=3 dir_gen=379 loaded_gen=323 in_ail=0 dirty=0 fields=0x4000 pin=1
   self_created=0` — the reload SELF-SKIPPED because the dir had own log mods in flight,
   keeping the stale base. loaded_gen is frozen because it only advances on a COMPLETE
   refresh, which the self-skip prevents.

The sess49 fix ("skip-the-skip" so a dir reload isn't suppressed by own-mods-in-flight)
was scoped to SHORTFORM (LOCAL-format) dirs only. BLOCK/LEAF dirs fell through → kept the
stale base → clobber. The shared mkdir-storm dir grows to block/leaf, so it hit the gap.

## THE FIX (build 6657565C, NOT yet verified at handoff)
`mxfs_dlm_reload_inode` gained a `bool post_release` param (header xfs_mxfs_dlm.h:194).
Self-skip guard now: `mxfs_dir_disk_superset = S_ISDIR && (if_format==LOCAL || post_release)`;
skip only when `!mxfs_dir_disk_superset && own-mods-in-flight`. Rationale: a POST-RELEASE
reacquire (slow-path from-NL grant) drained our blocks at release (Invariant 1), so on-disk
is a strict SUPERSET (our entries + the peer's) → reloading a dir cannot lose our work.
The sess36 regression (in-flight dir-grow rolled back) was a SAME-TENURE FASTEX refresh,
which keeps post_release=false → keeps the skip → no regression.

Call sites set: xfs_mxfs_dlm.c:1196 consumer_refresh(reader)=true, :5579 fastex=FALSE,
:5942 slow-path acquire=TRUE; xfs_dir2_readdir.c:558 reader=true; xfs_inode.c:875,1010 iget
=false (preserve); xfs_icache.c ×5 =false (preserve). Only the proven slow-path EX-acquire
site changes behavior for block/leaf dirs.

## Repro / verify
FAST repro: `./tests/criteria/zero_silent_loss.sh --iters 1 --dpn 100 --mode 1` (~90s,
iter1 reliably showed silent=11..1600 pre-fix). `tests/repro_dirent_loss.sh 16 R` (1
file/node) is TOO LIGHT — rarely fires. `tests/repro_dirent_loss_heavy.sh` (mkdir K/node)
written but also under-reproduces vs the storm's fresh-mount-per-iter. Use the single-iter
storm. ALWAYS `dmesg -C` on ALL 16 nodes (reset4 only reboots wedged nodes) + full
destroy+start all 16 for a clean slate before trusting results.

## NEXT (sess59)
1. Deploy 6657565C (reset4.sh 16; verify srcversion; dmesg -C all). 2. Run single-iter
storm ×3 — confirm silent=0 each AND P58-STALE-BASE-ADD / P58-SELFSKIP-STALE-DIR stop
firing (or at least no loss). 3. If clean, run full `verify_ship.sh --keep-going` end-to-end.
Remaining open criteria: fence_during_write lost=400, rsync_paired 148%, posix_semantics_multi16 >600s.
Probes P58-* are always-on+rate-limited (low overhead) — keep for now, gate behind instr once fix confirmed.
</body>
