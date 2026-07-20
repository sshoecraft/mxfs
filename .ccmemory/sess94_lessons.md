---
name: sess94_lessons
description: sess94 — fua_disable=1 now DEFAULT (eliminates 45x slowness + a CLASS of read corruption; clean run hit passed=2 fast). But PARTIAL: dialloc EFSCORRU…
metadata:
  type: project
---

# sess94 (2026-06-05, ccloop run 29df431e)

## WIN (KEEP): fua_disable=1 is now the module DEFAULT
`int mxfs_fua_disable = 1;` (xfs_mxfs_dlm.c:5562). On the SCST target, SCSI-FUA
reads return the UN-DESTAGED platter (BEHIND the shared write-back cache where a
peer's just-committed write lives) → FUA reads are actively STALE here. Disabling
FUA routes reads through the coherent shared cache.
- MEASURED clean run (build 354813F9): rename_visibility 372s+SHUTDOWN → 8s, NO
  shutdown; cache_coherency passed=2 (cross_visibility + rename_visibility PASS),
  fast. This is the best+healthiest state in many sessions.
- This is the "NON-FUA coherency mechanism" sess43 said was needed (sess43 found
  FUA-reread dir-coherency "fundamentally too slow at scale", 180s timeouts).

## BUT IT'S ONLY PARTIAL — the dominant shutdown PERSISTS with FUA fully OFF
HIGH run-to-run VARIANCE: one clean run = passed=2 fast/no-shutdown; the very next
(build 7B2C2B6D) = passed=1, rename 127s barrier-timeouts, **test2 SHUT DOWN at
153s with the SAME `xfs_dialloc` EFSCORRUPTED** as FUA-on:
`P-CREATE-ERR1 dialloc/icreate err=-117 ... P-CR62 new_ino=0 agno=0 err=-117
disk_di_mode=0177777 disk_di_gen=0 verdict=disk-read-err/badmagic` →
`xfs_trans_cancel line 1060 Caller xfs_create` → SHUTDOWN_CORRUPT_INCORE.
So fua_disable does NOT fix the dialloc corruption — the passed=2 run was variance/luck.
- P-CR62 `new_ino=0` ⇒ **xfs_dialloc itself returned -EFSCORRUPTED** (it never
  selected an inode; the 0xFFFF "badmagic" is just P-CR62 reading nonexistent ino 0).
- **NO xfs verifier/corruption_error message precedes P-CREATE-ERR1** ⇒ it's a
  LOGICAL `XFS_IS_CORRUPT(i!=1)` check inside dialloc (xfs/libxfs/xfs_ialloc.c has
  ~30 such), NOT a buffer-verifier failure. Likely AGI/inobt/finobt inconsistency
  (fresh AGI says inodes free, a cached-or-torn inobt/finobt disagrees).
- test1's other shutdown is at UNMOUNT only: SB summary counter ifree/icount=0
  mismatch failing xfs_sb_write_verify — SEPARATE, lower priority (P62-SBCLAMP).

## DISPROVEN this session (RULE-4 step 2a)
**Shortform-dir cached-EX fast-path lost-update** (my hypothesis): added field
`i_dlm_dir_loaded_gen` (xfs_inode.h:115) + set it at reload-OK + detection probe
`P-SFDIR-STALE-RMW` in the fast path (xfs_mxfs_dlm.c, by P-SFDIR-FASTEX). Probe
fired **0×** on all nodes. Reason: unlink_visibility's TESTDIR holds 120 files →
it is **BLOCK-format**, not shortform — the shortform fast-path can't apply. The
P-SFDIR-REVERT I'd seen was on ino=128 (.mxfs_test parent, shortform), a different
dir. The unlink lost-update is in the BLOCK-dir path. (The field + probe are
behavior-NEUTRAL — harmless to keep; loaded_gen is set but never read for control.)

## CURRENT BUILD = `7B2C2B6D` on all 4 nodes (fua_disable=1 default + the neutral
probe). Reverting the probe/field gives `354813F9` (fua default only). KEEP the
fua_disable=1 default regardless.

## REMAINING failures (clean passed=2 run, build 354813F9), both read-side:
- unlink_visibility: node2 cannot delete its OWN files (`rm: No such file`); 30/30
  dirents lost; post-check "0 remain" passes ⇒ DURABLE clobber by peers' concurrent
  BLOCK-dir writes (shared-dir lost-update, block format).
- cross_write_read: `Node2 verifies node1 integrity expected=<md5> actual=''` —
  node2 reads node1's reg-file as EMPTY (stale in-core data buffer / invalidation gap).

## NEXT (RULE-4: get the dialloc failure SITE first — it's the dominant shutdown)
1. Instrument the EXACT `XFS_IS_CORRUPT` in xfs_dialloc that returns -EFSCORRUPTED
   (xfs_ialloc.c: xfs_dialloc_ag_inobt 1177 / finobt_near 1461 / newino 1571 /
   update_inobt 1623 / xfs_dialloc_ag 1671 / good_ag 1827 / try_ag 1900). Dump
   agno, agi free counts, inobt/finobt lookup i-values, buffer freshness. WHY no
   xfs_corruption_error printed? (maybe a path that returns EFSCORRUPTED w/o
   XFS_IS_CORRUPT, or ratelimited.) This is the missing piece — we've never had the
   exact dialloc failure line.
2. If it's AGI/inobt inconsistency: check whether mxfs_dlm_invalidate_ag_meta
   (xfs_mxfs_dlm.c:6735, walks pag->pag_bcache via rhashtable_iter, stales all
   AG-meta b_ops) MISSES an inobt/finobt block (rhashtable_iter can skip during
   resize; or block not yet cached at acquire → read fresh but torn). P14-INSTR in
   the failing run staled only agi/agf for the AG (inobt/finobt not cached).
3. This dialloc corruption is independent of FUA (persists with FUA off) ⇒ it's
   cached-buffer-invalidation or a WRITE-side AG-inode corruption. Good candidate
   for a Gemini consult (RULE-5) with THIS sharp narrowing (FUA-off, logical
   dialloc EFSCORRUPTED, no verifier msg) — a genuinely new framing vs prior
   FUA-stale/bnobt consults.
4. Then the block-dir lost-update (unlink) + reg-file empty-read (cwr).

## INFRA (verified sess94 — all still true; see also sess93)
- `make clean` WIPES tools/ binaries → MUST `make tools` after, else reset4
  MKFS_FAIL / "Structure needs cleaning". Changes spanning .c+.h need clean build.
- srcversion is NOT a stable cross-session ID (hash quirks). Verify fixes via
  `strings mxfs.ko | grep <probe>`.
- INSMOD_OPTS="fua_disable=1" did NOT propagate via fresh_cluster_mount (param
  stayed 0). Use module DEFAULT or runtime `echo 1 >/sys/module/mxfs/parameters/fua_disable`.
- reset4 parallel-join RACE: a joiner racing test1's live dirty XFS log replays it
  → "Structure needs cleaning" mount fail (intermittent, random node). Clean virsh
  reboot ALL 4 + retry reset4 wins. (Real join-time log-recovery gap, not the blocker.)
- Clean reboot ALL 4: `sudo virsh -c qemu:///system destroy testN && start testN`,
  wait 65s, `bash tests/reset4.sh 4`. Slots t1=0 t2=3 t3=1 t4=2; ~20 AGs; mount
  /mnt/shared dev /dev/sda. /tmp/.mxfs_pass persists on HOST. Run cache_coherency:
  `( ./tests/criteria/cache_coherency.sh --nodes 4 >/tmp/cc.log 2>&1; echo EXIT=$? >>) &`
  then until-grep EXIT=. Detail log in RESULT reason=. Per-node assertions:
  /home/steve/.mxfs/results/<ts>/test_<name>/nodeN.log. dmesg persists across rmmod.
- Standalone `run_tests.sh --test ...` FAILS (rc=127/path): needs /mnt/mxfs-src test
  staging that only the full cache_coherency.sh does. Use the full criterion script.
