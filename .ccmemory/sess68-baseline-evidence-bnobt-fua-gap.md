---
name: sess68-baseline-evidence-bnobt-fua-gap
description: sess68 CORRECTED: symmetric v5 is at 3/4 (sess97/99635EAD), NOT a tar pit. ONLY blocker=unlink_visibility write-side dir-block handoff race. My bnobt…
metadata:
  type: project
---

# sess68 — CORRECTED frontier (supersedes my earlier bnobt-FUA hypothesis in this same file)

Companion to [[sess68-decision-reversal-stay-v5-port-mxfs1-coherency]]. Stay on v5 symmetric.

## ⚠️ MY EARLIER bnobt-FUA HYPOTHESIS IN THIS FILE IS REFUTED — do NOT chase it.
After reading [[sess94_lessons]][[sess95_lessons]] + sess96/sess97: `fua_disable=1` is the
DELIBERATE module default (sess94) because FUA-fresh reads caused 45x slowness + a CLASS of read
corruption. So the `fua_fresh=0` I saw is BY DESIGN, and the constant `P88-INSTR bnobt-WRITE-
low-numrecs disk_differs=1` is known instrumentation noise under fua_disable=1, NOT the blocker.
cross_write_read already PASSES on the good build — so the data-staleness invariants are met.

## ACCURATE CURRENT STATE: symmetric v5 is at cache_coherency 3/4, ONE blocker left.
Lineage: sess95 66A40A3D (3/4, P95 in-place reloads) → sess96 (typeflip dirent_ftype guard fix +
GPT 2-fence design) → **sess97 build `99635EAD` = cache_coherency 3/4** → sess67 EC07F422 =
99635EAD + INERT asymmetric scaffolding (carries all the fixes).
- PASS: cross_visibility, rename_visibility, cross_write_read.
- **FAIL: unlink_visibility ONLY** — durably loses ~1-2 of 80 concurrent distinct-dirent
  deletions; FAST 25s (perf fine). After settle ALL 4 nodes agree the file REMAINS = durable
  on-disk clobber, NOT cache divergence.
- My clean EC07F422 run got 2/4 (cwr ALSO failed, 1-3/6 borderline asserts) = the VARIANCE
  sess97 explicitly warns about ("trust ONLY cache_coherency.sh; back-to-back subtests give
  phantom cwr/cross_vis fails"). Re-run to confirm 3/4 before assuming a cwr regression.

## THE ONE BLOCKER — unlink_visibility = WRITE-SIDE dir-block handoff race (sess97 + GPT-5.5)
PROVEN it is NOT read/acquire-path (DIR-STALE-SKIP=0; acquire-evict skips all benign). A node
durably WRITES an OLD dir-block image AFTER the peer's deletion landed, via a path NOT gated by
the read/acquire/release fence. Mechanism: a non-releasing node's dirty/in-AIL/delwri/IN-FLIGHT
dir buffer (old image) reaches the shared store after the peer's newer write; the release fence's
durability predicate passes while a write is still IN-FLIGHT or _XBF_DELWRI_Q/XFS_LI_IN_AIL set.

## THE FIX (sess97 NEXT-SESSION plan, GPT-5.5 design) — implement this
Code sites (xfs/xfs_mxfs_dlm.c): RELEASE fence = `mxfs_dlm_bast_process` dir section ~L1247
(currently unbounded flush loop until mxfs_dir_data_durable); ACQUIRE fence =
`mxfs_dir_drain_evict_data_blocks` ~L520 (bounded 50 iters — keep bounded, do NOT add per-16
log_force SYNC, that caused 28s→155s unlink slowdown and did NOT fix it).
1. **Check-5 FIRST (cheap, verify before coding):** does CAW publish the DLM unlock/grant BEFORE
   the system_wq fence worker completes? Required order: BAST → block new local users → fence
   COMPLETE → publish unlock. If unlock publishes before the worker drains = the exact symptom.
2. At DLM EX release, for EACH dir buffer: **xfs_buf_lock it** (serialize vs in-flight I/O — do
   NOT judge durability from an unlocked flag snapshot), ensure NOT pinned / dirty-BLI / in-AIL /
   _XBF_DELWRI_Q / in-flight, THEN clear XBF_DONE. Do NOT xfs_buf_stale() live dir blocks; do NOT
   sever the BLI — drive normal IO completion. Force log ONCE per handoff (or xfs_log_force_lsn on
   max BLI lsn), batch via xfs_buf_delwri_submit.
3. Consider DEFER/batch inode inactivation off the dir-handoff path (unlink needs dirent-removal
   visible, not the inode fully freed) — also a perf lever. (INACT-SKIP-STALE fires a lot.)
DIAGNOSTIC to add if needed: trace every dir-block write submission (node, ino, daddr,
dlm-EX-held?, bp flags, delwri?, in-flight?, BLI dirty/in-AIL/pinned, lsn, caller). On failure
identify the LAST writer of the surviving block → pinpoints xfsaild-after-release vs late-async.

## VERIFY: clean reboot ALL 4 (virsh -c qemu:///system destroy+start, ~65s) → tests/reset4.sh 4 →
verify srcversion on ALL 4 → `cache_coherency.sh --nodes 4` (ONLY trustworthy test) → need
passed=4 → then full verify_ship.sh. Build spanning .c+.h needs `make clean && make modules`.
Other 11/12 ship criteria already PASS (.criteria_results.json); single_node 104% / rsync 103%.</body>
