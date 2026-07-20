---
name: sess22-progress-two-fixes-and-reuse-corruption-chain
description: sess22: 2 fixes landed (torn-SF flush skip + data-scan lookup fallback); remaining = ino-131 REUSE corruption chain (torn SF + bad-CRC data block) on…
metadata:
  type: project
---

## sess22 progress (build 4F45F442) — dir_reuse_coherency 2/tcp clean-slate

### FIX 1 (LANDED, PROVEN to prevent the iflush shutdown): torn-shortform flush skip
xfs/xfs_inode.c xfs_iflush, the `xfs_ifork_verify_local_data` fail branch (~4355): for a multi-node DIR, on shortform verify-fail do NOT `xfs_force_shutdown(CORRUPT_INCORE)` — set error=0, mark XFS_ISTALE_CAW, `goto flush_out` (skip cleanly + cold-reload). Detector `P22-SFTORN-SKIP`. PROVEN: caught a torn SF flush (`comm=rm dlm_mode=EX dirty_seq==ex_grant_seq if_bytes=22 hdr=[01 01 00 ...]` = count=1 i8count=1 garbage for small inodes) and prevented that shutdown.

### FIX 2 (LANDED, UNTESTED — shutdown hit first): authoritative data-scan lookup fallback
xfs/libxfs/xfs_dir2_leaf.c: new `mxfs_dir2_datascan_lookup()` + hook in `xfs_dir2_leaf_lookup` — on hash-lookup ENOENT for a multi-node dir, linearly scan the AUTHORITATIVE coherent data blocks (returns xfs_dir_cilookup_result => -EEXIST→0). Detector `P22-DATASCAN-HIT`. Targets the deterministic leaf-hash hole (node2_f50.md5, the LAST entry, every round). Only runs on ENOENT (no hot-path cost).

### REMAINING BLOCKER: ino-131 REUSE corruption chain (clean slate, round 2)
Round 1 PASSES; the FS shuts down during round-1 rm-rf teardown / round-2 mkdir REUSE of dir ino 131 (.dir_reuse_coherency, parent=root 128). THREE corruptions share this window:
1. Torn in-core shortform fork (FIX1 now skips the flush).
2. **Bad-CRC on-disk dir DATA block** at daddr 0x78 (ino 131 data block 0): `Metadata CRC error (error 74 EFSBADCRC) at xfs_dir3_data_read_verify, xfs_dir3_data block 0x78` → SHUTDOWN. PRE-EXISTING (FIX1 unmasked it by letting the FS limp past the torn-SF shutdown). A dir data block reaches disk with a bad CRC after daddr reuse.
3. Leaf-hash hole (FIX2 targets it).

### Mechanism (strong hypothesis, not yet root-fixed)
rm wants EX on ino 131 → `DLM inode lock failed: ino=131 mode=5 rc=-35` (EDEADLK, P109 conversion-deadlock prevention) → ilock hook (xfs_mxfs_dlm.c ~8435) releases via BAST drain + reacquires from NL → reacquire RELOADs ino 131 (`mxfs_dlm_reload_inode`: P62-RELOAD-FORK-SHRINK post_release=1, P34D-RELOAD-FRESHSRC src=plain, P91-RELOAD-PROTECT) adopting a mid-reuse-inconsistent disk image → in-core fork corrupt (torn SF) AND/OR a bad data block written. P78-FMT-TORN-FIX storms on ino 131 (EXTENTS nx=3) in xfsaild throughout.

### NEXT
Root-cause the SHARED reuse-corruption mechanism (reload adopting torn/inconsistent image during EDEADLK release/reuse; how daddr 0x78 gets a bad on-disk CRC — plain-bio write bypassing verifier? daddr double-alloc? torn write?). Likely the deep daddr-reuse double-alloc family (see sess20/sess39/sess42/sess47 memories). Keep FIX1+FIX2. Then re-test clean slate (`bash tests/reboot_cluster.sh 2; MXFS_TEST_ENV="DRC_ROUNDS=15" timeout 460 ./run.sh 2 tcp dir_reuse_coherency`).

### NOTE: run.sh "PASS" print can disagree with per-node `RESULT: FAIL` — trust the per-node RESULT lines + dmesg, not the run.sh summary line.
</body>
