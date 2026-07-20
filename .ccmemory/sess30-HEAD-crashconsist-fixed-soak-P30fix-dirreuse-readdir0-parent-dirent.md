---
name: sess30-HEAD-crashconsist-fixed-soak-P30fix-dirreuse-readdir0-parent-dirent
description: sess30(ccloop) HEAD: crash_consistency ABBA FIXED (verified 8/8). 4/tcp=16/17 (only soak, a no-buf-ops dump_stack; P30 fix added). 8/tcp dir_reuse=0/…
metadata:
  type: project
---

## sess30 HEAD — where the next session starts

### CRITERIA `./run.sh {1,2,4,8} tcp` 100% — NOT MET. Build under test: **04A615EE** (from F449AACE from keeper).
Winning modargs (levers still default-0; pass via MXFS_EXTRA_MODARGS): `dir_gen_per_handoff=1 dir_modify_extent_adopt=1 dir_release_invalidate=1 dir_relinval_clean=1`

### WINS this session
1. **crash_consistency ABBA hang FIXED** (build F449AACE) — verified PASS 8/8 IN-SUITE on 3 runs. Snapshot-daddrs-under-i_lock then flush without i_lock (`mxfs_dir_flush_data_blocks_relsafe`/`mxfs_dir_flush_one_daddr`). See [[sess30-FIX-crashconsist-ABBA-flush-snapshot-relsafe]]. This was sess21/29's PRIMARY 8/tcp wall.
2. **4/tcp = 16/17** (build F449AACE): only `soak` FAIL. Root: a rare `xfs_buf_verify_write: no buf ops on daddr` on an INODE buffer (mxfs reload/FUA left b_ops==NULL; xfsaild delwri-flushes it) → `dump_stack()` → trips soak's DPAT `call trace` → FAIL. Content benign (inode di_crc stamped at iflush). **FIX (build 04A615EE, pal/linux/xfs_buf.c)**: `mxfs_buf_ops_from_magic()` re-derives the verifier from on-disk magic in `xfs_buf_verify_write` when b_ops==NULL on a CRC fs → stamps CRC, no dump_stack. P30-OPS-RECOVER probe logs it. (Verifying on full4 now.)

### 8/tcp dir_reuse_coherency = 0/8 IN-SUITE (the deep 130-session blocker) — TWO flaky faces:
- **Face A (build F449AACE run): AGI EFSBADCRC shutdown** in xfs_inactive_ifree (daddr 0x2, err74) during round-8 rm-rf mass inode-free → EIO cascade. See [[sess30-dir_reuse-insuite-cascade-is-AGI-CRC-shutdown-not-dabuf]]. **P30 ops-recover did NOT fire for AGI (count=0) so the AGI bad CRC is NOT a no-buf-ops write** — mechanism still unconfirmed (torn read / concurrent modify?). sess22 says content valid, CRC wrong.
- **Face B (build 04A615EE run): readdir=0 with NO shutdown, FS healthy.** PROVEN: `mxfs-drc-FAIL readdir=0 exp=800 lookup_fail=0 missing=[]` + `drc-DIRID dirino=` EMPTY ⇒ **`stat "$D"` returns ENOENT — the directory `$D` (/mnt/shared/.dir_reuse_coherency) does not exist at verify time.** So after rank1's rm-rf+recreate churn (~15 rounds, 800-file mass-free each), the ROOT dir's dirent for ".dir_reuse_coherency" is LOST/incoherent on cold reload (drop_caches). NOTE: the test's `lookup_fail`/`missing` are USELESS (the loop reads names from `ls "$D"` itself, so readdir=0 ⇒ both auto-0). Bare rm-rf+recreate of an EMPTY dir is coherent (live test: all nodes see same ino across 3 cycles) — needs the 800-file churn + many rounds to break.

### NEXT (RULE 4)
- Confirm soak fix on full4 (expect 17/17). Then verify 1/tcp, 2/tcp (likely pass).
- dir_reuse Face B: instrument the ROOT-dir lookup/readdir of ".dir_reuse_coherency" after rm-rf+recreate churn — why does stat $D ENOENT on a healthy FS? (parent shortform/block dirent lost-update under remove+recreate, inode-reuse incarnation). Reproduce with a focused 8-node create-load+recreate loop watching live kmsg (stale /root/drc_*.dmesg files have CONFUSING interleaved round numbers — capture live, don't trust them).
- dir_reuse Face A (AGI CRC): needs a daddr-0x2 write-CRC + read-fail-CRC probe to find the bad-CRC write origin (NOT a no-buf-ops write).
Tools: tests/tcp/prefix_dirreuse.sh (reboot + 13-test prefix to dir_reuse, NO fault tests so dmesg survives). full8.sh N "MODARGS". Backups: xfs_mxfs_dlm.c.backup-sess30.
