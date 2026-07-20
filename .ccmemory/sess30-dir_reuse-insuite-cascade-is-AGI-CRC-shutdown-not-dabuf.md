---
name: sess30-dir_reuse-insuite-cascade-is-AGI-CRC-shutdown-not-dabuf
description: sess30(ccloop) PROVEN (RULE 4, prefix repro): dir_reuse 8/tcp in-suite cascade root = AGI EFSBADCRC shutdown in xfs_inactive_ifree during rm-rf mass…
metadata:
  type: project
---

## sess30 — dir_reuse 8/tcp in-suite cascade root PROVEN = AGI CRC shutdown

### RULE-4 reproduction (build F449AACE, winning modargs, prefix-to-dir_reuse run, NO fault tests so dmesg survived)
dir_reuse FAIL 0/8 in-suite. The kmsg signature `mxfs-drc-FAIL readdir=0 exp=800 lookup_fail=0 missing=[]` is MISLEADING: the test's lookup loop reads names FROM `ls "$D"` (readdir output), so readdir=0 ⇒ loop runs 0× ⇒ lookup_fail=0/missing=[] automatically. The ONLY real signal = `ls "$D"` returns 0.

**`ls /mnt/shared` returns Input/output error → the FS SHUT DOWN.** readdir=0 is pure downstream EIO.

### Actual shutdown trigger (test1, t=303s, during round-8 rm-rf mass inode-free):
```
mxfs: P82-ADD ino=87xx agno=0 ... (flood of iunlink-bucket adds, sync-inactive freeing 800 inodes in AG0)
XFS (sda): metadata I/O error in "xfs_read_agi+0x11f" at daddr 0x2 len 1 error 74
XFS (sda): Metadata I/O Error detected at xfs_inactive_ifree+0x2e9 (xfs_inode.c:2653). Shutting down filesystem.
```
daddr 0x2 = AGI of AG0. error 74 = EFSBADCRC. This is the long-documented **"AGI CRC shutdown in ifree (flaky, in-FULL-suite only)"** — the sess22/sess39/sess45 AG-meta-corruption family. dir_reuse's rm-rf+recreate (800 inodes × 24 rounds, all 8 nodes hammering AG0) exposes it most → EIO cascades into fence/fault/soak/tcp_dlm_scaling (all 0/8).

### sess22 prior diagnosis (still the lead): AGI content structurally VALID, only on-disk CRC wrong
So an AGI was written with a stale/incorrect CRC OR a node read a torn/corrupt block. BUT this session confirmed: AGI is NEVER FUA-written (only dir blocks use mxfs_pal_scsi_write_fua_bdev @ dlm.c:1834); normal AGI writes run xfs_buf_verify_write → correct CRC. So the bad-CRC source is NOT a verifier-skipping write in our tree. Candidates to instrument next: (a) concurrent in-core AGI modify during the write DMA window; (b) torn/stale FUA read at the LIO target under 8-node AG0 contention; (c) a node writing AGI mid-modify. NEED a probe on daddr 0x2: log write-CRC + read-verify-failure on-disk-CRC vs recomputed.

### zero_silent_loss: FLAKY, not a hard bug — PASSED 8/8 in the prefix run (failed 0/8 in the full8 run). Isolated (no cascade).

### crash_consistency: FIXED this session (ABBA), PASSED 8/8 in-suite TWICE now. See [[sess30-FIX-crashconsist-ABBA-flush-snapshot-relsafe]].
Repro tool: tests/tcp/prefix_dirreuse.sh (reboot + 13-test prefix, dmesg survives). See [[sess22-AGI-crc-shutdown-ifree-fua-write-no-crc]].
