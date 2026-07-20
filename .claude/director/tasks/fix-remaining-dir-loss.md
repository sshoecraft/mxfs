# Task: Investigate and Fix Remaining Directory Entry Loss (1/40)

## Context

We're running a concurrent two-node mkdir test: both test1 and test2 create 20 directories each in /mnt/mxfs/ simultaneously (40 total expected). After extensive debugging this session, we went from 0/10 passes to 9/10 passes. The last run showed 39/40 — one directory entry was lost.

## What's Already Been Fixed (DO NOT re-investigate these)

1. **Per-node XFS log slices** (Phase 5) — each node writes to its own 64MB XFS log slice. Fixed log grant starvation and large LSN divergence.
2. **Cross-node LSN check suppression** (Phase 6a) — `xfs_log_check_lsn` returns true when DLM is active. LSNs from different log slices are independent sequences. Fixed "Structure needs cleaning" errors.
3. **Directory data block cache invalidation** (Phase 6b) — `mxfs_dlm_reload_inode` stales the directory data block (block 0 of the data fork) after reloading the inode. Fixed stale block-format dir data.
4. **Stale-at-init** — `mxfs_dlm_inode_init` sets `i_dlm_stale = true` when DLM is active. First DLM acquire always reloads from disk. Fixed the mount-time stale state bug (test2 using empty dir from mount).
5. **Device flush in BAST** — `blkdev_issue_flush` after AIL push + inode cluster buffer stale + re-read in BAST handler. This was added as instrumentation and DISPROVED the storage flush hypothesis — storage writes are landing on disk correctly.

## Current State

- 9/10 concurrent mkdir runs pass (40/40 dirs)
- 1/10 shows 39/40 (one dir lost)
- Zero "Structure needs cleaning" errors
- Zero D-state hangs
- BAST flush verification always shows mem_size == disk_size (ok)
- Phase 6 instrumentation is still in the code (P6-INSTR prefix in dmesg)

## Your Task

Find and fix the cause of the 1/40 directory entry loss. Follow the methodology:

1. **Reproduce**: Run the 10-iteration concurrent mkdir test. If all 10 pass, run 10 more. You need a failure to investigate.

2. **Capture**: When a failure occurs (< 40 dirs), immediately capture:
   - `ls /mnt/mxfs/` from both test1 and test2 — which specific dir is missing?
   - `dmesg | grep P6-INSTR` from both nodes
   - `dmesg | grep -E 'BAST|reload|stale|error|warn'` from both nodes
   - Note: the last run's dmesg is only available if you DON'T reformat between runs

3. **Analyze**: Which specific directory name is missing? Was it from test1 or test2? What do the P6-INSTR logs show for that timeframe?

4. **Hypothesize**: Based on the data, form a specific hypothesis about why that one entry was lost.

5. **Instrument**: Add targeted logging to prove or disprove your hypothesis.

6. **Fix and validate**: Once proven, fix it. Run 10 iterations. Report pass rate.

## Important Notes

- The `blkdev_issue_flush` + buffer stale + re-read in the BAST handler is instrumentation, not a fix. It can be removed once the real fix is validated.
- The P6-INSTR logging (BAST-flush entry names, reload-pre, dir-data-block probe) is still active and useful.
- The 39/40 failure is RARE — it's a narrow timing window. You may need 20+ iterations to reproduce.
- A single dir loss (vs 20/40) suggests this is a different race than the ones already fixed — possibly during the shortform-to-block conversion, or an AG allocation race, or a dentry cache issue.

## Standard Test Loop

```bash
for run in $(seq 1 20); do
  tools/mxfs_sshpass.sh test1 /tmp/.mxfs_pass "umount /mnt/mxfs 2>/dev/null; umount -l /mnt/mxfs 2>/dev/null" 2>/dev/null
  tools/mxfs_sshpass.sh test2 /tmp/.mxfs_pass "umount /mnt/mxfs 2>/dev/null" 2>/dev/null
  tools/mxfs_sshpass.sh test1 /tmp/.mxfs_pass "/src/mxfs/tools/mkfs_mxfs -f -n 4 /dev/sda >/dev/null 2>&1 && mount -t mxfs /dev/sda /mnt/mxfs && dmesg -C" 2>/dev/null
  tools/mxfs_sshpass.sh test2 /tmp/.mxfs_pass "mount -t mxfs /dev/sda /mnt/mxfs && dmesg -C" 2>/dev/null
  tools/mxfs_sshpass.sh test1 /tmp/.mxfs_pass "for i in \$(seq 1 20); do mkdir /mnt/mxfs/t1_\$i 2>&1; done" 2>/dev/null &
  tools/mxfs_sshpass.sh test2 /tmp/.mxfs_pass "for i in \$(seq 1 20); do mkdir /mnt/mxfs/t2_\$i 2>&1; done" 2>/dev/null &
  wait
  COUNT=$(tools/mxfs_sshpass.sh test1 /tmp/.mxfs_pass "ls /mnt/mxfs/ 2>/dev/null | wc -l" 2>&1 | tail -1)
  echo "Run $run: $COUNT/40"
  if [ "$COUNT" != "40" ]; then
    echo "=== FAILURE — capturing ==="
    tools/mxfs_sshpass.sh test1 /tmp/.mxfs_pass "ls /mnt/mxfs/ | sort" 2>&1 | tail -40
    tools/mxfs_sshpass.sh test1 /tmp/.mxfs_pass "dmesg | grep -E 'P6-INSTR|BAST|reload|error'" 2>&1 | tail -30
    tools/mxfs_sshpass.sh test2 /tmp/.mxfs_pass "dmesg | grep -E 'P6-INSTR|BAST|reload|error'" 2>&1 | tail -30
    break
  fi
done
```
