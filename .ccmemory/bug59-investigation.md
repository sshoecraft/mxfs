# Bug 59/60 Investigation: 4-Node Happy-Path Duplicate Dir Entries

## Status: PARTIALLY MITIGATED — dedup-on-load prevents corruption, root cause narrowing

## What Works
- 2-node concurrent metadata: 9999/10000 PASS, zero duplicates
- 4-node 1000/node: 3997/4000 PASS, zero duplicates
- 4-node with kill-node: 0 duplicates (Bug 58 epoch fix + invalidation check work)
- Dedup-on-load (Bug 60) filters duplicate entries during parse, self-healing on next flush

## What Fails
- 4-node 2500/node happy-path produces on-disk duplicates (141 in run 3, ~2000 in run 1)
- Duplicates are filtered by dedup-on-load, so listing shows 0 duplicates (mitigation works)
- The underlying write-path bug that creates on-disk duplicates is NOT yet fixed

## Key Finding (Run 3 Analysis)
**The duplicates are created by the node's OWN flush and read back immediately.**

Timeline from test2 dmesg (T=46622-46623):
1. test2 loads 1651 entries from 14 data blocks at phys 9877792-9877805
2. test2 adds entry #1652, flushes all 14 data blocks to 9877792-9877805
3. Write log shows all 14 blocks written (blocks 0-13, phys 9877792-9877805)
4. test2 IMMEDIATELY reloads from disk (same lock_gen=6126, EX held throughout)
5. Blocks 12-13 (phys 9877804-9877805) contain OLD data from a previous flush
6. 141 duplicate entries detected (entries that moved to earlier blocks but still appear in blocks 12-13 with old data)

The DLM EX lock was held continuously (lock_gen unchanged). No membership changes occurred. No other node could have written to these blocks. The data blocks written by test2's flush are not reading back correctly.

## What's Been Ruled Out
1. **DLM dual-EX**: Corrected diagnostic (mode>=5 threshold) shows 0 true DUAL-EX events
2. **Stale block cache reads**: Bug 52 bypasses block cache for dir reads (direct bdev_read)
3. **Epoch/membership issues**: Duplicates appear 21 seconds before first SUSPECT event
4. **In-memory duplicates**: The LOAD finds 0 duplicates; the FLUSH writes a clean entry list
5. **Stale blocks beyond ci->size**: Bug 59 limiter reads exactly ci->size/blksize blocks

## Current Theory: I/O Write Coherency Issue
The writes go through mxfs_block_cache_write -> mxfs_block_cache_flush_range -> bdev_write (submit_bio_wait). The reads go through mxfs_pal_bdev_read (submit_bio_wait). Both use raw bios.

The storage path is: VM SCSI -> ESXi hypervisor -> shared VMDK (multi-writer). VMware multi-writer VMDKs do NOT guarantee cache coherency between VMs. Within the same VM, reads after writes should be coherent, but the test shows otherwise.

Possible causes:
- Hypervisor-level write caching with delayed persistence
- Linux block layer reordering between writes and reads
- SCSI driver (PVSCSI) write-back cache behavior

## Diagnostic Added: Read-After-Write Verify
Added bdev_read verification after each block_cache_flush_range in flush_leaf_dir. If the read-back doesn't match what was written, logs BUG60 RAW MISMATCH. This will confirm whether the issue is at the I/O level.

## Bug 60 Fix: Dedup-on-Load (ACTIVE)
In `parse_data_block_entries()`, before adding each entry to the linked list, check if the name already exists. If duplicate found, log BUG60 DUPLICATE ON DISK and skip. This:
- Prevents duplicate entries from entering the in-memory cache
- Self-heals on next flush (clean list overwrites corrupted disk data)
- Effectively mitigates the symptom regardless of root cause

## Test Results Summary
| Run | Duplicates On Disk | Duplicates In Listing | Files Created | Notes |
|-----|-------------------|-----------------------|---------------|-------|
| 1   | 1964              | 0 (dedup-on-load)     | 1786/10000    | DUAL-EX false positive, transport disconnects |
| 2   | 0                 | 0                     | 3257/10000    | test4 crashed, 0 DUAL-EX with corrected threshold |
| 3   | 141               | 0 (dedup-on-load)     | 3519/10000    | test6 crashed, all 141 on phys 9877804-9877805 |

## Files Changed
- `libmxfs/dir_cache.c` — Bug 60 dedup-on-load, diagnostic logging (FLUSH_LEAF, REALLOC, phys_addr in DUPLICATE log, read-after-write verify)
- `libmxfs/dlm.c` — Bug 60 diagnostic logging (EX_GRANT trace, DUAL-EX detection with corrected mode>=5 threshold)
