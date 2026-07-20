# sess35 H29 — REQ_META hypothesis

## Setting

E1b at LBA 4194264 (mxfs's actual dir block LBA): PASSES — userspace
direct concurrent writes from both initiators work cleanly.

mxfs at LBA 4194264: FAILS — writes have bi_status=0 but disk shows
zeros, peer reads zeros.

What differs between E1b's writes and mxfs's writes is the bio flags.
mxfs's `xfs_buf_bio_op` (pal/linux/xfs_buf.c:1366) returns
`op | REQ_META`. Userspace dd does NOT set REQ_META.

## Hypothesis H29

The host's block scheduler, the LIO target, or the SSD treats
REQ_META bios differently in a way that causes them to be silently
dropped or misordered under cross-initiator load.

## Falsifying experiment

Remove REQ_META from `xfs_buf_bio_op` (commented out in pal/linux/xfs_buf.c).
Build srcversion `2F9DBB1B8E82C8D96B4CFDD`. Run 3 iterations of
test_concurrent_mkdir.

### Pass condition (H29 supported)

If the bug rate drops from sess35 baseline (8/10 cache-divergence
+ 2/10 catastrophic = 10/10 buggy) to <50% buggy → REQ_META is
implicated.

### Fail condition (H29 falsified)

If the bug rate stays at 100% → REQ_META isn't the cause.

## Followup experiments if H29 supported

- What about REQ_META causes the issue? Block scheduler? LIO?
- Is there a kernel /sys knob to fix it without modifying mxfs?
- If we MUST drop REQ_META, what's the cost? (REQ_META is supposed
  to mark metadata bios for IO scheduler prioritization and crash
  recovery hints.)

## Followup experiments if H29 falsified

- Then mxfs's bug is something else. Possibilities:
  - mxfs's xfs_buf is being reused/zeroed before bio executes
  - mxfs's bio submission has a race with concurrent bast_process
  - mxfs's flush sequencing isn't durable per its own contract
- More instrumentation needed.

## Result — H29 FALSIFIED

3-iter (H29 build, REQ_META removed):
- iter 1 (00:26): BEFORE=98 AFTER=100 — cache divergence (saved by H17)
- iter 2 (00:28): BEFORE=0 AFTER=50 — catastrophic (50 missing from disk)
- iter 3 (00:33): in progress

Same bug surface as the 10-run baseline with REQ_META present. Both
patterns (cache divergence and catastrophic loss) reproduce identically.

**REQ_META is NOT the cause of the bug.**

Reverted `xfs_buf_bio_op` back to `return op | REQ_META;`. Cluster
needs re-deploy with reverted build before sess36.

## Sess36 next hypotheses to consider

Since storage stack is sound (E1/E1b) and REQ_META isn't the issue
(H29), the bug is somewhere ELSE in mxfs's I/O path or in xfs_buf
cache management. Candidates:

- **H30:** xfs_buf reuse — bp->b_addr memory is reused for a
  different buf while a previous bio is still in flight. The bio's
  data vector points to that memory, so the in-flight bio writes
  the NEW content (from the reusing buf) to the OLD LBA. Causes
  silent data corruption.
- **H31:** mxfs's xfs_buf_get/release pairs are unbalanced under
  cross-node BAST cycles. A dropped reference results in early
  reclaim. Bio still in flight refers to freed memory.
- **H32:** vmalloc'd buf pages have a kernel bug in 6.8 specific to
  bio_add_virt_nofail under high concurrency.

To investigate:
- Add P-H30 instrumentation: log bp pointer, bp->b_addr pointer,
  AND bp->b_hold (refcount) at xfs_buf_submit_bio time. Log again
  at xfs_buf_bio_end_io. Verify bp doesn't get reused/freed.
- Use kasan or kfence to catch use-after-free on bp->b_addr.

Or: completely different angle — instrument the WRITE PATH on the
LIO target side. Add printk in iblock_execute_rw to log every
metadata write (REQ_META) it receives, and the bytes it writes to
/dev/sda. Compare to what mxfs claims to have submitted.
