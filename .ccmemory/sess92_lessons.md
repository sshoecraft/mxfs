---
name: sess92_lessons
description: sess92 — bnobt lost-update is an IN-CORE revert (not drain-gap, not storage-persist); two GPT consults; mechanism F (read-completion TOCTOU) or buffe…
metadata:
  type: project
---

# sess92 (2026-06-05, ccloop run 29df431e)

cache_coherency still FAIL. Marker NOT written. Tree restored to baseline
`ECDE1FC5` (FIX2 v2; my probes were reverted — rebuilt .ko == ECDE1FC5).

## What I PROVED this session (decisive, instrumented) about the bnobt double-free
The sess79-91 bnobt durable lost-update (`ltbno+ltlen>bno` xfs_alloc.c:2244 shutdown)
is a **cross-node alloc/free + IN-CORE revert of the bnobt buffer before the release
drain** — it is NOT a drain-enumeration gap and NOT a storage-persistence failure.

Repro (ECDE1FC5, unlink_visibility, AG9 = SHARED ag, not affine to slots 0-3):
- test2 (slot3) created node2_file20 = ino 18874517 in AG9, allocated block 30
  (fsb 0x24001e), split bnobt free-rec (24,260891) in-core (P88 disk_differs=1, in-AIL).
- test1 (slot0) freed ino 18874517 → freed block 30 → bnobt left-rec STILL (24,260891)
  → block 30 already free → double-free → shutdown.
- `P47-INACT verdict=DISK-LIVE-same-gen=>A-lost-removal`; `P81-DEXT disk_claims_freed=1
  verdict=DISK-INODE-OWNS-FREED=>bnobt-lost-update` (on-disk INODE durably owns blk 30).
- **P28-INSTR disk_differs=0** at free → on-disk bnobt leaf ALSO has unsplit (24,260891);
  test1's in-core matches disk. So the split is simply not on the platter.

### Refutations (RULE 4) — narrowed the mechanism hard
1. **FIX1 FUA-skip guard never fires on bnobt** — all `P91-FUA-SKIP-LOGGED` are
   `ops=xfs_inode` (0 on bnobt/cntbt). So it's not mxfs_buf_read_fua clobbering a
   *logged* bnobt buffer.
2. **AIL is fully drained at release** — added a probe (P-AILVERIFY) that walks the AIL
   right before mxfs_v5_dlm_ag_unlock for AG-meta buffers in the AG: found **n=0**. The
   existing `xfs_ail_push_ag_sync_bounded` (xfs_mxfs_dlm.c:6312) DOES empty the AIL of
   AG-meta. AG9 used the FULL release path (`P10-INSTR ... agno=9 REL-INLINE-V55`), and
   `P75-INSTR` (bnobt in-AIL at release) did NOT fire. → REFUTES GPT's 1st hypothesis
   (drain enumeration gap).
3. **Storage persists at the drain** — generalized P80-INSTR (post-bwrite FUA readback)
   to ALL AGs with a retry loop: `P80-DESTAGE-RETRY` fired **0×** → every synchronous
   xfs_bwrite of an AG-meta buffer has disk_differs=0 immediately after. → REFUTES the
   sess44/79 "SCST ACKs-but-doesn't-persist" theory at the drain.

CONCLUSION: inode durable + AIL drained + drain writes persist ⇒ the in-core bnobt leaf
content is **reverted from split → pristine by a NON-TRANSACTIONAL path BEFORE the drain
writes it**; the drain then faithfully+durably writes the already-reverted pristine block.
P88 proves the split was once in-core; P28 proves it's gone (in-core==disk==pristine).

## GPT consult #2 (gpt-5.5, RULE-5 escalation; Gemini ×2 sess80/sess90 prior) — TOP LEAD
**Mechanism F = read-completion TOCTOU.** FIX1 checks logged/pinned at FUA-read *submit*;
if the buffer is CLEAN at submit but a txn logs the split into it while the read is
*in-flight*, the read *completion* DMAs the stale/pristine disk image over bp->b_addr.
Submit-time guard can't fire (clean at submit) → exactly why P91 never fires on bnobt.
2nd lead = buffer **aliasing** (two live/overlapping xfs_buf for one bnobt daddr, e.g.
via xfs_buf_stale() used for coherency, or different-length/uncached lookup) — pristine
alias wins the last home write.

### OPEN QUESTION the next session MUST answer first (decides F vs aliasing)
Is the buffer LOCKED across the FUA read, and is the read SYNC? mxfs_buf_read_fua reads
directly into bp->b_addr (pal/linux/xfs_buf.c:1569-70) and is called from xfs_buf_submit
(L2176) under the buffer lock; mxfs_pal_scsi_read_fua_bdev appears synchronous. If
locked+sync, a concurrent txn CANNOT modify the buffer mid-read ⇒ mechanism F is
impossible via this path ⇒ look at ASYNC/READAHEAD reads (xfs_buf_readahead /
xfs_dir3_data_reada — note this run also threw `xfs_dir3_data_reada_verify block 0x178`
corruption) or aliasing. RESOLVE THIS by code-reading before building.

### GPT's recommended FIX (robust regardless of F vs lock-gap): bounce-buffer reread
In mxfs_buf_read_fua: read into PRIVATE kmalloc'd memory (not bp->b_addr); AFTER I/O,
re-validate under bp lock (recheck pinned/b_log_item/!list_empty(b_li_list)/delwri AND a
new bp->b_mxfs_content_seq bumped in xfs_trans_log_buf for AG-meta); only memcpy into
bp->b_addr + set _XBF_FUA_FRESH if unchanged; else DISCARD (keep in-core authoritative).
Also treat read-in-flight as a protected state in mxfs_ag_meta_invalidate_stale.
Deadlock-safe: localizes to the reread; no global ail_push, no ILOCK across CAW poll.
GPT's decisive probe: FUA submit/complete cookie + content_seq + alias detector in
xfs_buf_find/get_map — confirms F (submit-clean/complete-after-split) vs alias.

## This session's runs (all passed=1 failed=3; cross_visibility always PASS)
- ECDE1FC5 (deployed, no clean reboot): rename 2/240, unlink bnobt-double-free SHUTDOWN
  (the analyzed one), cwr n/a (cluster broke).
- 2048A964 (my AIL-verify drain, too slow): inode-lock-timeout shutdown
  (`DLM inode lock unrecoverable ino=18874497 mode=5 rc=-110`) = SESS50-STARVE slowness
  aggravated by per-buffer FUA+bwrite+flush. P-AILVERIFY n=0 (the key refutation).
- 1557C8BF (P80 all-AG retry + CLEAN virsh reboot all 4): cross_vis PASS; rename 40/240
  (FAST regression, variable vs 2/240); unlink 32/122 (138s TIMEOUT); cwr 1/6 (124s
  TIMEOUT). NEW corruption: test1 `xfs_sb_write_verify` SB corruption; test2/3/4
  `xfs_dir3_data_reada_verify block 0x178`. P80-DESTAGE-RETRY 0× (storage persists).
  → corruption is VARIABLE/multi-root (bnobt, SB, dir3, inode-cluster) = broad cross-node
  cache incoherency; the in-core-revert/TOCTOU fix likely addresses the common root.

## NEXT SESSION PLAN
1. Resolve the OPEN QUESTION (locked+sync read?) by code-reading xfs_buf_submit lock
   state + readahead FUA paths + mxfs_pal_scsi_read_fua_bdev sync-ness.
2. If async/readahead or aliasing possible: implement GPT's bounce-buffer reread +
   content_seq (decisive probe form first per RULE 4), build, CLEAN virsh reboot all 4
   (NOT just reset4 — contaminated state causes the SESS50-STARVE inode-lock-timeouts),
   run cache_coherency. Watch P91/new-discard probe + whether bnobt/SB/dir3 corruption
   AND rename regression clear.
3. Don't re-add the slow per-buffer AIL-verify drain (proven no-op + too slow).

## INFRA (sess92)
- /tmp/.mxfs_pass wiped on reboot; restore: `cp ~/.mxfs/pass /tmp/.mxfs_pass`.
- Clean reboot: `sudo virsh -c qemu:///system destroy testN && ... start testN` (passwordless
  sudo works; VMs LOCAL under system URI). Then `bash tests/reset4.sh 4` (its ENSURE_NFS
  re-mounts /src via NFS 192.168.1.4:/src automatically). Slots t1=0 t2=3 t3=1 t4=2; ~20 AGs.
- cache_coherency auto-backgrounds under 10-min cap; run via `( ... > /tmp/cc.log 2>&1; echo
  EXIT=$? >> ) &` then until-grep EXIT=. Mount /mnt/shared, dev /dev/sda.
