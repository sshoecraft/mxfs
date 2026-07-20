---
name: sess41-GPT-diagnosis-release-fence-not-atomic-with-downconvert
description: sess41 GPT-5.5: dir_reuse 2/tcp root candidate = release fence not atomic w/ downconvert; fix=hard drain+invalidate-on-acquire+incarnation cookie. Co…
metadata:
  type: project
---

## sess41 GPT-5.5 consult (RULE 5) — dir_reuse_coherency 2/tcp. Root + fix plan + CODE LOCATIONS.

### PROVEN paradox: 240 xfsaild writes of block-0 (daddr 120), disk_cnt=buf_cnt+1, comm=xfsaild, **i_dlm_mode=EX(5)**, bgen==dirgen (dir_gen stuck 4), b_tenure_id==cur_epoch. Node holds EX yet flushes a block 1 entry behind disk. Durable loss = node1_f1..f14 (block-0 first-wave). Release fence (sess97) proven-working (P-SF-DURABLE-FAIL=0).

### GPT VERDICT (A): REAL cross-tenure stale flush. "Holds EX at submit" ≠ "buffer dirtied from a disk image read THIS tenure"; an xfs_buf carries state across tenure boundaries; gen/tenure re-stamped on relog read "current" but payload is older. +1 = peer added exactly one dirent in the intervening EX tenure. Most likely escape: RELEASE FENCE NOT ATOMIC WITH DOWNCONVERT.

### CODE MAP (xfs/xfs_mxfs_dlm.c) — the inode BAST-release fn (~4560-5511)
- 4650: `i_dlm_mode=NL` set EARLY (so local fast-path sees NL). i_dlm_state set to DEMOTING by the CALLER (bast scheduler) before this fn.
- 4690-4800: release fence loop (xfs_log_force SYNC + xfs_ail_push_ag_sync + mxfs_dir_flush_data_blocks; loops until mxfs_dir_data_durable==true; uses mxfs_drain_ilock_READ per-iter + up_read). Proven to leave NO dirty/in-AIL block at fence-exit.
- 5031-5054: **sess35 best-effort flush→stale loop** (mxfs_dir_stale_data_blocks until nskip==0) — already targets the re-dirty TOCTOU but is best-effort (drops i_lock each pass; can exhaust → P35F-STALE-RETRY-EXHAUSTED → proceeds anyway).
- 5057+: sess43 i_dlm_dir_gen bump on BAST-release.
- 5485: `mxfs_v5_dlm_inode_unlock` — the ACTUAL on-disk handoff. (Large gap 5054→5485.)
- 5504-5510: state→NONE + `wake_up_all(&ip->i_dlm_wait)` (wakes DEMOTING waiters).
- ilock_begin @8116: fast-path @8342. **Dirs ALREADY gated: fast-path requires state==CACHED** (8368-8370) → diverts to slow path during BAST/DEMOTING (comment 8344-8354 describes THIS exact bug). TCP self-created dirs get an extra mirror-held verify (8292-8323, P-TCPEX-REACQ). So the OBVIOUS re-dirty window is already guarded — yet clobber persists ⇒ subtler gap.
- Deeper concern (5000-5002): "post-evict re-reads return STALE under fua_disable=1 — reread does not reliably pull peer's just-committed dir block from SCST." (But sess41 detector's mxfs_pal_bdev_read_plain_bdev DID see disk coherent/ahead — so refetch path coherency is timing-dependent or path-dependent.)

### GPT FIX PLAN (priority; NO content comparison — ghost reuse defeats it)
1. **Hard local-writer DRAIN atomic with downconvert**: per-inode rwsem/DRAINING; create/remove/rename take READ; release takes WRITE, sets DRAINING before fence, waits active_writers==0, flush+wait ALL dir DA blocks (verify by buffer-cache/daddr lookup NOT iext walk), unlock WHILE drained, clear DRAINING AFTER unlock. The existing state==CACHED gate is the partial version; make it airtight (close the [state-read .. DEMOTING-set] and [fence-exit .. 5485 unlock] windows).
2. invalidate-ALL-on-acquire (data+leaf+node+free) after any peer tenure; dirty buffers at acquire = bug (ASSERT).
3. expand fence/invalidate to WHOLE dir DA fork (leaf lingers — P21S 70×).
4. owner/incarnation cookie on every dir buffer; validate at bio submit → xfs_buf_stale (NOT write) on mismatch. (NOTE sess40 i_generation incarn skip fired 0× — use a RELIABLE incarnation, not the stuck dir_gen.)
5. on unlink/free/truncate: stale/binval ALL old-incarnation dir buffers+log items before daddr reuse.

### DEFINITIVE next instrumentation (to pin the EXACT losing write, since obvious window is guarded): target-side (SCST) write journal for daddr-120 sectors (seq/node/payload-hash/live-count/contains-node1_f1..f14 bitmap) → match final cold-read hash to the losing write; + initiator ring buffer (ino==131||daddr==120) tracing DLM grant/BAST/fence/convert + buffer read/dirty/AIL/submit, with WARN_ON(fence_clean && active_writers!=0) and WARN at dlm_convert_submit if any incore dir buf (by daddr) is dirty.

### TREE STATE (clean): build 2A64E9BD = baseline B9F9326E behavior + DORMANT scaffolding. dataclobber DEFAULT 0 (write-side skip REFUTED: ghost reuse → rounds 1-6 lookup_fail=150), dirrefresh DEFAULT 0 (content-refresh INERT). P-DATACLOBBER-SKIP detector (mode 1) logs kind/bgen/dirgen/mode/tenure/epoch — reusable. drc_loop.sh counts P-DATACLOBBER-SKIP. See [[sess41-FIX-tenure-gated-dataclobber-guard-AF02E775]].
Builds: AF02E775→3CC51B7E→B6E72DF5(REGRESS)→A4D7996F→2A64E9BD. Supersedes [[sess40-CORRECTION-production-DOES-fail-bugA-real-at-dirwr0]].
