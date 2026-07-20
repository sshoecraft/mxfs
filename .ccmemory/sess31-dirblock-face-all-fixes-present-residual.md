---
name: sess31-dirblock-face-all-fixes-present-residual
description: sess31: after FACE B fix, sole dir_reuse blocker = dir-DATA-block dirent loss (readdir 185/200). ALL architectural fixes already present; dirskip=1 h…
metadata:
  type: project
---

## sess31 (ccloop 8ddb16a2) — dir_reuse_coherency 2/tcp: dir-DATA-block lost-update is the SOLE residual after FACE B fix

After [[sess31-FACEB-FIXED-p116-grant-held-discriminator]] (P116 grant-held, builds 5E706CBF KEEP), EVERY run now fails ONLY with the dir-DATA-block dirent loss: `readdir=185/200 lookup_fail=0` (~12-16 of one node's first-wave dirents, e.g. node1_f1..f12, durably missing from the shared dir ino 131 data block 0; both nodes agree = durable write-side loss). This is the sess28/29 residual.

### What I PROVED this session (RULE 4)
- **Release-side fences are ALL present and WORKING** (P-SF-DURABLE-FAIL=0, P97-RELFENCE-WEDGE=0, P35F-STALE-RETRY-EXHAUSTED=0). The dir-EX→NL release path (xfs_mxfs_dlm.c ~4409): unbounded durable loop (xfs_log_force SYNC + xfs_ail_push_ag_sync + mxfs_dir_flush_data_blocks=xfs_bwrite-waits-unpin) until !in_ail&&!pinned&&data_durable, THEN sess99 flush→xfs_buf_stale loop (500-iter TOCTOU) removing the buffers from cache, THEN mxfs_dlm_dir_inode_durable (shortform) + inode-cluster quiesce. So at release every dir block is landed durable AND staled (next acquire = cold read).
- **DIR-STALE-SKIP (30-71×/run) is mostly FALSE POSITIVES**: buf_gen=0 ALWAYS (a cold-read fresh buffer has b_mxfs_dir_gen=0, trips the gen!=inode_gen compare, but its content is fresh). Don't chase DIR-STALE-SKIP count.
- **dirskip=1 REFUTED**: caused a barrier HANG/wedge (no-result both nodes). The write-side xfsaild dir-write skip (mxfs_buf_xfsaild_skip_dir_write, default off) is too blunt — its tenure-mismatch arm false-positives on block→leaf conversion (skips a legit write → wedge). So the proven sess29 xfsaild-stale-flush canNOT be fixed via dirskip.

### GPT-5.5 consult (RULE 5, this session)
GPT confirmed the architecture: DLM EX must be a cache-coherency token; release-drain must xfs_log_force(CIL) BEFORE pin/AIL wait so CIL-resident-pinned commits don't slip into the next acquire; acquire-side must discard+re-read. **VERDICT: all of this is ALREADY IMPLEMENTED in mxfs.** GPT explicitly advised AGAINST: acquire-side log-force-after-peer-mod (can make stale image AIL-eligible), buffer-level 3-way merge of pinned dir buffers (WAL violation, CIL already captured old bytes), clearing XBF_DONE on pinned. So GPT's recommended fix is present; the gap is elsewhere.

### Remaining hypothesis (next session, UNPROVEN)
sess29 PROVED the clobber is `comm=xfsaild, mode=5 (EX-held)` — xfsaild flushes a stale dir block WHILE this node holds the dir EX. Since release-stale guarantees a cold read at acquire, the cold-read base SHOULD be fresh, yet the RMW base is stale. Two candidates:
1. **COLD-READ STALENESS at the storage layer**: a plain bio read after a peer's release returns a transiently STALE image (LIO per-initiator read cache / write-propagation window), so the acquire cold-read gets a stale block 0 → RMW stale → xfsaild persists it. sess35 P35C/sess96/sess43 all hint "dir-block reread staleness under fua_disable=1". TEST: directly verify plain-read coherency across initiators on this LIO target (caw_verify/fua_verify tools, or a scratch-LBA write/read). If cold reads ARE stale, the fix is a read-path SYNCHRONIZE CACHE / coherent-read primitive, NOT more mxfs buffer logic. This is the most likely TRUE root and is under-tested.
2. **Within-tenure stale-base RMW** during the block→leaf conversion or block-0 fill under the rapid EX ping-pong (no release between the add and the clobber).

### Decisive detector to add next: write-side content-revert
At a dir3_data_buf_ops WRITE (pal/linux/xfs_buf.c ~2028, the P56 block, or reuse sess29 P29-DATAWRITE gated dirwr), plain-read the coherent on-disk block, and fire CLOBBER iff disk holds an inumber the buffer LACKS (buffer missing committed entries) — NOT raw count<count (false-positive on rm-rf). Log daddr + comm + the lost inumbers + i_dlm_mode. sess29 already saw comm=xfsaild EX; confirm post-FACE-B.

### KEEP this session: P116 grant-held (FACE B fix, 5E706CBF), P31-FACEA detector (xfs_dir2_readdir.c), P31B-RELOAD-BUF detector (xfs_mxfs_dlm.c). Criterion (./run.sh 2 tcp 100%) NOT met — marker NOT written.
</body>
</invoke>
