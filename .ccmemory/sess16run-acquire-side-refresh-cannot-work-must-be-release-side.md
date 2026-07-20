---
name: sess16run-acquire-side-refresh-cannot-work-must-be-release-side
description: sess16(ccloop) DECISIVE: acquire-side evict/refresh CANNOT fix the dir_reuse lost-update. Evict runs heavily (P68-EVDECIDE=6000) and KEEPS 3720 block…
metadata:
  type: project
---

## sess16 (ccloop) — acquire-side refresh structurally CANNOT fix it; must be release-side

### Evidence (build 247E2BCB, mht=50 dirwr=0 FAIL)
On test2 (a clobbering node): P68-EVDECIDE=6000 (capped), ALL ino=131. Breakdown: undurable=0 → 2280 (evicted: DONE cleared, next read FUA-refetches), undurable=1 → **3720 KEPT** (stale base kept for the RMW). P-DIRREFRESH-EVICT (sess41 data-block refresh, needs disk live-count > incore) fired **0**. My new P16-LEAFREFRESH-EVICT (leaf/free crc-differ refresh) fired **0**.

### Why both refreshes miss (the structural flaw of acquire-side)
The acquire/modify-path evict (mxfs_dir_evict_data_blocks) decides at the moment THIS node starts its modify. To refresh a kept block it plain-reads disk and checks "is disk newer?" (data: more dirents; leaf: crc differs). But at that instant the PEER's newer write to the shared block is often NOT yet on the LUN (the peer is mid-tenure or its drain hasn't landed) → disk == our stale incore → refresh declines → we RMW the stale base → and the clobber materializes only LATER when the peer's write and ours interleave. An acquire-side "is disk newer?" check is racing the peer and structurally cannot be reliable. (Also: a kept-undurable block flagged in_ail-undestaged is a FALSE POSITIVE for "our work" after a serialized handoff — our work was drained at our own release — but the refresh's disk-compare still misfires on timing.)

### THE conclusion (now over-determined)
Double-grant RULED OUT [[sess16run-DECISIVE-double-grant-RULED-OUT-bug-is-buffer-layer]] (EX serialized). Acquire-side re-read/refresh REFUTED (force_coherent, postread_reread, b_mxfs_dir_epoch, dir_release_fua_write, the data-refresh, my leaf-refresh — ALL fail). The ONLY structurally-sound place to enforce coherence is the RELEASING node, BEFORE it drops the grant: GPT design [[sess16run-GPT-design-tenure-scoped-dirbuf-coherency-FIX]] parts 1+2. The releasing node, under a REVOKING writer-fence, must (a) finish/quiesce active local dir txns, (b) drain ALL dir metadata blocks (data+leaf+node+freeindex) durable, (c) INVALIDATE its own cached copies, THEN (d) drop the grant. dir_release_invalidate (existing) does a partial version (data blocks only, no fence, leaf blocks uncached-at-release per P34-LEAF-DRAIN) → insufficient. The acquirer then ALWAYS cold-reads the durable image (no racing disk-compare needed).

### NEXT SESSION — implement (high confidence this converges)
In mxfs_dlm_bast_process (xfs_mxfs_dlm.c:5592) release path: BEFORE mxfs_v5_dlm_inode_unlock, after the existing drain, add a REVOKING fence + invalidate of ALL the dir's cached metadata buffers. Key: the leaf/freeindex blocks are UNCACHED at release (P34-LEAF-DRAIN CACHED=0) — they were already written by xfsaild, so the releasing node may have NO cached copy to invalidate, and the next acquirer reads them fresh anyway; the gap is the DATA block (block0) kept in_ail-undestaged. So the minimal effective fix may be: at release, force-invalidate the dir's cached DATA/leaf buffers that are in_ail-undestaged (clear DONE) — they're durable (drained), so safe — under a fence so nothing re-dirties before unlock. Validate at dirwr=0 (dirwr masks). Target: P-DIRWR daddr=120 count monotonic; dir_reuse 8/tcp PASS @ mht=50; tcp_dlm ≤60s; 17/17; 1/2/4. Canaries unlink/rename_visibility/crash_consistency PASS (resurrection).

### Build 247E2BCB = + P16 leaf-refresh (gated mxfs_dirrefresh, safe, fired 0) + MX-DOUBLEGRANT auditor (KEEP) + b_mxfs_dir_epoch (gated off) + P32F fence (off-discriminator). Default mht=300 dir_reuse PASS believed unregressed (new logic safe/gated). Criterion NOT met — marker not written.</body>
