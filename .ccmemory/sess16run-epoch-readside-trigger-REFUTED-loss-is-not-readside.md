---
name: sess16run-epoch-readside-trigger-REFUTED-loss-is-not-readside
description: sess16(ccloop) REFUTED: read-side tenure-epoch re-read trigger (build 42178C17, b_mxfs_dir_epoch) does NOT fix dir_reuse mht=50 loss. Epochs advance…
metadata:
  type: project
---

## sess16 (ccloop) — read-side tenure-epoch trigger REFUTED (build 42178C17)

Implemented GPT design part 3 ("enforce at use"): added `b_mxfs_dir_epoch` (xfs_buf.h), stamped = `dp->i_dlm_dir_valid_epoch` at coherent dir-block reads (xfs_da_btree.c), and added a postread-reread trigger `b_mxfs_dir_epoch < i_dlm_dir_valid_epoch` that OVERRIDES the payload-LSN undestaged keep-guard (since epoch only advances after we released EX → our work was Invariant-1 drained → safe to discard). Gated by `dir_postread_reread` (kept default 0 → INERT at production; my new logic only runs with postread_reread=1).

### Result: REFUTED
mht=50 + postread_reread=1: dir_reuse STILL FAILS 0/8, SAME loss (node1_f1.md5, node5_f40.md5). Engagement data on test5: P65-EPOCH-ADOPT=10, P63-HANDOFF=16, grant_epoch advancing 771→773→780→785→792 (valid_epoch trailing) — so the epoch machinery IS live and handoffs ARE detected — but **P67-POSTREAD-REREAD fired only 2×**. The stale-RMW data block is NOT being re-read.

### What this PROVES
Combined with [[sess16run-mht50-dirreuse-loss-durable-survives-forcecoherent]] (force_coherent=1 also fails), the dir_reuse loss is **NOT a read-side cache staleness**. Re-reading the block before RMW — by ANY trigger (dir_gen, grant_gen, force_coherent, my epoch) — does not prevent it. At test2's read time the block content it reads is what it RMWs; the loss is that test2 read content (count=77) that was ALREADY SUPERSEDED on the LUN by test4 (count=126), yet test2's coherent read returned 77.

Two remaining explanations (decide NEXT, RULE 4):
1. **Overlapping EX grants (TCP double-grant)**: test2 and test4 both held EX on ino=131 in overlapping windows (the count 126/77 writes are 225µs apart). sess52 claimed ex_pop=1 but that may be CAW or stale. RE-TEST on THIS 8-node-TCP build: instrument the EX-holder set for ino=131 at each daddr=120 WRITE submission — if test4 still holds (or recently held without a complete drain+revoke) when test2 writes, it's a serialization break in the DLM grant/handoff itself (dlm/ layer), NOT the XFS buffer layer.
2. **Write-ordering race**: both reads were legitimately current at read time but the WRITES interleave; needs the RELEASE-side fence so a handoff cannot complete until the prior owner's block is durable AND the next owner re-reads.

### Direction for NEXT session
STOP trying read-side re-read fixes (force_coherent, postread_reread, epoch trigger all REFUTED). Implement GPT-5.5 design [[sess16run-GPT-design-tenure-scoped-dirbuf-coherency-FIX]] **parts 1+2 (RELEASE-side drain-then-invalidate + REVOKING writer-fence + acquire-side epoch barrier)** — the buffer must be invalidated at the HANDOFF point under a fence, not re-read at use. BUT FIRST settle double-grant (explanation 1) because if the DLM grants overlapping EX, no buffer-layer fix converges — the fix would be in dlm/ (grant serialization / honor-BAST-before-grant-peer). Decisive instrument: log EX holder(s) of ino=131 at every daddr=120 P-DIRWR.

### Build state
42178C17 = BAB5566E + b_mxfs_dir_epoch trigger (INERT at default: postread_reread=0). P32F-NXSHRINK-FENCE (xfs_inode.c, dir_nxshrink_fence default 1) still present but proven never-fires. Default-config (mht=300) dir_reuse PASS should be UNREGRESSED (new logic gated off) — not re-verified this session. Repro: virsh reboot test1-8; `MXFS_EXTRA_MODARGS='inode_mht_ms=50 dirwr=2' MXFS_TEST_ENV='DRC_ROUNDS=2' ./run.sh 8 tcp dir_reuse_coherency`; merge P-DIRWR owner=131, grep daddr=120 count regressions.</body>
