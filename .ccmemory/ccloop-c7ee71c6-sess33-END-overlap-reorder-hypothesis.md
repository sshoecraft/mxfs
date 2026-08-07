---
name: ccloop-c7ee71c6-sess33-END-overlap-reorder-hypothesis
description: sess33 END: stale-split PRIMARY mechanism = overlapping same-daddr cluster writes completing out of order (mxfs_submit_partial_inode_write, 35 suppre…
metadata:
  type: project
---

# sess33 END — resume point for D-CRASH-COLDREAD-STALE-SPLIT

REVISED PRIMARY MECHANISM (full decode in the ledger entry's
sess33_final_timeline_decode): dd was STILL WRITING f1 during the
13:19:06 burst; `mxfs_submit_partial_inode_write` produced 14+
OVERLAPPING submissions of ONE 16KB cluster buffer in ~1s (35 suppressed
callbacks); all ranks' f1 files are co-resident in ONE recycled cluster.
Among overlapping same-daddr writes, one carrying cc>=6 completed
(durable=flush honestly advanced, ledger closed, obligation=0) while an
OLDER-image write landed LAST at the device → platter/target-cache
settled on cc=4/size=4096 with every mask+ledger satisfied. No dual
buffer instance needed. Upstream XFS cannot do this (buffer lock +
single delwri submission serialize); the MXFS partial-submit path
evidently allows overlap.

## Session-15 resume sequence
1. Read `mxfs_submit_partial_inode_write` (pal/linux/xfs_buf.c:3028,
   caller at 5825) — find the overlap window (submission without
   exclusive buffer ownership across completion?). Confirm whether
   concurrent submissions of one bp are possible and how iodone
   ordering discharges the ledger.
2. Fix shapes to evaluate (RULE 5 consult FIRST — note: TWO GPT attempts
   were content-filter rejected (false positive); use mcp__ask_gemini
   (historically in the RULE-5 chain: sess79 Gemini design, daf50d34
   chokepoint design) or a further-neutralized GPT prompt; the full
   consult text is in the sess33 transcript):
   (a) per-daddr single-outstanding-write serialization (match upstream
       semantics), (b) landed-image monotonic version guard at
       submit+iodone (also serves D-INODE-CLUSTER closure req 1).
3. crash_consistency harness now SELF-CAPTURES (data heal-reread x2 +
   watch_ino + per-ino dmesg) — every crash lap is a repro attempt.
4. Evidence: tests/logs/sess33_crash_md5_mismatch/ (+ scratchpad
   bulk_crash_run this boot; /mnt/shared forensics until next mkfs).

## Tree state
0.11.292 (58EFAA05953ADF05138AA59) deployed all-32 knob=0; boards green
except the one captured incident; 12 OPEN (7 crit) in the ledger;
state.md has the full ordered program.
