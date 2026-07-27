---
name: ccloop-c7ee71c6-sess14-J-P175-REFUTED-obligation-tracking-required
description: sess14 CLOSE: P175 SF-content arm REFUTED (residual recurred with 0 fires, third sub-shape). Per-exit patching is exhausted — next session must imple…
metadata:
  type: project
tags: [d3, residual, refuted, obligation-tracking, next-session, open, reproducer]
---

# sess14-J: P175 refuted — stop patching drain exits, implement the obligation counter

## What was tried (v0.11.132) and why it is REFUTED
Diagnosis sess14-I showed node9's drain printing
`P146-RELDUR size=181 dsize=105 flushed=1 wrote=0 rerr=-11` then releasing — declaring
durability without writing. I extended the drain's EAGAIN-branch identity test (which
compared dinode HEADER fields only) to also memcmp the SHORTFORM fork against the platter
(`P175-SFCONTENT-UNLANDED`).
**Result: the residual RECURRED at .132 with P175 firing 0 times.** The unlanded state is
therefore NOT reached through that branch.

## What the recurrence showed (tests/logs/resid132_211425/)
- Shape: cv **lost-add** on ONE node (`test1:FAIL: cv node1 sees node6.txt ... node15.txt`)
  — a THIRD distinct sub-case, different from both the cv clobber fixed by P174 (sess14-G)
  and the uv lost-remove of sess14-I.
- Census of that single run: `P146-RELDUR ... flushed=1 wrote=0 rerr=-11` appeared
  **~11,800 times** (6339 at size=4096, 1792 at 8192, 1563 at 12288, 1100 at 6, 987 at 104
  …) and in EVERY case `size == dsize`. The drain routinely completes without writing, and
  no header-or-content comparison can separate "genuinely durable" from "obligation
  outstanding" — because both look identical once the in-core and platter images agree on
  the fields being compared while a committed change sits only in the log/CIL.

## Conclusion for session 15 — the per-exit approach is exhausted
Three drain/write-path predicates have now been built and refuted this session
(NL-skip, epoch-gate, SF-content-compare) plus one that regressed (stranded dir).
Implement the real mechanism GPT specified (sess14-D and the second consult, item 2a):
1. A per-inode **publication obligation**: `pending_seq` bumped when a dirop commits;
   `durable_seq` advanced ONLY on confirmed home-location write completion. Tracked
   independently of XFS dirty state / ili_fields / AIL membership — those are exactly the
   signals that are lying here.
2. The release drain returns success **only** when `pending_seq == durable_seq`; otherwise
   it must reconstruct and submit the image (not return success on "nothing dirty").
3. A drain that cannot land must fail the handoff: bounded retry, then fence/withdraw —
   never a silent release. (An EX handoff after an unlanded obligation is a protocol
   violation, not a case to arbitrate later.)
4. Only then do the write-side guards (P56-NL-LOGGED-DIR-SKIP, P32D/P32E, P146D) become
   the pure assertions they should be.

## Reproducer (cheap, reliable enough to iterate on)
`./run.sh 32 caw prep_cluster` then IMMEDIATELY `./run.sh 32 caw cache_coherency`.
Hit rate observed ~1 in 2-4 cycles. ALWAYS capture on failure before re-running (the
criteria row is overwritten): the loop used at the end of sess14 does prep -> cc -> on FAIL
harvest all 32 dmesg + row.json into tests/logs/resid<ver>_<HHMMSS>/.
