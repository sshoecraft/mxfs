---
name: ccloop-c7ee71c6-sess14-K-P176-obligation-counter-VALIDATED-116-fires
description: sess14 FINAL: obligation counters wired (steps 1-2) + P176 probe VALIDATED — drain declares success with an unlanded committed change 116×/6 nodes in…
metadata:
  type: project
tags: [d3, obligation-tracking, validated, p176, next-session, open, measurement]
---

# sess14-K: publication-obligation counter WIRED and VALIDATED (v0.11.136)

## What is now in the tree (builds clean, deployed, cc PASS — no behavior change yet)
Design + wiring order documented inline at `xfs_inode.h` (`i_mxfs_pub_pending_seq` block).
- **Step 1 DONE** — `xfs/libxfs/xfs_trans_inode.c::xfs_trans_log_inode`: `pending_seq++` on
  every logged inode-core change. Single chokepoint for "a change was committed";
  deliberately independent of ili_fields / XFS_LI_DIRTY / AIL membership (all of which read
  clean while a committed change sits in the log — the whole reason this defect hid).
  ILOCK_EXCL is asserted there, so a plain increment is safe.
- **Step 2 DONE** — `xfs_mxfs_dlm.c` drain, at the `xfs_bwrite(r_bp)` / `p2_loop_wrote`
  point: `durable_seq = pending_seq` (bwrite is synchronous ⇒ slot is on the platter).
  CAVEAT carried in the comment: the sess31 hole means `xfs_iflush_cluster` rc==0 only
  proves ">=1 inode in the cluster flushed", not necessarily THIS one — if step 3 proves
  the obligation is cleared too eagerly, this placement is the first suspect.
- **Step 3 MEASURED, NOT YET ENFORCED** — `P176-OBLIGATION-OPEN` prints at the drain's
  silent-success exit (the `!v_behind → flushed = true` return that precedes grant release)
  whenever `pending != durable`.

## THE DECISIVE RESULT
    cache_coherency 32/32 PASS ... and P176 fired **116 times across only 6 nodes**
The drain declares durability with an unlanded committed change CONSTANTLY — in a run that
passed. So:
- the counter is a working discriminator (it fires exactly where the sess14-I forensics
  said the obligation is dropped: `P146-RELDUR flushed=1 wrote=0 rerr=-11` → `P51-REL`);
- the condition is PERVASIVE, not rare. Data loss only manifests when a peer reads the
  home location before some later opportunistic flush happens to land the change — which
  explains the intermittency (~1 in 15 prep→cc cycles) with no change in the underlying
  frequency of the unsafe release;
- therefore the intermittency was never a "rare race"; it is a pervasive protocol violation
  with a probabilistic observable. That reframing matters for verification: absence of
  failures does NOT indicate absence of the defect — count P176 instead.

## NEXT SESSION — step 3, then step 4
1. Convert P176's site from a print into enforcement: do NOT `flushed = true` while
   `pending != durable`; submit the image instead (reconstruct/re-log then retry the loop),
   and if it still cannot land after a bounded retry, FAIL THE HANDOFF (fence/withdraw) —
   never release the grant silently (GPT, both consults).
2. Expect a wave of secondary breakage: paths that relied on the silent release will now
   block or retry. Watch for drain latency / handoff stalls and treat them as the real cost
   being made visible, not as regressions to paper over.
3. Verify with the reproducer (prep → immediate cc) AND with the P176 counter: success is
   **P176 → 0** plus ~15 clean cycles, not merely green runs.
4. Step 4: once obligations are enforced, the write-side guards (P56-NL-LOGGED-DIR-SKIP,
   P32D/P32E, P146D, P174) revert to pure assertions and should stop firing in normal
   operation; if they keep firing, something still publishes without authority.

## Build state at handoff
v0.11.136 srcver 9BF181DE87B3B6C5BD43061, deployed + prepped on all 32 nodes, cc PASS.
