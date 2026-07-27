---
name: ccloop-c7ee71c6-sess14-F-D3-CV-ROOT-BYTE-EXACT-nl-logged-dir-slot-write-FIXED
description: sess14 D3 THIRD root, byte-exact: co-resident filter's "logged⇒always write" published a DIR slot at NL, reverting 7 names→3 (4 files lost). FIX v0.1…
metadata:
  type: project
tags: [d3, root-cause, byte-exact, fixed, coresident, nl-write, cache-coherency, 32-node]
---

# sess14-F: cache_coherency cv loss — ROOT BYTE-EXACT and FIXED (v0.11.124)

## The hit (18:39:39, v0.11.123, storm+chain lap)
cache_coherency FAIL 8 checks/32 nodes: 4 files missing cluster-wide (node16, node23,
node27, node32) — including on their OWN writers (test16 could not see node16.txt).
Harvest: tests/logs/d3ring_20260726_184529_cchit/ (32 dmesg + P172 rings).

## The merged 32-node ledger (P56-DIRWRITE, realns-aligned) — the whole story in 3 lines
    18:39:39.415 test27  mode=5  write=[13 12 5 16 32 23 27]     ← 7 names, correct
    18:39:39.472 test5   mode=0  write=[13 12 5]                 ← **REVERT: 4 names erased**
    18:39:39.477 test26  mode=5  write=[13 12 5 26]              ← everyone builds on the corpse
The 4 erased names are EXACTLY the 4 the test reported missing. Every later write extends
the reverted base; the entries never return. (Dir was SHORTFORM: entries live inline in the
dinode, so this is an inode-cluster slot write, daddr=39771384.)

## Root cause (code-proven)
`mxfs_submit_partial_inode_write` (pal/linux/xfs_buf.c ~3099) — the co-resident cluster
write filter — had the rule *"Logged/buf-logged THIS round = our genuine committed change;
always write it"*, evaluated BEFORE the NL/free guards. test5's dir slot was logged during
its EX tenure at 39.167; the cluster buffer kept that stale image; the write was submitted
at 39.472 when test5 was already **NL** (mode=0 in the print). The "logged" rule therefore
out-ranked every NL protection (P119, P32E, dirskip): the buffer image, not the fork, was
the vehicle — which is why the earlier xfs_iflush-level fences (P32E/P32D) fired ZERO times
in this run (they are exonerated, not the cause).

## The fix (v0.11.124, srcver D9F7230690E35FFAB72796C)
In the logged branch: if the slot is a DIRECTORY and the in-core inode's grant is NL (and
not free), SKIP it — marker **P56-NL-LOGGED-DIR-SKIP** — param `mxfs.dir_nl_logged_skip`
default 1. Rationale (GPT RULE-5 invariant, sess14-D): never publish an inode core at NL;
if our committed change landed, the release drain wrote it (rewriting can only revert
peers); if it did NOT land, that is a drain defect to fix at the drain.

## Verification so far
- Immediately after deploy: cache_coherency 32/32 PASS (654 checks), guard fired 2× (real
  interceptions in a passing run — the hazard is common, the loss now prevented).
- Storm+chain lap at .124: cc / dlm_scaling / dir_reuse_coherency / fence_during_write ALL
  PASS (drc back to 58 checks, 115s).
- RULE 6: keep lapping — this is variant #3 of the D3 family fixed today (dead-incarnation
  re-log, NL zombie dir flush, NL logged dir slot). All three share the GPT invariant, so
  the structural end-state (tenure-tagged flush authority) remains the right follow-up.
