---
name: AAA-ccloopcc87-sess7-SECONDARY-fdw-page-cache-hypothesis-inconclusive-0.10.95
description: sess7: rare fence_during_write fdw-MISS data mismatch @ 16/caw (1 occurrence, needs heavy prior churn). Applied defensive page-cache-truncate fix (0.…
metadata:
  type: project
tags: [ccloop-cc87fed3, fence_during_write, fdw-MISS, build-0.10.95, RULE4, inconclusive, watch]
---

## Context
While validating the PRIMARY fix (0.10.94, double-add list corruption -- see sibling memory
`AAA-ccloopcc87-sess7-ROOT-CAUSE-FIXED-double-add-reset-for-create-0.10.94`), the full 16-test
2/caw... wait, 16/caw suite hit ONE unrelated failure: `fence_during_write` FAILED with
`test12:FAIL:fdw node12 own data intact(exp=1 got=0)` -- a checksum mismatch on node12's own
private file (`f7`), durable (survives `echo 1 > drop_caches`, i.e. NOT a plain page-cache-
staleness-heals-on-reread artifact). ino=21513481, size=4096, showed heavy `P9-NLEDGE
reset4create` cycling earlier in the same run (multiple resets across ~3 minutes of wall time)
before fence_during_write claimed it.

## Investigation
1. Confirmed via 4x isolated re-runs of `fence_during_write` alone (on an already-converged,
   NOT freshly-churned 16-node cluster): 4/4 PASS, does not reproduce in isolation. The failure
   needs the ACCUMULATED churn state from ~13 prior tests in the same suite run (matches this
   project's known "needs prior churn" bug shape, e.g. BUG3 had the same precondition pattern).
2. Traced the call chain for the reset-for-create reuse path
   (`mxfs_dlm_reset_inode_for_create`, xfs_mxfs_dlm.c) and its caller
   (`xfs_icreate` -> `xfs_inode_init`, libxfs/xfs_inode_util.c, CONFIRMED unmodified stock code).
   Neither function touches `inode->i_mapping` (VFS page cache) at all. Structural finding:
   EVERY other inode-reuse path gets its page cache cleared for free, because
   `xfs_fs_evict_inode()` (pal/linux/xfs_super.c) unconditionally calls
   `truncate_inode_pages_final()` before a struct can ever become IRECLAIMABLE or return to the
   slab. The reset-for-create path's WHOLE POINT is to skip evict() (avoid a disk re-read) -- so
   it also skips this page-cache clear that every other path gets implicitly.
3. Hypothesis: a stale page (dirty or clean) from this node's OWN prior use of the same struct
   survives the reset and can be read back / win a writeback race under the new file identity,
   producing a mismatch that would NOT heal via drop_caches if the stale page is dirty
   (`invalidate_mapping_pages`, used elsewhere in this file for a DIFFERENT self-deadlock-prone
   context, explicitly skips dirty pages -- matches the observed `healed=0`).

## Fix applied (build 0.10.95, srcversion EFAC61E3507BE8B597E20C1)
Added `truncate_inode_pages(inode->i_mapping, 0)` at the top of
`mxfs_dlm_reset_inode_for_create`, plus a P143-RESET-STALE-PAGES diagnostic (logs nrpages found,
capped 200) as direct-proof instrumentation. Verified safe to use the BLOCKING/unconditional
truncate (not the non-blocking invalidate_mapping_pages used elsewhere) because: (a) this branch
only runs for i_count-idle structs (no live fd/mmap holder can be racing a page write -- the
prior incarnation's last closer already dropped to 0, a precondition of reaching this branch);
(b) dirty pages MUST be dropped here, not preserved -- they belong to a dead incarnation and must
never reach disk under the new file's identity.

## Validation status: INCONCLUSIVE (be honest about this, don't overclaim)
Re-ran the FULL 16-test 16/caw suite once more (same churn-heavy sequence) on 0.10.95:
**16/16 PASS this time, including fence_during_write clean.** BUT: **P143 fired ZERO times**
across all 16 nodes' dmesg -- meaning `truncate_inode_pages` never found any stale nrpages
during ANY reset-for-create call in this entire run. Since the original bug only reproduced
ONCE out of roughly 20 fence_during_write executions across this session (1/2/4/8/16-node runs
+ 4 isolated 16-node re-runs + this one), a single clean re-run is NOT strong evidence the fix
was the difference-maker -- the failure may simply not have been triggered this time, same as
the earlier isolated re-runs that also passed without needing this fix at all.

## Disposition: KEEP the fix (safe, structurally justified), KEEP WATCHING
Do not treat this as closed. The fix is low-risk (only touches an idle, about-to-be-repurposed
struct's page cache, matches what evict() already does unconditionally elsewhere) so leaving it
in carries no regression risk even if it turns out not to be the actual cause. But the ORIGINAL
fdw-MISS mechanism is NOT proven, only hypothesized-and-patched-defensively. If fdw-MISS (or any
other "own data intact"-style checksum mismatch) recurs in ANY future run at ANY node count:
1. Check P143 first -- did it fire near the failure? If yes, mechanism CONFIRMED, this fix is
   validated (or was insufficient if it still fires AND the mismatch still occurs -- would mean
   truncate_inode_pages isn't fully closing the window, look for a TOCTOU between the truncate
   and the actual first write of the new incarnation).
2. If P143 does NOT fire but the mismatch still occurs: this hypothesis is REFUTED, the real
   cause is elsewhere -- do not keep re-patching this same function blindly. Candidates not yet
   ruled out: a data BLOCK (not page-cache) level staleness (the disk extent itself reused before
   the old content was ever flushed/invalidated at the block-buffer layer, analogous to but
   distinct from the page-cache gap just fixed -- check xfs_buf-level staleness for the DATA
   fork's extents, not just the inode's own metadata buffer which xfs_iget_recycle already
   protects via the P91-RECYCLE-PROTECT machinery); OR a genuine test-harness race unrelated to
   mxfs (less likely given the specific "durable, unhealed by drop_caches" signature, but should
   not be ruled out without evidence).
3. Re-run the FULL suite (not isolated) to reproduce -- isolated single-test runs on an
   already-converged cluster do NOT reproduce this (confirmed 4/4 clean in isolation).

## Next steps for whoever picks this up
Proceeding with the 1/2/4/8/16/32 sweep regardless (this is a rare, defensively-patched issue,
not a blocking hang/corruption like the PRIMARY bug). 32/caw's heavier churn is a natural
additional data point -- watch its fence_during_write (and any other checksum-verifying test)
closely. If the full sweep completes clean multiple times at 32-node scale too, that's much
stronger (though still not 100%) evidence this was a genuine rare flake now fixed rather than an
open bug. Do not mark the overall criteria met while this remains genuinely unproven if it
recurs even once more -- go back to RULE 4 step 1 with the two candidates above.
