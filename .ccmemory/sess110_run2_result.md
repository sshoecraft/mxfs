---
name: sess110_run2_result
description: sess110 RUN-2 (build 87726318): P110-BIO=0 everywhere → bnobt revert is NOT the plain-bio read path. Points to ALIASING / clean-cached-skip gap. Next…
metadata:
  type: project
---

# sess110 RUN-2 decisive result (build 87726318, clean reboot)

Reads with [[sess110_lessons]].

## Outcome (RULE 4 — bio-path hypothesis DISPROVEN)
- **P110-BIO-OVER-LOGGED = 0 on ALL 4 nodes.** The plain-bio-read guard I added NEVER fired →
  the bnobt in-core revert does **NOT** go through the plain-bio read path. Do NOT pursue that vector.
- **ltbno = 0 on all 4** — the bnobt double-free did NOT reproduce this particular run (it's
  intermittent/variable, as sess92 noted: corruption is multi-root — bnobt, SB, dir3, inode-cluster).
- **test2 shutdown=1 via a DIFFERENT corruption** (not ltbno). Did not capture exact type before relay;
  next session: `dmesg | grep -iE 'Internal error|Corruption|verify'` on test2 (dmesg intact). Activity
  around it was P106-MKDIR parent=136 "cv_verify_done" + P-SFDIR-RELOAD ino=136 → likely a dir/inode
  coherency corruption in cross_visibility's verify phase, NOT the allocator.

## What this means
With the FUA path (sync+locked, P91-guarded) and the plain-bio path (P110-BIO=0) BOTH ruled out as
the b_addr-clobber vector, the remaining mechanism for the bnobt split→pristine revert is:
**(a) ALIASING** — xfs_buf_stale on an in-AIL split buffer clears _XBF_DELWRI_Q (cancels its writeback)
and/or a 2nd xfs_buf for the same daddr wins the home write; or
**(b) the CLEAN-CACHED-SKIP gap** in mxfs_dlm_ag_drain_meta_buffers (xfs_mxfs_dlm.c:6476-6480): the
P99-AGMETA-STALE only stales DRAINED (in-AIL/pinned) bnobt bufs; a clean-but-stale cached bnobt buf is
skipped → survives as a stale alias into the next tenure → fast-path re-grant RMWs it → clobber.

## KEEP / decision
- P110-SFNULL guard (xfs_dir2_sf.c) — KEEP (defensive, harmless, never fired clean).
- P110-BIO guard (xfs_buf.c) — keep as backstop but it is NOT the fix (never fires). Build 87726318.

## Next session (highest value)
1. Capture test2's exact shutdown corruption (dmesg on test2). The criterion now fails via VARIABLE
   multi-root corruption, all of the SAME cross-node cached-buffer-coherency family.
2. Implement the GPT/sess98/NEWARCH cold-read pairing for AG-meta: stale ALL cached bnobt/cntbt (and
   ideally AGF/AGI/inode-cluster) bufs in the AG at EX RELEASE (not just drained ones — close the
   6476-6480 skip), PAIRED with cold-read (stale-incore) at every AG EX ACQUIRE. One side alone fails.
   This is the tenure-local-cache model NEWARCH prescribes; it should kill the whole variable-corruption
   family at once rather than one symptom at a time.
3. Then NEWARCH Phase 0 force_coherent gate (sess108 item 3) for the Outcome-1-vs-2 decision.
</body>
