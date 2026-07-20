---
name: sess26-dataclobber-detector-catches-only-legit-removes-creastage-loss-invisible
description: sess26(ccloop): dataclobber=1 detect run on a real WHOLE-BLOCK loss (node2_f13-32.md5, round1) — P-DATACLOBBER-SKIP fired ONLY on comm=rm legit remov…
metadata:
  type: project
---

## sess26 — dataclobber=1 detect run: decisive characterization

Real loss captured (build CA135E9C, dataclobber=1 detect-only, clean reboot): round 1 lost a CONTIGUOUS BLOCK node2_f13.md5 .. node2_f32.md5 (~20 entries = one dir DATA block of node2's md5 sidecars) — LOOKUP_ENOENT, detected at round-1 verify (BEFORE any rm-rf).

### P-DATACLOBBER-SKIP (every dir write inspected, disk plain-read + fingerprint):
ALL 12 hits on test1 + 1 on test8 were:
`kind=data owner=131 daddr=120 buf_cnt=154 disk_cnt=155 bufgen=379 dirgen=379 mode=5 real_mode=5 in_txn=0 in_ail=1 bdirty=0 pin=0 incarn==bincarn stale=0 comm=rm`
- **comm=rm** → these are the rm-rf phase legit removals (round END, after the verify that already failed). buf_cnt = disk_cnt-1 = a legit single-entry removal, NOT a clobber. This is the FALSE-POSITIVE that makes dataclobber>=2 / subset-guard catastrophic (they'd suppress legit removes → resurrection/readdir=0).
- **bufgen==dirgen (379==379), stale=0** on ALL → `i_dlm_dir_gen` does NOT advance across a fast-path EX handoff. So dc_stale (bgen<dirgen) is BLIND to the real stale base; no gen-based guard can ever catch it.
- **ZERO create-phase (comm=dd/bash) clobbers logged on ANY node** despite dataclobber=1 inspecting every write → at each create-phase dir write's SUBMIT moment, disk did NOT have more entries than the in-core buffer.

### Conclusion (decisive)
The create-phase whole-block loss is INVISIBLE to a write-time disk comparison: when the clobbering node submits its (stale) block, the peer's about-to-be-lost entries are NOT yet on the LUN, so disk_cnt is not > buf_cnt → not flagged. The entries land, then the stale image is destaged over them in a later interleave the detector's one-shot read can't see. This is fundamentally why ALL write-side submit-time guards fail (racy disk read) AND why gen-based read-side guards fail (gen doesn't advance on fast handoff). The ONLY non-racy point is the SYNCHRONOUS RELEASE FENCE while the node holds EX and disk is quiescent.

### NEXT (implementing): release-side lingering-BLI detach
At EX release (bast_process drain / mxfs_dir_flush_data_blocks), after each dir DATA block is drained durable, DETACH its BLI (so no lingering stale in-AIL image survives into the next tenure for xfsaild to re-push) — the P126/P60 `xfs_buf_stale` pattern (xfs_buf_item.c:608/638), gated strictly to CLEAN destaged buffers (GPT verdict: xfs_buf_stale safe only on !dirty !undestaged !pinned). Testing as a gated lever next. [[sess26-PIVOTAL-loss-is-write-side-not-read-fua-pierces-still-loses]] [[sess69-TRUE-ROOT-crossnode-stale-readcache-hit-poisons-rmw-base]]
