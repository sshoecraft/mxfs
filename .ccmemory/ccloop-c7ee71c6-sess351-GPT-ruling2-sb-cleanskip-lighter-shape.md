---
name: ccloop-c7ee71c6-sess351-GPT-ruling2-sb-cleanskip-lighter-shape
description: sess351 follow-up ruling #94: NO racy SB rebuild write — clean-skip + durable SB_COUNTERS_UNTRUSTED obligation for future mounts; publish recovery im…
metadata:
  type: project
---

# sess351 follow-up ruling — lighter #94 shape (supersedes rebuild steps 3-8 of ruling 1)

Facts presented: no live consumer of on-disk SB counters in MXFS multi-node
(statfs sums per-AG summaries sess39; admission = local percpu, separate
ledgered drift defect; SB home is last-writer-wins from every node's drifted
values, no SB grant).

## Q1 — racy replayer SB-home rebuild write: NO
AG scan without cluster quiesce is not point-in-time coherent; result
immediately clobberable; plausible-but-wrong value would be TRUSTED by a later
clean mount. Provides no correctness property. Skip it; release victim slot
sooner. Durable state means SB_COUNTERS_UNTRUSTED (do not trust on-disk SB
counters regardless of clean-log status); future mounts must force
xfs_initialize_perag_data EVEN ON CLEAN MOUNT. In clustered mode there may be
no reason ever to clear it (cannot prevent subsequent untrusted writeback).

## Q2 — marker alone sufficient to publish recovery complete: YES, provided
persist-before-first-skip ordering; mount-path enforcement (overrides clean-
mount trust); obligation survives slot release/descriptor reclaim (fs-wide
sticky, multi-victim safe); successor replayer sees pre-skip stage or durable
revocation; all authoritative AGF/AGI/metadata replay complete (marker only
substitutes for redundant SB counters).

## Q3 — comparison baseline: replay-local effective SB, NOT moving home SB
Two independent gates: (1) purity from txn semantics/log-item dirty masks —
txn contains ONLY whitelisted-counter SB effects, no other items (NOTE
sess351: xfs_log_sb logs the WHOLE sb buffer, so dirty-mask cannot isolate
fields; content compare is the load-bearing gate; purity gate = every item is
a primary-SB buf image, nothing else); (2) masked compare against effective SB
walked in victim LSN order, seeded from stable recovery snapshot of non-counter
fields. Under the blanket (nothing ever applied) effective SB never advances →
seed = replayer's own m_sb; a victim-side growfs image mismatches → fail
closed (false refusal acceptable). Home-SB fresh read only as conservative
already-applied optimization, never the semantic baseline.

## sess351 implementation decision
Adopt the LIMIT CASE of Q1: mxfs mounts distrust on-disk SB counters
UNCONDITIONALLY (force per-AG recompute at every mxfs mount, single- and
multi-node) — subsumes the durable marker (no new on-disk state, no
persist-ordering, trivially multi-victim/successor safe) and fixes the latent
pre-existing bug where a clean mount after cluster use trusts drifted
counters. Multi-node already reads every AGF/AGI at mount (statfs baseline) so
added cost ~0. To be re-validated in the post-landing GPT diff review.
