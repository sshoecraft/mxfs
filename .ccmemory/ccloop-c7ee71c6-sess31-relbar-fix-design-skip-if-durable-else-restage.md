---
name: ccloop-c7ee71c6-sess31-relbar-fix-design-skip-if-durable-else-restage
description: D-RELEASE-BARRIER-OPEN fix design: 14516 is bast_process's completed-release tail; leak = post-drain re-logs (inodegc). Skip stale_nl slot iff pub_du…
metadata:
  type: project
---

# sess31 — release-barrier fix design (NEXT SESSION: consult GPT, then implement)

## The window, precisely
Line 14516 (`i_dlm_epoch++`, epsrc of ALL measured P219 events) is inside
`mxfs_dlm_bast_process` — the COMPLETED-release tail: Phase-2 drain ran, wire
unlock done, mode=NL, epoch++. The leak is anything COMMITTED between the
drain's flush pass and the unlock: async inodegc/inactivation re-logging the
just-unlinked orphan is the measured case (class X). The drain's completion
criteria do not include "no dirty inode log items remain on cluster buffers".
P220's wire-unlock IFLUSHING check is structurally blind to it (items attach at
precommit; IFLUSHING clears at iodone while the re-logged item stays attached).

## Fix design (grounded in EXISTING fields — sess14/18 obligation counters)
At the masking loop's logged-slot branch, for a slot with
`stale && dlm_mode==NL && !relflush && !demoter` (the stale_nl class):
- If `ip->i_mxfs_pub_durable_seq >= ip->i_mxfs_pub_flush_seq` at submit — the
  staged bytes ALREADY LANDED under their staging tenure (the drain published
  them); this late rewrite is REDUNDANT, and writing it can only hurt (a peer
  may have republished/reused the cluster since our release). SKIP the slot.
  Lossless by construction.
- Else (bytes never landed): cannot skip (loses a committed change). Options:
  hold/requeue the buffer (A, AIL-pileup hazard) or reacquire+reload/adopt+
  restage (C, GPT's ranked recovery). Start with counting how often this arm
  even occurs (suspicion: near-zero — the drain flushes everything flushable,
  so un-landed + stale + NL should be rare); if ~zero, ship the skip and make
  the else-arm a loud probe + hold.
CAUTION from the pal.md refinement note: discharging a log item whose bytes
never landed converts a clobber into a lost write — the skip MUST NOT complete
the item's iodone-side accounting as if written; check how skipped slots
interact with xfs_buf_inode_iodone (the existing P56 dir-skip already navigates
this — mirror its treatment: ili roll-back / MXFS_IF_PUB_SKIPPED re-arm).

## Verification plan
Producer: dirent_durability@32/caw (~13 events/lap). A/B knob (skip on/off);
acceptance: stale_nl_written → 0 in fix arm, dirent_durability + dir_reuse +
cache_coherency stay green, crash_consistency unaffected (log recovery must
still see consistent state — the skipped image's changes are in the JOURNAL,
which is what protects them). Also watch P56-family counters for double-skip
interactions.

## Class Z follow-up (separate)
Shared-parent mid-EX submits with multi-epoch-old bytes are drain-covered
today; instrument whether any UNLOCK path can skip re-flushing a dirty shared
parent (that would be the D-SILENT-MKDIR-LOSS bridge).
