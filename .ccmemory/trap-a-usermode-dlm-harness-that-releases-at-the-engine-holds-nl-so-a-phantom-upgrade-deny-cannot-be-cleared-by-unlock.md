---
name: trap-a-usermode-dlm-harness-that-releases-at-the-engine-holds-nl-so-a-phantom-upgrade-deny-cannot-be-cleared-by-unlock
description: TRAP (D-0968, s59): a ramp remaster leaves a node's own PR bit at the new master; its EX is denied -EDEADLK at once (no budget spent); unlock of NL s…
metadata:
  type: feedback
tags: [dlm, tauth, formation_test, EDEADLK, phantom, harness]
---

# A phantom upgrade deny in a usermode DLM harness

**Shape.** tests/tauth/formation_test ramps 12 in-process nodes and each hammers ino 128 with PR, unlock, EX, unlock at the ENGINE level (mxfs_dlm_lock_retries / mxfs_dlm_unlock). 3 of 8 runs failed with rc=-35 on the EX.

**What the instrument showed** (tests/evidence/formation_s59/): every failure was an EX request denied while the worker's local mode was NL; the master's P-CONVBLK-DENY count equalled the failure count; "failed after 10 retries" never printed. The engine returns -EDEADLK through the pass-through arm of mxfs_dlm_lock_retries (dlm.c ~7948) at once — the retry budget is never spent on it, so "the budget is too small" was never a candidate.

**Why the entry is stale.** During the ramp (remaster 9-40 per run) the node's release goes to a master the page has since left; the new master imported the page with the node's PR holder bit. The EX then reads as a blocked upgrade. This is the phantom class the kernel's ilock layer names P109-EDEADLK-NL (D-0904, xfs_mxfs_dlm.c ~37491): unlock finds nothing, so it sends the gen-0 unconditional release (mxfs_dlm_release_orphan_if_unheld, gated on the local table holding no entry) and re-acquires from NL.

**The trap.** Unlock-and-retry alone made it WORSE (5 of 8 failed, the deny repeating through all 10 laps): mxfs_dlm_unlock with nothing held locally is a local -ENOENT no-op and sends nothing, so it cannot clear a phantom. Only the unconditional release clears it — with it, 8 of 8 pass and each phantom heals in one lap.

**Rule.** A usermode harness that drives the engine directly must mirror the kernel's P109 handling on -EDEADLK at NL; asserting "no request fails" at the engine API is one layer below where the designed refusal is handled. Do not file the deny as an engine livelock without the first-failure trace (request, held mode, rc, call wall, deny count).
