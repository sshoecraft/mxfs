---
name: sess27-SYNTHESIS-slot-collision-needs-durability-ordering-not-more-rereads
description: sess27(ccloop) SYNTHESIS: the proven dir-slot collision is gated by DURABILITY ORDERING, not re-read frequency. force_coherent=1 (re-read everything)…
metadata:
  type: project
---

## sess27 — the slot-collision fix is DURABILITY ORDERING, not "re-read more"

### The tension (why naive coherency fixes fail)
PROVEN mechanism: intra-block slot collision — node7's addname picks off=1280 occupied by node5_f46.md5, because node7's in-core data block's bestfree offers off=1280 as free (stale, missing node5's add). [[sess27-SMOKINGGUN-intrablock-slot-collision-off1280-node7-overwrites-node5]]

Naive fix = force node7 to re-read the data block coherently so its bestfree sees off=1280 occupied. BUT force_coherent=1 (which does exactly that on every read) made it WORSE (readdir=788 vs 799). Because: aggressive re-reads ALSO re-read blocks whose committer's data-block write has NOT yet reached the platter → the re-read pulls a STALE platter image → reverts that committer's just-added entry (the sess11 "logged-then-vanish" revert). Net negative.

### Therefore the binding constraint is DURABILITY ORDERING (Invariant 1 for the DATA BLOCK)
For node7's coherent read to be SAFE and CORRECT, node5_f46.md5 must already be on the PLATTER when node7 reads. I.e. node5's release of the dir EX must make the modified DATA BLOCK platter-durable BEFORE the DLM unlock — so the next holder's read (cached-refresh or cold) sees the occupied slot and its bestfree skips it. If the block isn't durable at release, node7 reads stale → collision; if you force node7 to re-read anyway, you instead revert node5 (force_coherent's regression).

### Why current code doesn't guarantee it
- Release drain (mxfs_dir_flush_data_blocks) SKIPS blocks UNCACHED at release ("already on disk", P11-FLUSH-UNCACHED, fires comm=dd on all nodes). dir_gen_per_handoff's invalidation clears XBF_DONE on clean blocks → reclaimed → uncached at release → skipped.
- The gen-handoff bump that would refresh node7 sometimes doesn't fire (node5→node7 handoff missed → node7's b_gen==dir_gen → served stale). [[sess27-HANDOFF-head-state-and-next-step]]

### NEXT (sess28) — the fix must do BOTH, ordered:
1. GUARANTEE the modified dir data block is platter-durable before EX release (close P11-FLUSH-UNCACHED: if a logically-mapped dir data block is uncached at release-drain, it may have been reclaimed before its committed content was written — verify via FUA-read, and if the committed dirent is absent on the platter, re-stage it). 
2. THEN make the next holder's read coherent (reliable handoff gen-bump, OR a targeted coherent re-read of the chosen data block at xfs_dir2_node_addname_int:1959 — gated so it only fires for a multinode shared dir AND only refreshes a CLEAN buffer, never node's own dirty in-tenure work).
Order matters: (2) without (1) = force_coherent regression. (1) without (2) = node7's gen-miss still serves stale.
DECISIVE PROBE first (RULE 4): at xfs_dir2_node_addname_int:2016-2022 slot-pick, log (daddr, chosen off, freetag/name currently at that off on a FUA-read of the platter, b_gen vs dir_gen) for ino<=256 — catch node7 picking a platter-occupied slot and confirm whether the platter already has node5_f46.md5 (→ pure read-staleness, fix=(2)) or not (→ durability, fix=(1)).
Existing site already has P22-FREESLOT-STALE repair (freeindex-vs-bestfree) but NOT bestfree-vs-platter.
