---
name: sess34-REFUTED-drain-graft-pivot-newtenure-evict-retire
description: sess34: drain-side graft REFUTED twice (801 cross-block/cross-disk dup, even with global in-core dedup — can't see disk-only blocks). Pivot to acquir…
metadata:
  type: project
---

## sess34 — drain-side graft is a DEAD END (re-confirmed, matches sess29/sess33). Pivoting.

### REFUTED (RULE 4, on-cluster):
- **8F1E17A0** (removed-set drain-merge, per-block name dedup): round3 readdir=801 + lookup_fail(node7_f17). Cross-BLOCK dup (peer entry in in-core block A grafted again draining disk block B).
- **DBD82AB2** (+ whole-dir GLOBAL in-core dedup via mxfs_dir_name_incore_global): round1 readdir=801 + lookup_fail(node3_f50), IDENTICAL on all 8 nodes (on-disk dir corrupted by a graft). Global IN-CORE dedup is insufficient: the dup arises when the entry lives on a DISK block we never cached this tenure — our in-core scan can't see it, so we graft it into a different block → on-disk DUPLICATE. To dedup correctly we'd have to read ALL disk blocks (too expensive) — exactly the "can't verify global uniqueness from one block" wall sess29 hit. **Graft-at-drain ABANDONED.** dir_drain_merge stays default-0 (build is keeper-equiv at default; removed-set infra retained, inert).

### The removed-set DID work (disambiguation correct): merge fired surgically 1-2×/node (NOT 100s), proving inumber-vs-removed-set correctly distinguishes peer-add from our-remove. The wall is purely the graft's global-consistency + leaf-desync, not the ambiguity.

### PROVEN mechanism (keep): loss-write = release-drain bwrite of a CURRENT-tenure (b_epoch==valid), undestaged, comm=rm block that is a stale base (missing a peer's add). The block was KEPT by the modify-evict's undestaged keep-clause `(in_ail && !new_tenure && is_undestaged)`. At the FIRST modify of a NEW tenure that "undestaged" is a FALSE POSITIVE (Inv 1 drained it durable at our prior release, BEFORE the peer's tenure).

### NEXT (acquire-side, the principled fix): NEW-TENURE force-evict + BLI-RETIRE.
- `dir_newtenure_evict` (default 0) ALREADY bypasses the undestaged keep-clause when new_tenure (master epoch advanced since last evict) → force-evicts (clears DONE). It was REFUTED (readdir=0) because clearing DONE leaves the zombie BLI in the AIL → it reflushes the stale image (sess33 mechanism).
- FIX = ADD a BLI-retire in mxfs_dir_evict_data_blocks `!undurable` branch (xfs/xfs_mxfs_dlm.c ~3718), gated on `new_tenure` (NOT on !undestaged like the existing zombie_retire at ~3754): at new_tenure the block is durable (Inv 1) so retiring its in_ail BLI is loss-safe and STOPS the stale reflush. Then the modify cold-reads the peer's image → fresh base → correct RMW (normal XFS maintains data+leaf consistency, no graft, no leaf-desync).
- Test: `drc_repro_loop.sh 6 "dir_newtenure_evict=1" 24`. Watch readdir==800 AND no readdir=0 (the prior corruption) AND no lookup_fail.
- new_tenure reliability: master dir epoch (dg_shadow) made eviction-immune in sess23 — reliable. Risk if new_tenure false-positives: retire genuine un-landed current work → loss; but it only fires when a peer genuinely held EX since our last evict.

[[sess34-HEAD-removed-set-drain-merge]] [[sess33-HEAD-handoff]]
</body>
