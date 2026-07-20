---
name: sess37-REFUTED-release-retire-bli-and-readside-coherent
description: sess37: reads ARE coherent (P28-PLATTER 7152 MATCH); loss is zombie-BLI stale reflush. Manual BLI retire after release bwrite = CORRUPTION/shutdown.…
metadata:
  type: project
---

## sess37 — two decisive results closing off more of the solution space.

### 1. READS ARE COHERENT (refutes read-served-stale): P28-PLATTER (FUA-read-vs-in-core compare at addname, build C949F3C3) = **7152 MATCH vs 48 DIFFER**, and ALL 48 DIFFER have `dirty=1` (our own uncommitted work — expected, not staleness). So a CLEAN in-core dir block ALWAYS equals the platter. The RMW base at addname is coherent (matches sess32 POSTRMW-superset). Therefore the readdir=799 loss is NOT a stale read/RMW base — it is purely a **zombie-BLI stale DESTAGE** of a block whose content was correct at addname but is reflushed later in a peer-superseded (stale) form.

### 2. MANUAL BLI RETIRE AT RELEASE-DRAIN = CORRUPTION (refuted, do NOT retry): new lever `dir_release_retire_bli` (default 0) called `xfs_buf_item_done(dbp)` right after the release-drain `xfs_bwrite` (mxfs_dir_flush_one_daddr, ~line 1978) to retire the just-durable DONE=1 zombie BLI. **Result: `XFS (sda): Metadata I/O Error (0x1) at xfs_trans_read_buf_map` → FS SHUTDOWN on all nodes, round 1.** Calling xfs_buf_item_done after a manual xfs_bwrite corrupts the buffer/AIL state (the buffer is still cache-resident; freeing its BLI out-of-band breaks a later read). The DONE=1 zombie BLI CANNOT be retired this way. (release_invalidate's xfs_buf_stale is the only safe post-bwrite action, and it does NOT remove the BLI from the AIL — hence the zombie persists, hence the ~50% ceiling.)

### NET (sess37): the loss is a zombie-BLI reflush; reads are coherent; but EVERY mechanism to stop the zombie is blocked —
- write-side DROP/suppress at any chokepoint → corruptor (sess23/33/37, ~5×).
- manual BLI retire after release bwrite → Metadata-IO-Error shutdown (sess37).
- xfs_buf_stale (release_invalidate, default on) → doesn't remove the BLI from AIL → zombie survives.
- per-lever acquire-evict + zombie_retire + zombie_push + read-side stack → ~50% ceiling (some zombie always escapes the gen/epoch/grant predicates).

### THE REMAINING PATH (architectural, the only one not yet refuted): GPT's owner-checkpoint — make the buffer NEVER reach an independent destage. Options to explore next session:
1. The zombie exists because xfs_bwrite (manual, in the release drain) does NOT run the normal IO-completion BLI retirement that delwri/AIL writeback does. Investigate WHY a normal xfsaild writeback retires the BLI but the manual release xfs_bwrite leaves it in the AIL — if the release drain instead used the DELWRI-queue + xfs_buf_delwri_submit path (which DOES retire BLIs on completion), the zombie would be retired correctly by the normal machinery (no manual xfs_buf_item_done corruption).
2. OR prevent the dir buffer from ever having an independent BLI/AIL presence in multi-node mode (route all dir-metadata durability through a checkpoint that retires BLIs as a unit).
3. Investigate xfs_buf_item_done's preconditions — maybe it needs the buffer marked stale FIRST, or the BLI's li_lsn must match; the manual call may need to mirror exactly what xfs_buf_ioend→xfs_buf_item_done does on real IO completion (flush-locked state, etc.).

### Build on disk = `DFAEAF39` = keeper-equiv at DEFAULT (dir_release_retire_bli + all sess37 levers default 0). Cluster: FS shut down on nodes by this run; next cap/batch reboots clean. See [[sess37-HEAD-handoff]] [[sess37-DECISIVE-clobber-on-nonmaster-stale-local-dlm-EX]] [[sess26-PIVOTAL-readside-loses-writeside-corrupts-fix-is-release-fence]].
