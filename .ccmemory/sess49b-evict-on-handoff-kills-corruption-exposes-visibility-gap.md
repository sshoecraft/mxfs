---
name: sess49b-evict-on-handoff-kills-corruption-exposes-visibility-gap
description: sess49b: build 4403BECE (reload-gate + handoff-evict) ELIMINATES ALL 8/tcp corruption (HOLE/DISK-TORN/oops=0). Remaining = dir-DATA-block release-dur…
metadata:
  type: project
---

## sess49b — combined fix: corruption ELIMINATED; remaining = dir-data release durability

### Build 4403BECE (KEEP — best foundation: NO corruption ever)
= torn-disk reload gate + P68-PREEVICT owner-evict extended to fire on `genuine_handoff` (xfs_mxfs_dlm.c ~12902: `gen_change || shrink || genuine_handoff`). Placed after the reload gate (torn disk bails first → no interaction).

### RESULT (clean-reboot iter): FAIL 0/8 BUT all corruption GONE
P68-PREEVICT handoff=1 fires (41× test1, 83× test6). **HOLE=0, DISK-TORN=0, oops=0, no shutdown, mnt OK.** The DABUF_MAP_HOLE cascade + kernel oops + disk-torn — ALL eliminated. test6 readdir=0, others 719/800 (missing node6's). Pure visibility, zero corruption — the safest state in the whole 130-session investigation.

### SHARP diagnosis (corrected): it's a DURABILITY gap, NOT evict-too-aggressive
`mxfs_dir_evict_owned_dir_blocks` (xfs_mxfs_dlm.c:3899) ALREADY evicts ONLY CLEAN/durable blocks — it SKIPS dirty/pinned/in-AIL/_XBF_DELWRI_Q/!XBF_DONE (lines 3916-3923). So it does NOT drop test6's in-flight work. test6 reads 0 because: the evict forces a cold re-read of test6's clean-cached dir DATA blocks FROM DISK, and disk comes back EMPTY → **test6's dirents were never landed on the platter** (the dir DATA block was marked clean/XBF_DONE in cache but its content is not durable, OR a peer's release-drain dropped them). This is the long-standing "dir block released un-landed" / Invariant-1 gap — previously MASKED by the stale-cache that the new evict now strips away. The evict didn't cause the gap; it EXPOSED it.

### NEXT (RULE 4) — close the dir-DATA-block release durability
The fix that removed corruption now requires the dual: a node must LAND all its dir DATA blocks on the platter before releasing EX (so a peer's post-handoff cold re-read sees them). Investigate `mxfs_dir_data_durable` (xfs_mxfs_dlm.c:1418, iterates iext + bwrite each data block) — is it actually called on EVERY dir EX release and does it bwrite+wait every DATA block (not just leaf/bmbt)? Probe: P68-DIRINODE-DURABLE-FAIL, and add a release-time probe that FUA-verifies each just-written dir data block is on disk before unlock. If a block is clean-in-cache but not on disk → the destage/iflush path marked it done without landing it (the _XBF_FUA / LIO FUA-drop interaction, or a release that log_forces but doesn't bwrite the data home). Also check the per-round dir REUSE: test6 reads 0 of its OWN entries every round 7-24 — confirm test6 resolves $D to the SAME dirino as peers (drc-DIRID) and isn't on a divergent incarnation.

### Verify protocol once durability closed: drc_reliab_iter.sh 8 >=5x all PASS, then run.sh {2,4} tcp (no regression).
### Reconsider if needed: if dir-data durability is too deep, the handoff-evict could be scoped to LEAF/NODE-only (don't cold-re-read DATA blocks) — but that re-admits the masking, not a real fix.
See [[sess49b-NEXT-leaf-vs-map-destage-atomicity]] [[sess49b-BREAKTHROUGH-torn-disk-reload-gate-partial-8tcp]] [[sess49-8tcp-root-is-durable-dir-delalloc-extent-tear]].
</body>
