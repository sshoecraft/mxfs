---
name: sess48-FINAL-state-extentmap-staleness-is-next-root
description: sess48(ccloop) FINAL: 1/2/4 tcp dir_reuse PASS 100% (build 237F937D config#1). 8/tcp NOT met — intermittent ~1-2/24 per-handoff dirent lost-update; n…
metadata:
  type: project
---

## sess48 (ccloop 4cb2d0a2) FINAL — criterion NOT met (8/tcp)

### Build 237F937D = CONFIG #1 (baked defaults, KEEP as base)
dir_owner_scan=1, dir_grant_evict=1, dir_modify_target_flush=1 (were 0).
dir_release_flush_all_done=0, dir_release_flush_leaf=0 (A/B levers, REVERTED — cause
P21H-LEAFHOLE→DABUF_HOLE tear when on; release_flush_all_done helps RDMISS marginally but
intermittently and adds RULE-0 slowness). P48 instrumentation (DG-CHAIN, OWNEREVICT-DIRTYSKIP)
present, harmless. Source builds clean to 237F937D.

### RESULTS
- 1/tcp, 2/tcp, 4/tcp dir_reuse_coherency: **PASS 100%** (24 rounds, 0 loss, 0 shutdown). Solid.
- 8/tcp: **FAIL** — intermittent ~1-2 dirent loss per 24 rounds (readdir=796-799/800,
  LOOKUP_ENOENT REREAD_MISS, all nodes agree, durable). Last build streak: one run 21 rounds
  clean, next run lost at round 23 → NOT reliably fixed by ANY config tried. NO real FS shutdown.

### PROVEN: per-handoff lost-update (loss ∝ EX-handoff count)
inode_mht_ms=0 (per-create handoff) → 8/10 rounds lose; mht=300 (batch) → ~1-2/24. Batching
HELPS (fewer handoffs). Each cross-node EX handoff has a small chance of dropping a just-added
dirent (peer RMWs a dir DATA block on a base missing entry X). This is the ~130-session core.

### RULED OUT (instrumented): split-brain (MX-DOUBLEGRANT=0, P-DOUBLEGRANT is false-positive
stale shadow); acquire dirty-base skip (DIRTYSKIP dirty1=0); owner_scan causing DABUF_HOLE
(=0 effect); MHT batching as cause; release di_size durability (blkdev_flush present,
GROWREL/SFREL STALE-DISK=0); release_flush_all_done as reliable fix (intermittent).

### NEXT ROOT LEAD (NOT yet investigated — most promising): dir EXTENT-MAP staleness
The DABUF_MAP_HOLE_OK storm (xfs_da_btree.c:2876, ~3-4k/run, self-heals non-fatally) = a peer's
LEAF references a logical block that is a HOLE in its in-core EXTENT MAP (i_df). So the peer's
extent map is STALE vs the durable dir (lags the current incarnation/grow). owner_scan reloads
DATA/LEAF buffers on handoff but the inode EXTENT MAP reload (mxfs_dlm_reload_inode) may be
inconsistent/stale → P RMWs on a stale map → misses/drops entries (the lost-update) AND leaf
refs unmapped blocks (DABUF_HOLE). HYPOTHESIS: dir i_df extent map is not reliably reloaded
coherently with the leaf/data on each cross-node handoff (esp. under rm-rf+recreate inode REUSE).
INVESTIGATE: mxfs_dlm_reload_inode dir-fork reload on handoff/incarnation; whether leaf, data,
and extent map are reloaded as ONE consistent snapshot. The P13-COLLIDE "ourdir=0 downer=foreign
bufgen=0" variant also points here (extent map → foreign/freed daddr).

### Repro: tests/drc_dirtyskip.sh "<modargs>" <rounds> <N>  (reboot-clean, run, correlate).
RULE-0: ~16-25s/round (owner_scan per-AG rhashtable walk per handoff + release flush). Too slow;
24 rounds doesn't fit a 600s bash call — run.sh in background or reduce reboot.
See [[sess48-8node-perhandoff-lostupdate-ruledout-set]] [[sess47-GPT-consult-leaf-coherence-invariant-and-design]].
</body>
