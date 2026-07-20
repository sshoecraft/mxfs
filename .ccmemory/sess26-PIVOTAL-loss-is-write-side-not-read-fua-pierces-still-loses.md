---
name: sess26-PIVOTAL-loss-is-write-side-not-read-fua-pierces-still-loses
description: sess26(ccloop) PIVOTAL: forcing FUA pierce on ALL dir DATA base reads (P26-FUAREFRESH fired 8000x, reads ARE fresh from LUN; P91 skips dir blocks onl…
metadata:
  type: project
---

## sess26 — PIVOTAL: the dir_reuse lost-update is WRITE-SIDE, not read-side

Builds on [[sess26-fua-refresh-data-only-no-shutdown-but-loss-persists-base-is-undestaged-or-plainbio]].

### Decisive experiment (build BDD8DDD9, dir_fua_refresh_destaged=1 data-only + P26-FUAREFRESH probe)
- **P26-FUAREFRESH fired 8000× (capped)** = dir DATA base reads ARE redirected to a real FUA SCSI pierce (fresh-from-LUN, bypasses SCST per-initiator read cache). Most fire `has_bli=0` (plain destaged blocks).
- **P91-FUA-SKIP-LOGGED fired only 4×, ALL `ops=xfs_inode`** — i.e. P91 essentially NEVER skips dir DATA/LEAF blocks. So the earlier "P91 keeps a stale lingering-BLI dir base" theory is WRONG; dir block reads were already FUA-piercing.
- **Loss STILL occurs** (readdir=799, round 7). Forcing fresh FUA reads on all dir DATA bases does NOT prevent the durable lost-update.

### Conclusion (rules out the whole read-side family)
The stale RMW base is NOT the cause. The read gets the peer's fresh image, the create adds correctly — then a STALE in-core copy of the dir DATA block is DESTAGED (xfsaild background push) over the peer's fresh disk, dropping the peer's entry. This RE-CONFIRMS sess25's PROVEN write-side clobber (EX-held, in_ail=1, bdirty=0, comm=dd/bash, stale=0, EQUAL-count DIFFERENT-fingerprint) and definitively eliminates read-side re-read/evict/FUA as the fix locus (consistent with the standing CLAUDE.md lesson: write-side, but suppression must be done right).

### THE NEXT FIX (sess25's identified path — SUBSET check at the bio write chokepoint)
At the dir-DATA-block write submit (pal/linux/xfs_buf.c, where ex_write_guard / mxfs_buf_needs_fua_read live), for a CLEAN (bdirty=0, in_ail=1) multinode dir DATA block being pushed by xfsaild (NOT the dirty release-drain write):
1. Plain-read the current on-disk block.
2. Parse dirents of BOTH in-core (about-to-write) and disk.
3. If the disk block contains ANY dirent (by inumber+name) ABSENT from the in-core image → the in-core is STALE (a peer added it after we cached) → SKIP the write + invalidate the buffer (clear XBF_DONE) so it re-reads. Writing it would clobber the peer (the readdir=799 loss).
4. If in-core ⊇ disk (superset) → write is SAFE (we're adding, not dropping) → proceed.
CRITICAL distinguisher vs a LEGIT REMOVE (in-core has FEWER entries than disk by design): only apply to CLEAN/destaged blocks (xfsaild ABA push). A legit remove is a DIRTY block (active modify) → falls through to normal write. This is the SUBSET check sess25 said is needed (fingerprint count+sum+xor CANNOT prove subset; must compare actual dirents). AVOID the sess25 defer (XFS_ITEM_LOCKED pins log tail → DLM starvation shutdown) — this SKIPS+invalidates (no pin, no I/O withheld permanently; the block's content is re-read fresh on next access).

### Tree
Build BDD8DDD9 = keeper + gated default-0 levers (dir_newtenure_evict, dir_modify_target_flush, dir_fua_refresh_destaged + P26 probe) + i_dlm_dir_evict_mep field. All params default 0 == KEEPER, no regression. 1/2/4 tcp unaffected. Dead-ends this session: MHT, dir_tenure_evict, dir_newtenure_evict, dir_modify_target_flush, dir_fua_refresh_destaged (all read-side or band-aid). [[sess25-PROVEN-clobber-is-background-aild-destage-of-stale-incore-dirblock]]
