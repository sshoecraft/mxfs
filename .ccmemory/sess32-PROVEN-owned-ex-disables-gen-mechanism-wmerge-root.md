---
name: sess32-PROVEN-owned-ex-disables-gen-mechanism-wmerge-root
description: sess32 PROVEN: dir_reuse loss = EX-held async-destage of stale in-core base (P-WMERGE MERGE-NEEDED). DIR-STALE-SKIP never fires bc owned_ex disables…
metadata:
  type: project
---

## sess32 — full instrumented diagnosis of the dir_reuse single-dirent loss

### The clobber (PROVEN, P-WMERGE detector, build 1C845861, dir_writeprobe=1)
At the xfsaild WRITE/destage chokepoint (pal/linux/xfs_buf.c:2429): `P-WMERGE owner=131 disk_extra=1 incore_extra=1 held_mode=5(EX) in_ail=1 dirty=0 bgen=0 kind=data — MERGE-NEEDED`, ~30×/run across nodes. Detector uses a **PLAIN read** of disk → disk has the peer's add (f4) we lack (disk_extra=1) AND we hold an add disk lacks (incore_extra=1). Writing our in-core block reverts the peer's f4 = the durable single-dirent loss (readdir 799/800). Still fires on a PASS run (other keeper mechanisms mask it sometimes; ~1/2 it manifests as the loss).

### Why the read-side refreshes never catch it (PROVEN)
- **DIR-STALE-SKIP (xfs_da_btree.c:3427) fires 0×** during the whole run. Reason: under EX, `owned_ex` GATES OFF the gen mechanism (xfs_da_btree.c:3154 bumps dir_gen 0→1 only `!owned_ex`). So an EX holder keeps `dir_gen=0`; the stale cached base has `bgen=0`; `bgen==dir_gen==0` → treated FRESH → served to the RMW. The whole gen/epoch/ABA read-time staleness machinery is INERT for an EX holder.
- The acquire-evict SKIP branch (mxfs_dir_drain_evict_data_blocks) sees only **done=0** blocks (342/342 done=0) — no kept-stale done=1 block at acquire. So the acquire-time reconcile flag premise was structurally wrong.

### Refuted fixes (all this session, with evidence)
1. v2 reconcile gen-filter (bgen!=dir_gen): P31 fired 0× (inert). 
2. broad reconcile (gen-filter dropped) armed at acquire-SKIP: P31 still 0 (flag-set needs XBF_DONE; SKIP blocks are done=0).
3. reconcile armed at read-time DIR-STALE-SKIP + PLAIN read (build 1C845861): DIR-STALE-SKIP never fires under EX → P31 still 0, P-WMERGE still ~30×. INEFFECTIVE.
4. (sess31) create-time dir_merge FUA: ineffective (FUA reads lagging platter, misses f4).
5. (sess31) dir_write_merge byte-graft at destage: bnobt double-free SHUTDOWN (no txn leaf/freeindex update).
6. suppress MERGE-NEEDED write (like P26-SUBSET-SKIP): would lose OUR entry — reconcile re-adds disk→incore only, cannot recover our incore_extra once refreshed away.

### The architectural impasse (for GPT consult)
Need a TRANSACTIONAL 3-way merge (keep our incore_extra + add peer's disk_extra) to close an EX-held write-side async-destage TOCTOU on a NODE-format dir. Byte-graft corrupts bnobt; suppress loses our entry; read-side refresh is off under EX. Where/how to apply the union transactionally before the destage?

### Standing: 1/2/4 tcp=100%; 8/tcp blocked only by this. Keeper build 37A37B10 (reconcile default off). [[sess32-reconcile-v2-inert-gen-filter-dropped]] [[sess31-KEY-loss-is-async-destage-TOCTOU-create-and-read-merges-ineffective]]
</body>
