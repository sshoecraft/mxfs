---
name: sess41-NEXT-sum-discriminator-bmbt-orphan-vs-insert-loss
description: sess41 IMMEDIATE NEXT STEP: run drc_cap8 dirland=1, on fail sum the failing incarnation's per-daddr final dirent counts — ~802=bmbt-orphan (block unr…
metadata:
  type: project
---

## sess41 (ccloop 4cb2d0a2) — IMMEDIATE NEXT STEP for the next session. Build `5E7CC562` on disk (dirland/choke_merge default OFF = keeper functionally; ring tool ready). Cluster clean.

### The decisive discriminator (uses the count-augmented landing ring already built)
The loss is INSERT-time / never-clobbered (PROVEN this session: merge dko=0, no reorder, no count-regression — see [[sess41-DEFINITIVE-loss-is-insert-time-not-writeback-ring-proven]]). Two remaining candidates:
- (b) **bmbt extent-map lost-update orphaning a written block** — the entry IS durably written to a data block, but that block is dropped from the dir's data-fork extent map, so readdir's bmap walk never visits it (→ "missing" → cascades to DABUF_MAP_HOLE / readdir=0, which IS observed in later rounds). 
- (a) **true insert-loss** — the entry is never written to any data block.

DISCRIMINATOR: on a fail, sum the FINAL (max-realns) per-daddr active-dirent count over all DATA-block daddrs of the FAILING incarnation (the latest incarnation in the ring dump). Each data block's count includes its real dirents; block 0 also has `.`+`..`. Expected full = 800 user entries + 2 (`.`,`..`) = **802**.
- sum ≈ 802 → all entries ARE on disk in data blocks → the lost one is in an ORPHANED block (bmbt extent-map lost-update). Fix = dir inode bmbt/extent-fork coherency on concurrent data-block allocation during growth.
- sum ≈ 801 → one entry never written → true insert-loss in addname/leafn_add/freeindex. Fix = the concurrent add path.

### EXACT COMMANDS
1. `cd /src/mxfs && rm -f tests/tcp/drc_cap/dland_*.txt`
2. `setsid bash tests/drc_cap8.sh 5 "dirland=1" > /tmp/cap.log 2>&1 &`  (NO DRC_STREAM — too slow; NO DRC_OWNCHECK — caused near-wedge, was reverted)
3. Wait for a FAIL (intermittent ~25-50%/iter, ~7min/iter, 24 rounds; breaks on first fail; nodes hold state). Lost entry+round from the RDMISS in /tmp/cap.log.
4. dland files land in tests/tcp/drc_cap/dland_<host>.txt (NFS). Parse: `cat dland_test*.txt | grep 'P-DLAND d=' | sed -E 's/.*d=([0-9]+) o=([0-9]+) i=([0-9]+) s=(0x[0-9a-f]+) n=(-?[0-9]+) t=([0-9]+).*/\2 \1 \3 \5 \6/' | awk '$1==131 && $4>=0'` → fields: owner daddr incarn count realns.
5. Identify failing incarnation = the i= value with the largest realns activity (the latest round). For that incarn, for each daddr take the max-realns row's count, sum the counts. Compare to 802.

### Then implement the matching fix:
- bmbt-orphan → instrument + fix the dir data-fork bmbt update under concurrent growth (cross-ref sess40 CORRECTION "inode/bmbt extent-fork detector"; sess46 btree-block AG read-coherence). 
- insert-loss → instrument xfs_dir2_node_addname / xfs_dir2_leafn_add / xfs_dir2_data_use_free / freeindex (xfs_dir3_free) coherency under concurrent cross-node adds (cross-ref sess22 freeslot family).
Re-verify 1/2/4 tcp + 8 tcp full before any criterion claim.
