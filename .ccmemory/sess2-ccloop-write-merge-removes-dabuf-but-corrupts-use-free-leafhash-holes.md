---
name: sess2-ccloop-write-merge-removes-dabuf-but-corrupts-use-free-leafhash-holes
description: sess2(ccloop): dir_write_merge=1 ELIMINATES DABUF-HOLE + runs all 24 rounds (vs shutdown r9) but introduces xfs_dir2_data_use_free corruption (l2157)…
metadata:
  type: project
---

## sess2 — dir_write_merge=1 A/B (current build EA485CE6 + modarg)

### Result: FAIL 0/8, but a DIFFERENT (and partly better) failure than baseline
- **DABUF_MAP_HOLE = GONE** (0 on all nodes). The write-side graft of peer disk-only dirents prevents the leaf-refs-freed-block tear. Test ran ALL 24 rounds (baseline shut down at ~round 9).
- **NEW corruption**: `xfs_dir2_data_use_free` Internal error at xfs_dir2_data.c:2157 → xfs_create → xfs_trans_cancel (xfs_trans.c:1060) → "Corruption of in-memory data" shutdown at round 19. The graft leaves the dir DATA block's bestfree/freespace metadata inconsistent → a later addname's use_free asserts. This is why dir_write_merge is DEFAULT OFF (sess52 "wedge" = this corruption class).
- **Persistent leaf-hash holes**: rounds 2-18 readdir=590/800 with **lookup_fail=90** (90 listed names NOT lookup-able), missing set = **node2_f1.md5 .. node2_f21.md5** (node2's md5 SIDECARS) — STABLE across rounds. = the dir LEAF INDEX lacks entries that exist in the DATA blocks (opposite of DABUF-HOLE's leaf-refs-missing-data). Data-side merge does NOT fix leaf-index divergence.

### What this PROVES
The root is cross-node concurrent dir modification producing **leaf-index ↔ data-block divergence**. Single-sided fixes SHUFFLE the corruption:
- baseline (no merge): leaf refs freed/absent data → DABUF_MAP_HOLE shutdown.
- write_merge: data grafted coherent, but leaf index still diverges → leaf-hash holes + freespace-metadata corruption (use_free).
No data-block-only fix converges; the LEAF index and freespace metadata must stay coherent with the data across the concurrent multi-writer churn. Confirms the sess36 "stale WRITE not stale base" + sess44 "intra-block double-alloc" root: two nodes modify the same dir block's data+leaf+freespace divergently.

### Merge param inventory (all default OFF except shortform): dir_write_merge(0, bio-submit graft, CORRUPTS use_free), dir_drain_merge(0, sess34 removed-set-gated release graft — UNTESTED this run, safer: operates on quiescing block at release not live bio), dir_choke_merge(0, REFUTED inert), dir_sf_rebase_merge(1 shortform), dir_merge_enabled(0). 

### NEXT: (1) test dir_drain_merge=1 (release-drain graft, removed-set gated — shouldn't corrupt live freespace like write_merge). (2) If still leaf-hash holes → need a LEAF-index reconcile on release/acquire (rebuild leaf from data, or graft missing leaf-hash entries) paired with the data merge. (3) Architectural: the real fix is strict EX serialization so no two nodes modify the same dir block concurrently — consult GPT-5.5 (RULE 5 bar met: complete diagnosis, write_merge+epoch+evict+revalidate all refuted, architectural Q).
See [[sess2-ccloop-EA485CE6-still-fails-rank1-rm-leaf-vs-data-and-p13collide-garbage]] [[sess36-...]]
